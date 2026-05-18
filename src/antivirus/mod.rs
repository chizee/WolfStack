// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Host-side signature antivirus / rootkit scanning.
//!
//! Wraps **ClamAV** (signature AV), **rkhunter** (rootkit hunter), and
//! **chkrootkit** (complementary rootkit scanner) so an operator can
//! install + scan + quarantine across an entire fleet from the
//! Security page.
//!
//! ## Coverage model
//!
//! One install per *host* covers every workload on it: ClamAV reads
//! the host filesystem directly, which includes every LXC rootfs
//! (`/var/lib/lxc`, `/var/lib/vz/private`), every Docker overlay
//! (`/var/lib/docker`), and every container engine path WolfStack
//! manages. Running VMs are NOT covered — their disks are locked and
//! their filesystems are independent. That's a separate feature
//! (libguestfs / guest-agent driven), explicitly out of scope here.
//!
//! ## Action model
//!
//! - **ClamAV** findings → file path is known + confidence is high.
//!   Default action: **quarantine** the file (chmod 000 + move to
//!   `/var/quarantine/wolfstack/<id>/<basename>`) AND **kill any
//!   processes currently using it** (via fuser / /proc walk). Both
//!   reversible from the UI — restore puts the file back with its
//!   original mode + owner; delete removes it permanently.
//! - **rkhunter** / **chkrootkit** findings → high false-positive rate
//!   on Debian/Proxmox (`/dev/.udev`, `/etc/.pwd.lock`, package-upgrade
//!   transient warnings). Stored as findings + alert only; no auto-action.
//!
//! ## Distros
//!
//! Detected via `/etc/os-release` ID/ID_LIKE. Supported install
//! managers: `apt` (Debian/Ubuntu/Proxmox), `dnf` (Fedora/RHEL/Rocky/
//! Alma), `pacman` (Arch), `zypper` (openSUSE). On Arch, chkrootkit
//! is AUR-only and is reported as `not_available` rather than failed.
//!
//! ## Persistence
//!
//! - `/etc/wolfstack/antivirus.json`           — config
//! - `/etc/wolfstack/antivirus-findings.json`  — last N findings (cap 500)
//! - `/etc/wolfstack/antivirus-quarantine.json` — current quarantine inventory
//! - `/var/quarantine/wolfstack/`              — quarantined file payloads

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;
use std::time::SystemTime;

// ══════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════

const CONFIG_PATH: &str = "/etc/wolfstack/antivirus.json";
const FINDINGS_PATH: &str = "/etc/wolfstack/antivirus-findings.json";
const QUARANTINE_INDEX_PATH: &str = "/etc/wolfstack/antivirus-quarantine.json";
const QUARANTINE_ROOT: &str = "/var/quarantine/wolfstack";
const MAX_FINDINGS_RETAINED: usize = 500;
/// Live-output ring buffer cap for install runs. apt-get install with a
/// fresh ClamAV signature download emits a few hundred lines; 800 gives
/// plenty of headroom without unbounded growth if something goes wrong.
const MAX_INSTALL_LINES: usize = 800;

/// Filesystem subtrees never worth scanning. Kernel-virtual or
/// WolfStack-owned. ClamAV's `--exclude-dir` accepts regex anchored
/// at the start.
const SCAN_EXCLUDE_REGEX: &[&str] = &[
    "^/sys",
    "^/proc",
    "^/dev",
    "^/run",
    "^/var/lib/wolfstack",
    "^/var/quarantine",
    // Live VM disk images — locked, scanning while running can hang or
    // produce false reads.
    "^/var/lib/vz/images",
    "^/var/lib/libvirt/images",
    // Network mounts — typically huge + scanned by their server, not us.
    "^/mnt",
    "^/media",
];

/// Default scan root. Single `/` walks everything else through the
/// excludes above. Operators can override via config.
const DEFAULT_SCAN_ROOT: &str = "/";

// ══════════════════════════════════════════════════════════
// Configuration
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusConfig {
    /// Master enable. When false, no scheduled scans, no auto-action.
    /// On-demand scans from the API still work for verification.
    #[serde(default)]
    pub enabled: bool,
    /// Hours between scheduled scans. 0 = manual only. Clamped to
    /// [1, 168] at apply time when non-zero.
    #[serde(default = "default_schedule_hours")]
    pub schedule_hours: u32,
    /// Quarantine ClamAV-detected files automatically. Default true.
    #[serde(default = "default_true")]
    pub auto_quarantine: bool,
    /// Kill processes currently using a ClamAV-detected file.
    /// Default true. Only triggers when `auto_quarantine` is also true.
    #[serde(default = "default_true")]
    pub auto_kill: bool,
    /// Include ClamAV in scans.
    #[serde(default = "default_true")]
    pub run_clamav: bool,
    /// Include rkhunter in scans.
    #[serde(default = "default_true")]
    pub run_rkhunter: bool,
    /// Include chkrootkit in scans.
    #[serde(default = "default_true")]
    pub run_chkrootkit: bool,
    /// Roots to scan with ClamAV. Defaults to `["/"]` which (combined
    /// with the exclude regex) walks the full host including container
    /// layers.
    #[serde(default = "default_scan_roots")]
    pub scan_roots: Vec<String>,
    /// Additional excludes (regex, ClamAV `--exclude-dir` form).
    /// Appended to `SCAN_EXCLUDE_REGEX`.
    #[serde(default)]
    pub extra_excludes: Vec<String>,
}

fn default_true() -> bool { true }
fn default_schedule_hours() -> u32 { 24 }
fn default_scan_roots() -> Vec<String> { vec![DEFAULT_SCAN_ROOT.into()] }

impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule_hours: default_schedule_hours(),
            auto_quarantine: true,
            auto_kill: true,
            run_clamav: true,
            run_rkhunter: true,
            run_chkrootkit: true,
            scan_roots: default_scan_roots(),
            extra_excludes: Vec::new(),
        }
    }
}

impl AntivirusConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = Path::new(CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into());
        std::fs::write(CONFIG_PATH, body)?;
        let _ = chmod_600(CONFIG_PATH);
        Ok(())
    }

    /// Build the effective exclude-regex list (defaults + user extras).
    pub fn effective_excludes(&self) -> Vec<String> {
        let mut out: Vec<String> = SCAN_EXCLUDE_REGEX.iter().map(|s| s.to_string()).collect();
        out.extend(self.extra_excludes.iter().cloned());
        out
    }
}

// ══════════════════════════════════════════════════════════
// Installation status
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolStatus {
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Last ClamAV signature update timestamp (ClamAV only). Format: RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_db_update: Option<String>,
    /// Set to true when the tool exists in repos but isn't currently
    /// installed (e.g. chkrootkit on Arch — AUR-only, we don't auto-pull).
    #[serde(default)]
    pub not_available_on_distro: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstallStatus {
    pub clamav: ToolStatus,
    pub rkhunter: ToolStatus,
    pub chkrootkit: ToolStatus,
    pub distro: String,
    pub package_manager: String,
}

pub fn detect_install_status() -> InstallStatus {
    let (distro, id_like) = parse_os_release();
    let family = distro_family_with_idlike(&distro, &id_like);
    let pm = pkg_manager_family(family);
    InstallStatus {
        clamav: detect_clamav(),
        rkhunter: detect_simple_binary("rkhunter", "--version"),
        chkrootkit: detect_chkrootkit_family(family),
        distro,
        package_manager: pm.unwrap_or_default(),
    }
}

fn detect_clamav() -> ToolStatus {
    let mut s = detect_simple_binary("clamscan", "--version");
    if !s.installed { return s; }
    // ClamAV signature freshness — read the main.cvd / daily.cvd file
    // mtimes in /var/lib/clamav. Newest mtime wins.
    let dir = Path::new("/var/lib/clamav");
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut newest: Option<SystemTime> = None;
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if !(n.ends_with(".cvd") || n.ends_with(".cld")) { continue; }
            if let Ok(m) = e.metadata() {
                if let Ok(t) = m.modified() {
                    newest = Some(newest.map(|x| x.max(t)).unwrap_or(t));
                }
            }
        }
        if let Some(t) = newest {
            s.last_db_update = Some(format_rfc3339(t));
        }
    }
    s
}

fn detect_simple_binary(bin: &str, version_arg: &str) -> ToolStatus {
    let path = which(bin);
    if path.is_none() {
        return ToolStatus { installed: false, ..Default::default() };
    }
    let version = Command::new(bin).arg(version_arg).output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").trim().to_string())
        } else { None });
    ToolStatus { installed: true, version, last_db_update: None, not_available_on_distro: false }
}

fn detect_chkrootkit_family(family: &str) -> ToolStatus {
    let mut s = detect_simple_binary("chkrootkit", "-V");
    if !s.installed && family == "arch" {
        // Arch / CachyOS / Manjaro core repos don't ship chkrootkit —
        // it's AUR-only.
        s.not_available_on_distro = true;
    }
    s
}

// ══════════════════════════════════════════════════════════
// Distro detection + package manager dispatch
// ══════════════════════════════════════════════════════════

/// `/etc/os-release` ID, lowercased. Kept public so other modules can
/// branch on the raw distro name without re-parsing os-release.
#[allow(dead_code)]
pub fn detect_distro_id() -> String {
    parse_os_release().0
}

/// Parse `/etc/os-release` and return (ID, ID_LIKE) — both lowercased.
/// ID_LIKE is space-separated in the file; we keep it as a single string
/// so callers can split it themselves.
fn parse_os_release() -> (String, String) {
    let text = match std::fs::read_to_string("/etc/os-release") {
        Ok(t) => t, Err(_) => return ("unknown".into(), String::new()),
    };
    let mut id = String::from("unknown");
    let mut id_like = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ID=") {
            id = rest.trim().trim_matches('"').to_ascii_lowercase();
        } else if let Some(rest) = line.strip_prefix("ID_LIKE=") {
            id_like = rest.trim().trim_matches('"').to_ascii_lowercase();
        }
    }
    (id, id_like)
}

#[cfg(test)]
fn distro_family(distro: &str) -> &'static str {
    distro_family_with_idlike(distro, "")
}

/// Resolve a distro family, falling back to ID_LIKE for derivatives
/// the explicit table doesn't know (CachyOS, EndeavourOS variants,
/// downstream RHEL rebuilds, etc.). Match the FIRST entry in ID_LIKE
/// — os-release lists them most-specific-first.
fn distro_family_with_idlike(distro: &str, id_like: &str) -> &'static str {
    let direct = match distro {
        "debian" | "ubuntu" | "proxmox" | "raspbian" | "linuxmint" | "pop" | "kali" => "debian",
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "amzn" => "redhat",
        "arch" | "archlinux" | "manjaro" | "endeavouros" | "garuda" | "cachyos" => "arch",
        "opensuse-leap" | "opensuse-tumbleweed" | "opensuse" | "sles" | "sled" => "suse",
        _ => "unknown",
    };
    if direct != "unknown" { return direct; }
    // Fallback: scan ID_LIKE tokens. Recurse with the first token as a
    // "distro" to reuse the table — never recurses more than once
    // because direct lookups can't return "unknown" inside this path.
    for tok in id_like.split_whitespace() {
        let fam = match tok {
            "debian" | "ubuntu" => "debian",
            "fedora" | "rhel" | "centos" => "redhat",
            "arch" => "arch",
            "opensuse" | "suse" | "sles" => "suse",
            _ => continue,
        };
        return fam;
    }
    "unknown"
}

/// The package manager binary appropriate for the host distro family.
fn pkg_manager_family(family: &str) -> Option<String> {
    match family {
        "debian"  => Some("apt-get".into()),
        "redhat"  => Some("dnf".into()),
        "arch"    => Some("pacman".into()),
        "suse"    => Some("zypper".into()),
        _ => None,
    }
}

/// Build the install command argv for a list of packages on the
/// given distro family. Returns None for unsupported families.
fn build_install_cmd_family(family: &str, packages: &[&str]) -> Option<Vec<String>> {
    match family {
        "debian" => {
            // DEBIAN_FRONTEND=noninteractive is set by the caller via env.
            let mut v = vec!["apt-get".into(), "install".into(), "-y".into(),
                             "--no-install-recommends".into()];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        "redhat" => {
            let mut v = vec!["dnf".into(), "install".into(), "-y".into()];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        "arch" => {
            let mut v = vec!["pacman".into(), "-S".into(), "--noconfirm".into(), "--needed".into()];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        "suse" => {
            let mut v = vec!["zypper".into(), "--non-interactive".into(), "install".into(), "--no-recommends".into()];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        _ => None,
    }
}

/// Package names per distro family. Debian and SUSE name ClamAV
/// `clamav` + a separate `clamav-freshclam`; Fedora ships freshclam
/// in `clamav-update`. rkhunter and chkrootkit are consistent across
/// supported distros except chkrootkit on Arch (AUR, skipped).
fn packages_for_family(family: &str) -> Vec<&'static str> {
    match family {
        "debian" => vec!["clamav", "clamav-freshclam", "rkhunter", "chkrootkit"],
        "redhat" => vec!["clamav", "clamav-update", "rkhunter", "chkrootkit"],
        "arch"   => vec!["clamav", "rkhunter"], // chkrootkit AUR-only — skipped
        "suse"   => vec!["clamav", "rkhunter", "chkrootkit"],
        _        => vec![],
    }
}

// ══════════════════════════════════════════════════════════
// Install action
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct InstallResult {
    pub ok: bool,
    pub distro: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub status: InstallStatus,
}

/// Install ClamAV + rkhunter + chkrootkit on this host using the
/// distro's native package manager. Idempotent — pre-installed
/// packages are skipped by the package manager itself. After install,
/// kicks off `freshclam` once to seed signature DB (best-effort,
/// failures are surfaced but don't fail the install).
/// Run a command with stdout+stderr streamed line-by-line into the
/// install_progress ring buffer. Returns true if the command exited 0.
/// Lines are pushed as they arrive (interactive feel for the UI) and
/// every line is prefixed with the command's short label so the operator
/// can tell apart `apt-get update` output from `freshclam` output in
/// the combined log.
fn run_streaming(
    state: &AntivirusState,
    label: &str,
    argv: &[&str],
    env: &[(&str, &str)],
) -> bool {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    if argv.is_empty() {
        state.push_install_line(format!("[{}] ERROR: empty argv", label));
        return false;
    }
    state.push_install_line(format!("$ {}", argv.join(" ")));

    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env { cmd.env(k, v); }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            state.push_install_line(format!("[{}] ERROR: failed to spawn: {}", label, e));
            return false;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => { state.push_install_line(format!("[{}] ERROR: no stdout pipe", label)); return false; }
    };
    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => { state.push_install_line(format!("[{}] ERROR: no stderr pipe", label)); return false; }
    };

    // Read stdout + stderr concurrently. Using std::thread::scope so we
    // can borrow `state` and `label` directly — no Arc cloning needed
    // because the scope joins both threads before returning.
    std::thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines().map_while(|r| r.ok()) {
                state.push_install_line(line);
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines().map_while(|r| r.ok()) {
                // Tag stderr lines so the UI can colour them differently.
                // apt + dnf emit progress on stderr; rkhunter writes
                // warnings to stderr — keeping them visible is the
                // whole point of streaming.
                state.push_install_line(format!("[stderr] {}", line));
            }
        });
    });

    match child.wait() {
        Ok(s) => s.success(),
        Err(e) => {
            state.push_install_line(format!("[{}] wait() failed: {}", label, e));
            false
        }
    }
}

pub fn install_tools(state: &AntivirusState) -> InstallResult {
    // Mark running and clear any previous log.
    {
        let mut g = state.install_progress.write().unwrap();
        *g = InstallProgress {
            running: true,
            started_at: Some(now_rfc3339()),
            finished_at: None,
            ok: None,
            error: None,
            lines: Vec::new(),
        };
    }

    let (distro, id_like) = parse_os_release();
    let family = distro_family_with_idlike(&distro, &id_like);
    state.push_install_line(format!("==> Detected distro: {} (family: {})", distro, family));

    // Open the firewall holes the install path needs (no-op if the
    // block-outbound.sh lockdown isn't active). We MUST remove these
    // again in finalize_install — caller's responsibility.
    open_install_holes(state);

    let pkgs = packages_for_family(family);
    if pkgs.is_empty() {
        let err = format!(
            "Unsupported distro '{}' (ID_LIKE='{}'). Supported: apt (Debian/Ubuntu/Proxmox), dnf (Fedora/RHEL/Rocky/Alma), pacman (Arch/CachyOS), zypper (openSUSE).",
            distro, id_like);
        state.push_install_line(format!("==> ERROR: {}", err));
        finalize_install(state, false, Some(err.clone()));
        return InstallResult {
            ok: false, distro, command: String::new(),
            stdout: String::new(), stderr: err,
            status: detect_install_status(),
        };
    }

    let argv = match build_install_cmd_family(family, &pkgs) {
        Some(v) => v,
        None => {
            let err = "no package manager command for distro family".to_string();
            state.push_install_line(format!("==> ERROR: {}", err));
            finalize_install(state, false, Some(err.clone()));
            return InstallResult {
                ok: false, distro, command: String::new(),
                stdout: String::new(), stderr: err,
                status: detect_install_status(),
            };
        }
    };
    let cmdline = argv.join(" ");

    // apt-get update first (apt only — dnf/pacman/zypper handle this
    // implicitly on install).
    if family == "debian" {
        state.push_install_line("==> apt-get update".into());
        run_streaming(
            state, "apt-update",
            &["apt-get", "update"],
            &[("DEBIAN_FRONTEND", "noninteractive")],
        );
    }

    // Actual install.
    state.push_install_line(format!("==> Installing: {}", pkgs.join(" ")));
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let install_env: &[(&str, &str)] = if family == "debian" {
        &[("DEBIAN_FRONTEND", "noninteractive")]
    } else { &[] };
    let ok = run_streaming(state, "install", &argv_refs, install_env);

    if !ok {
        state.push_install_line("==> Install command FAILED — see lines above for details.".into());
        finalize_install(state, false, Some("package manager exited non-zero".into()));
        return InstallResult {
            ok: false, distro, command: cmdline,
            stdout: String::new(), stderr: "package manager failed".into(),
            status: detect_install_status(),
        };
    }

    // Seed ClamAV signatures (best-effort).
    if which("freshclam").is_some() {
        state.push_install_line("==> freshclam (seeding ClamAV signatures)".into());
        // On Debian the daemon holds the DB lock — stop, run one-shot, restore.
        let svc_was_active = systemd_is_active("clamav-freshclam.service")
            || systemd_is_active("clamav-freshclam-daemon.service");
        if svc_was_active {
            run_streaming(state, "systemctl", &["systemctl", "stop", "clamav-freshclam.service"], &[]);
        }
        run_streaming(state, "freshclam", &["freshclam"], &[]);
        if svc_was_active {
            run_streaming(state, "systemctl", &["systemctl", "start", "clamav-freshclam.service"], &[]);
        } else {
            run_streaming(state, "systemctl", &["systemctl", "enable", "--now", "clamav-freshclam.service"], &[]);
        }
    }

    // rkhunter signature + property baseline (idempotent).
    if which("rkhunter").is_some() {
        state.push_install_line("==> rkhunter --update".into());
        run_streaming(state, "rkhunter", &["rkhunter", "--update", "--nocolors"], &[]);
        state.push_install_line("==> rkhunter --propupd".into());
        run_streaming(state, "rkhunter", &["rkhunter", "--propupd", "--nocolors"], &[]);
    }

    state.push_install_line("==> Install complete.".into());
    finalize_install(state, true, None);

    InstallResult {
        ok: true, distro, command: cmdline,
        stdout: String::new(), stderr: String::new(),
        status: detect_install_status(),
    }
}

fn finalize_install(state: &AntivirusState, ok: bool, error: Option<String>) {
    // Always close the firewall holes — even on failure paths. The
    // close is idempotent so calling it when no holes were opened
    // is a cheap no-op.
    close_install_holes(state);
    if let Ok(mut g) = state.install_progress.write() {
        g.running = false;
        g.finished_at = Some(now_rfc3339());
        g.ok = Some(ok);
        g.error = error;
    }
}

fn systemd_is_active(unit: &str) -> bool {
    Command::new("systemctl").args(["is-active", "--quiet", unit])
        .status().map(|s| s.success()).unwrap_or(false)
}

// ══════════════════════════════════════════════════════════
// Firewall hole coordination for the block-outbound lockdown
// ══════════════════════════════════════════════════════════
//
// Operators run block-outbound.sh on their Proxmox hosts to default-deny
// outbound. That lockdown breaks apt-get install and freshclam unless
// we open the right holes. We coordinate this here so the operator
// doesn't have to manually run allow-updates.sh + an as-yet-unwritten
// allow-clamav.sh before clicking Install.
//
// Rules we add are tagged `IR-allow-av-install` so they're cleanly
// removable even if WolfStack crashes mid-install (operator can grep
// the tag and delete by hand).

const FIREWALL_TAG: &str = "IR-allow-av-install";

/// Hostnames the antivirus install path reaches beyond apt mirrors —
/// these are NOT in /etc/apt/sources.list and need explicit allowance.
const AV_EXTRA_HOSTS: &[&str] = &[
    // ClamAV signature CDN (freshclam fetches from these).
    "database.clamav.net",
    "db.local.clamav.net",
    "current.cvd.clamav.net",
    // rkhunter signature checks (SourceForge-hosted, redirects across
    // a CDN; the canonical host is enough for the initial connect, and
    // the redirect destinations come back via DNS so they're resolved
    // through our DNS allow rule).
    "rkhunter.sourceforge.net",
    "sourceforge.net",
];

/// True when the block-outbound.sh "default deny" rule is present.
fn lockdown_active() -> bool {
    let out = match Command::new("iptables-save").output() {
        Ok(o) => o, Err(_) => return false,
    };
    String::from_utf8_lossy(&out.stdout).contains("IR-block: default deny")
}

/// Hostnames discovered from /etc/apt/sources.list and sources.list.d.
/// Same parsing logic as allow-updates.sh so we cover ceph.list,
/// docker.list, kcare.list, pve-enterprise.list, etc., without
/// hard-coding.
fn apt_mirror_hosts() -> Vec<String> {
    let mut hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Main sources.list
    if let Ok(s) = std::fs::read_to_string("/etc/apt/sources.list") {
        for url in extract_urls_from(&s) { hosts.insert(url); }
    }
    // .list and .sources under sources.list.d/
    if let Ok(entries) = std::fs::read_dir("/etc/apt/sources.list.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "list" && ext != "sources" { continue; }
            if let Ok(s) = std::fs::read_to_string(&path) {
                for url in extract_urls_from(&s) { hosts.insert(url); }
            }
        }
    }
    // Proxmox-specific extras even if not currently in sources (some
    // helpers fetch from these directly).
    hosts.insert("download.proxmox.com".into());
    hosts.insert("enterprise.proxmox.com".into());
    hosts.into_iter().collect()
}

fn extract_urls_from(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        // Find http:// or https:// and extract the host portion (up to / or whitespace).
        for proto in ["http://", "https://"] {
            let mut start = 0;
            while let Some(idx) = trimmed[start..].find(proto) {
                let abs = start + idx + proto.len();
                let rest = &trimmed[abs..];
                let end = rest.find(|c: char| c == '/' || c.is_whitespace()).unwrap_or(rest.len());
                let host = &rest[..end];
                if !host.is_empty() {
                    // Strip :port if present.
                    let host = host.split(':').next().unwrap_or(host);
                    out.push(host.to_string());
                }
                start = abs + end;
            }
        }
    }
    out
}

fn dns_resolvers() -> Vec<String> {
    let text = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(t) => t, Err(_) => return Vec::new(),
    };
    text.lines()
        .filter_map(|l| l.strip_prefix("nameserver"))
        .map(|r| r.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn resolve_host_ips(host: &str) -> Vec<String> {
    let out = match Command::new("getent").args(["ahosts", host]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let mut ips = std::collections::HashSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(ip) = line.split_whitespace().next() {
            ips.insert(ip.to_string());
        }
    }
    ips.into_iter().collect()
}

/// Insert a single ACCEPT rule with the IR-allow-av-install tag.
/// `family` is "v4" or "v6"; the right binary is selected accordingly.
fn add_accept_rule(family: &str, dest: &str, proto: &str, dport: u16, label: &str) -> bool {
    let bin = if family == "v6" { "ip6tables" } else { "iptables" };
    let comment = format!("{}: {}", FIREWALL_TAG, label);
    let status = Command::new(bin)
        .args(["-I", "OUTPUT", "1", "-d", dest, "-p", proto, "--dport", &dport.to_string(),
               "-j", "ACCEPT", "-m", "comment", "--comment", &comment])
        .status();
    status.map(|s| s.success()).unwrap_or(false)
}

/// Open every outbound hole the install path needs. No-op if the
/// IR-block lockdown isn't active.
pub fn open_install_holes(state: &AntivirusState) {
    if !lockdown_active() {
        state.push_install_line("==> No block-outbound lockdown detected — skipping firewall hole coordination.".into());
        return;
    }
    state.push_install_line(format!("==> block-outbound lockdown detected — opening temporary holes (tag '{}')", FIREWALL_TAG));

    // 1. DNS to configured resolvers — needed to resolve everything else.
    let resolvers = dns_resolvers();
    if resolvers.is_empty() {
        state.push_install_line("[firewall] WARNING: no nameservers in /etc/resolv.conf — install will fail to resolve mirrors.".into());
    }
    for ns in &resolvers {
        let family = if ns.contains(':') { "v6" } else { "v4" };
        add_accept_rule(family, ns, "udp", 53, "DNS");
        add_accept_rule(family, ns, "tcp", 53, "DNS");
        state.push_install_line(format!("[firewall] +DNS to {}", ns));
    }

    // 2. apt mirror hosts.
    let mirrors = apt_mirror_hosts();
    state.push_install_line(format!("[firewall] Found {} apt mirror hostname(s) to whitelist", mirrors.len()));
    for host in &mirrors {
        let ips = resolve_host_ips(host);
        if ips.is_empty() {
            state.push_install_line(format!("[firewall] WARN could not resolve {} — skipping", host));
            continue;
        }
        for ip in &ips {
            let family = if ip.contains(':') { "v6" } else { "v4" };
            add_accept_rule(family, ip, "tcp", 443, &format!("{}:443", host));
            add_accept_rule(family, ip, "tcp", 80,  &format!("{}:80",  host));
        }
        state.push_install_line(format!("[firewall] +{} -> {} IP(s)", host, ips.len()));
    }

    // 3. AV-specific hostnames (ClamAV CDN, rkhunter mirrors).
    for host in AV_EXTRA_HOSTS {
        let ips = resolve_host_ips(host);
        if ips.is_empty() {
            state.push_install_line(format!("[firewall] WARN could not resolve {} — skipping", host));
            continue;
        }
        for ip in &ips {
            let family = if ip.contains(':') { "v6" } else { "v4" };
            add_accept_rule(family, ip, "tcp", 443, &format!("{}:443", host));
            add_accept_rule(family, ip, "tcp", 80,  &format!("{}:80",  host));
        }
        state.push_install_line(format!("[firewall] +{} -> {} IP(s)", host, ips.len()));
    }
}

/// Remove every rule tagged IR-allow-av-install. Safe to call even if
/// `open_install_holes` was never invoked (or already closed) — both
/// iptables-save and the per-rule delete are idempotent here.
pub fn close_install_holes(state: &AntivirusState) {
    let match_str = format!("--comment \"{}", FIREWALL_TAG);
    let mut removed = 0usize;
    for bin in ["iptables", "ip6tables"] {
        let save_bin = format!("{}-save", bin);
        loop {
            let saved = match Command::new(&save_bin).output() {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => break,
            };
            let line = match saved.lines().find(|l| l.contains(&match_str)) {
                Some(l) => l.to_string(), None => break,
            };
            // Convert "-A OUTPUT ..." to "-D OUTPUT ..." and pass each
            // token as a separate arg (iptables doesn't accept a single
            // pre-quoted string).
            let delete_line = line.replacen("-A ", "-D ", 1);
            let argv = match shell_split(&delete_line) {
                Some(v) => v, None => break,
            };
            let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            let status = Command::new(bin).args(&argv_refs).status();
            if status.map(|s| s.success()).unwrap_or(false) {
                removed += 1;
            } else {
                // If iptables refuses to delete a rule we just located,
                // bail to avoid an infinite loop.
                break;
            }
        }
    }
    if removed > 0 {
        state.push_install_line(format!("==> Removed {} firewall hole(s) tagged '{}'", removed, FIREWALL_TAG));
    }
}

/// Tiny shell-style splitter for iptables-save rule lines. They use
/// regular space-separated tokens with `--comment "quoted text"` as the
/// only quoting case. Returns None if quoting is malformed.
fn shell_split(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in s.chars() {
        match ch {
            '"' => in_quote = !in_quote,
            ' ' if !in_quote => {
                if !cur.is_empty() { out.push(std::mem::take(&mut cur)); }
            }
            _ => cur.push(ch),
        }
    }
    if in_quote { return None; }
    if !cur.is_empty() { out.push(cur); }
    Some(out)
}

// ══════════════════════════════════════════════════════════
// Findings + persistence
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// "clamav" | "rkhunter" | "chkrootkit"
    pub scanner: String,
    /// "critical" | "warning" | "info"
    pub severity: String,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    pub detected_at: String,
    /// "quarantined" | "killed_processes" | "alert_only"
    pub action_taken: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_id: Option<String>,
    #[serde(default)]
    pub killed_pids: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub original_mode: u32,
    pub original_uid: u32,
    pub original_gid: u32,
    pub size_bytes: u64,
    pub threat_name: String,
    pub scanner: String,
    pub quarantined_at: String,
}

fn load_findings() -> Vec<Finding> {
    std::fs::read_to_string(FINDINGS_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_findings(v: &[Finding]) -> std::io::Result<()> {
    if let Some(parent) = Path::new(FINDINGS_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(v).unwrap_or_else(|_| "[]".into());
    std::fs::write(FINDINGS_PATH, body)?;
    let _ = chmod_600(FINDINGS_PATH);
    Ok(())
}

fn load_quarantine_index() -> Vec<QuarantineEntry> {
    std::fs::read_to_string(QUARANTINE_INDEX_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_quarantine_index(v: &[QuarantineEntry]) -> std::io::Result<()> {
    if let Some(parent) = Path::new(QUARANTINE_INDEX_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(v).unwrap_or_else(|_| "[]".into());
    std::fs::write(QUARANTINE_INDEX_PATH, body)?;
    let _ = chmod_600(QUARANTINE_INDEX_PATH);
    Ok(())
}

// ══════════════════════════════════════════════════════════
// In-memory state — referenced from AppState
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanState {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_scanner: Option<String>,
    pub progress_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_clamav_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rkhunter_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chkrootkit_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            running: false, started_at: None, completed_at: None,
            active_scanner: None, progress_message: String::new(),
            last_clamav_run: None, last_rkhunter_run: None, last_chkrootkit_run: None,
            last_error: None,
        }
    }
}

/// Live install-run state. The endpoint `GET /api/antivirus/install-log`
/// returns this; the UI polls it to render a terminal-style log box.
#[derive(Debug, Clone, Serialize, Default)]
pub struct InstallProgress {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// `None` while running, then `Some(true|false)` after exit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Ring-buffered log lines (oldest first). Capped at MAX_INSTALL_LINES.
    pub lines: Vec<String>,
}

pub struct AntivirusState {
    pub config: RwLock<AntivirusConfig>,
    pub scan_state: RwLock<ScanState>,
    pub findings: RwLock<Vec<Finding>>,
    pub quarantine: RwLock<Vec<QuarantineEntry>>,
    pub install_status: RwLock<InstallStatus>,
    pub install_progress: RwLock<InstallProgress>,
}

impl AntivirusState {
    pub fn load() -> Self {
        let config = AntivirusConfig::load();
        let findings = load_findings();
        let quarantine = load_quarantine_index();
        // Reconstruct ScanState's "last X run" markers from findings so
        // the UI shows continuity across restarts.
        let mut scan_state = ScanState::default();
        for f in &findings {
            match f.scanner.as_str() {
                "clamav"     => scan_state.last_clamav_run     = Some(f.detected_at.clone()),
                "rkhunter"   => scan_state.last_rkhunter_run   = Some(f.detected_at.clone()),
                "chkrootkit" => scan_state.last_chkrootkit_run = Some(f.detected_at.clone()),
                _ => {}
            }
        }
        let install_status = detect_install_status();
        Self {
            config: RwLock::new(config),
            scan_state: RwLock::new(scan_state),
            findings: RwLock::new(findings),
            quarantine: RwLock::new(quarantine),
            install_status: RwLock::new(install_status),
            install_progress: RwLock::new(InstallProgress::default()),
        }
    }

    pub fn refresh_install_status(&self) {
        let s = detect_install_status();
        if let Ok(mut g) = self.install_status.write() { *g = s; }
    }

    /// Append a line to the rolling install log. Caller is responsible
    /// for not flooding (we trim to MAX_INSTALL_LINES from the front to
    /// keep memory bounded even on a misbehaving subprocess).
    pub fn push_install_line(&self, line: String) {
        if let Ok(mut g) = self.install_progress.write() {
            g.lines.push(line);
            if g.lines.len() > MAX_INSTALL_LINES {
                let drop = g.lines.len() - MAX_INSTALL_LINES;
                g.lines.drain(..drop);
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
// ClamAV scan
// ══════════════════════════════════════════════════════════

/// One ClamAV hit as parsed from `clamscan --infected` output.
#[derive(Debug, Clone)]
struct ClamHit {
    path: String,
    threat: String,
}

/// Run clamscan over the configured scan roots. Returns the list of
/// hits. Never panics — clamscan returning non-zero (which it does
/// when it finds anything) is treated as a normal "has hits" path.
fn run_clamav_scan(cfg: &AntivirusConfig) -> Result<Vec<ClamHit>, String> {
    if which("clamscan").is_none() {
        return Err("clamscan binary not found — install ClamAV first".into());
    }
    let mut args: Vec<String> = vec![
        "-r".into(),         // recursive
        "--infected".into(), // only print hits
        "--no-summary".into(),
        // Stay on one filesystem boundary per root? No — we WANT to
        // descend into bind mounts because that's where container
        // rootfs trees live.
    ];
    for ex in cfg.effective_excludes() {
        args.push(format!("--exclude-dir={}", ex));
    }
    // Skip files clamscan can't read (locked, deleted under us).
    args.push("--max-filesize=200M".into());
    args.push("--max-scansize=2000M".into());
    args.push("--cross-fs=yes".into());
    for root in &cfg.scan_roots { args.push(root.clone()); }

    let output = Command::new("clamscan").args(&args).output()
        .map_err(|e| format!("failed to exec clamscan: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // clamscan exit codes:
    //   0 = no virus
    //   1 = virus found
    //   2 = error
    let code = output.status.code().unwrap_or(-1);
    if code == 2 {
        return Err(format!(
            "clamscan reported errors (code 2). stderr={}",
            stderr.chars().take(400).collect::<String>()));
    }

    Ok(parse_clamav_output(&stdout))
}

/// Parse `clamscan --infected` output. Lines look like:
///   /path/to/file: Threat.Name.Variant FOUND
/// The path may contain ": " in theory but in practice clamscan emits
/// only one ": " — the separator before the threat name. We split on
/// the LAST " FOUND" suffix and the LAST ": " before it to be safe.
fn parse_clamav_output(s: &str) -> Vec<ClamHit> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if !line.ends_with(" FOUND") { continue; }
        let body = &line[..line.len() - " FOUND".len()];
        if let Some(idx) = body.rfind(": ") {
            let path = body[..idx].trim().to_string();
            let threat = body[idx + 2..].trim().to_string();
            if path.is_empty() || threat.is_empty() { continue; }
            out.push(ClamHit { path, threat });
        }
    }
    out
}

// ══════════════════════════════════════════════════════════
// rkhunter scan
// ══════════════════════════════════════════════════════════

fn run_rkhunter_scan() -> Result<Vec<Finding>, String> {
    if which("rkhunter").is_none() {
        return Err("rkhunter binary not found".into());
    }
    let output = Command::new("rkhunter")
        .args(["--check", "--skip-keypress", "--report-warnings-only",
               "--nocolors", "--no-mail-on-warning"])
        .output()
        .map_err(|e| format!("failed to exec rkhunter: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // rkhunter exit codes:
    //   0 = no warnings
    //   1 = warnings (still a successful run)
    //   2 = warnings + errors
    //   non-zero with empty output = real failure
    let code = output.status.code().unwrap_or(-1);
    if code > 2 && stdout.trim().is_empty() {
        return Err(format!("rkhunter exited {} with no output. stderr={}",
            code, stderr.chars().take(400).collect::<String>()));
    }
    Ok(parse_rkhunter_output(&stdout))
}

/// Parse rkhunter --report-warnings-only stdout. Warning lines:
///   Warning: <text>
/// Sometimes wrapped:
///   [13:42:01] Warning: <text>
fn parse_rkhunter_output(s: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let now = now_rfc3339();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Strip leading "[HH:MM:SS] " timestamp if rkhunter emitted it.
        let stripped = if line.starts_with('[') {
            line.find("] ").map(|i| line[i+2..].trim()).unwrap_or(line)
        } else { line };
        let Some(rest) = stripped.strip_prefix("Warning:")
            .or_else(|| stripped.strip_prefix("WARNING:")) else { continue; };
        let detail = rest.trim();
        if detail.is_empty() { continue; }
        out.push(Finding {
            id: new_id(),
            scanner: "rkhunter".into(),
            severity: "warning".into(),
            title: detail.chars().take(120).collect(),
            detail: detail.into(),
            path: None, threat_name: None,
            detected_at: now.clone(),
            action_taken: "alert_only".into(),
            quarantine_id: None,
            killed_pids: Vec::new(),
        });
    }
    out
}

// ══════════════════════════════════════════════════════════
// chkrootkit scan
// ══════════════════════════════════════════════════════════

fn run_chkrootkit_scan() -> Result<Vec<Finding>, String> {
    if which("chkrootkit").is_none() {
        return Err("chkrootkit binary not found".into());
    }
    let output = Command::new("chkrootkit").output()
        .map_err(|e| format!("failed to exec chkrootkit: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(parse_chkrootkit_output(&stdout))
}

/// chkrootkit output is a sequence of "Checking `name'... result" lines.
/// Findings are lines where the result is NOT one of the known-clean
/// stock strings.
fn parse_chkrootkit_output(s: &str) -> Vec<Finding> {
    const CLEAN_TOKENS: &[&str] = &[
        "not infected", "not found", "nothing found", "no suspect",
        "not promiscuous", "no suspicious files", "clean",
    ];
    let now = now_rfc3339();
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Filter to result lines.
        let Some(idx) = line.find("...") else {
            // chkrootkit also prints standalone "INFECTED" hits.
            if line.contains("INFECTED") || line.contains("infected") {
                if !CLEAN_TOKENS.iter().any(|t| line.contains(t)) {
                    out.push(Finding {
                        id: new_id(),
                        scanner: "chkrootkit".into(),
                        severity: "critical".into(),
                        title: line.chars().take(120).collect(),
                        detail: line.into(),
                        path: None, threat_name: None,
                        detected_at: now.clone(),
                        action_taken: "alert_only".into(),
                        quarantine_id: None,
                        killed_pids: Vec::new(),
                    });
                }
            }
            continue;
        };
        let result = line[idx + 3..].trim().to_ascii_lowercase();
        if result.is_empty() { continue; }
        if CLEAN_TOKENS.iter().any(|t| result.contains(t)) { continue; }
        // Anything else is a hit worth surfacing.
        let severity = if result.contains("infected") || result.contains("found") {
            "critical"
        } else {
            "warning"
        };
        out.push(Finding {
            id: new_id(),
            scanner: "chkrootkit".into(),
            severity: severity.into(),
            title: line.chars().take(120).collect(),
            detail: line.into(),
            path: None, threat_name: None,
            detected_at: now.clone(),
            action_taken: "alert_only".into(),
            quarantine_id: None,
            killed_pids: Vec::new(),
        });
    }
    out
}

// ══════════════════════════════════════════════════════════
// Quarantine + process kill
// ══════════════════════════════════════════════════════════

/// Move `path` into the quarantine root, preserving original
/// permissions / owner in the index entry so restore is exact.
/// Returns the new QuarantineEntry.
pub fn quarantine_file(
    path: &str, threat_name: &str, scanner: &str,
) -> Result<QuarantineEntry, String> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::MetadataExt;

    let p = Path::new(path);
    let meta = std::fs::metadata(p)
        .map_err(|e| format!("stat {}: {}", path, e))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path));
    }
    let id = new_id();
    let dest_dir = PathBuf::from(QUARANTINE_ROOT).join(&id);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("create {}: {}", dest_dir.display(), e))?;
    let _ = chmod_path(&dest_dir, 0o700);

    let basename = p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let dest = dest_dir.join(&basename);

    // chmod 000 BEFORE moving so any concurrent reader gets EACCES the
    // moment we begin.
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000));
    // Try rename first (cheap, atomic, same-filesystem). If that fails
    // because the source crosses a filesystem boundary, fall back to
    // copy + remove.
    if let Err(_) = std::fs::rename(p, &dest) {
        std::fs::copy(p, &dest)
            .map_err(|e| format!("copy {} -> {}: {}", path, dest.display(), e))?;
        std::fs::remove_file(p)
            .map_err(|e| format!("remove {} after copy: {}", path, e))?;
    }
    let _ = chmod_path(&dest, 0o000);

    let entry = QuarantineEntry {
        id,
        original_path: path.to_string(),
        quarantined_path: dest.display().to_string(),
        original_mode: meta.permissions().mode() & 0o7777,
        original_uid: meta.uid(),
        original_gid: meta.gid(),
        size_bytes: meta.size(),
        threat_name: threat_name.into(),
        scanner: scanner.into(),
        quarantined_at: now_rfc3339(),
    };
    Ok(entry)
}

/// Move a quarantined file back to its original path with original
/// mode / owner. Updates the on-disk index to remove the entry.
pub fn restore_quarantined(state: &AntivirusState, id: &str) -> Result<(), String> {
    use std::os::unix::fs::chown;
    use std::os::unix::fs::PermissionsExt;
    let (entry, removed_idx) = {
        let g = state.quarantine.read().map_err(|_| "lock poisoned".to_string())?;
        let idx = g.iter().position(|e| e.id == id)
            .ok_or_else(|| format!("quarantine entry {} not found", id))?;
        (g[idx].clone(), idx)
    };
    let dest = Path::new(&entry.original_path);
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if dest.exists() {
        return Err(format!(
            "refusing to restore: {} already exists. Move it aside first.",
            entry.original_path));
    }
    std::fs::rename(&entry.quarantined_path, dest)
        .or_else(|_| std::fs::copy(&entry.quarantined_path, dest).map(|_| ()))
        .map_err(|e| format!("restore move failed: {}", e))?;
    // Set permissions + ownership before announcing success.
    let _ = std::fs::set_permissions(dest,
        std::fs::Permissions::from_mode(entry.original_mode));
    let _ = chown(dest, Some(entry.original_uid), Some(entry.original_gid));
    // Clean up the now-empty quarantine subdir.
    if let Some(parent) = Path::new(&entry.quarantined_path).parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
    // Persist index — drop the entry.
    {
        let mut g = state.quarantine.write().map_err(|_| "lock poisoned".to_string())?;
        g.remove(removed_idx);
        save_quarantine_index(&g).map_err(|e| format!("save index: {}", e))?;
    }
    Ok(())
}

/// Permanently delete a quarantined entry. The on-disk payload is
/// shredded if `shred` is available, otherwise normal unlink.
pub fn delete_quarantined(state: &AntivirusState, id: &str) -> Result<(), String> {
    let (entry, removed_idx) = {
        let g = state.quarantine.read().map_err(|_| "lock poisoned".to_string())?;
        let idx = g.iter().position(|e| e.id == id)
            .ok_or_else(|| format!("quarantine entry {} not found", id))?;
        (g[idx].clone(), idx)
    };
    let payload = Path::new(&entry.quarantined_path);
    if payload.exists() {
        if which("shred").is_some() {
            let _ = Command::new("shred").args(["-u", "-z", "-n", "1"])
                .arg(payload).output();
        }
        // shred -u removes; if shred missing or failed, fall back to unlink.
        if payload.exists() {
            let _ = std::fs::remove_file(payload);
        }
    }
    // Clean up containing dir.
    if let Some(parent) = payload.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
    {
        let mut g = state.quarantine.write().map_err(|_| "lock poisoned".to_string())?;
        g.remove(removed_idx);
        save_quarantine_index(&g).map_err(|e| format!("save index: {}", e))?;
    }
    Ok(())
}

/// Best-effort enumeration of PIDs currently using `path`. Tries
/// `fuser` first (most accurate), then walks /proc/*/exe + /proc/*/maps
/// as a fallback so we still get something on hosts without fuser.
pub fn pids_using(path: &str) -> Vec<i32> {
    let mut pids: HashSet<i32> = HashSet::new();
    if which("fuser").is_some() {
        if let Ok(out) = Command::new("fuser").arg(path).output() {
            // fuser writes PIDs to stderr (yes, really) prefixed with the path.
            let s = String::from_utf8_lossy(&out.stderr);
            for tok in s.split_whitespace() {
                if let Ok(p) = tok.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<i32>() {
                    if p > 0 { pids.insert(p); }
                }
            }
            let s2 = String::from_utf8_lossy(&out.stdout);
            for tok in s2.split_whitespace() {
                if let Ok(p) = tok.parse::<i32>() {
                    if p > 0 { pids.insert(p); }
                }
            }
        }
    }
    // /proc walk fallback / supplement — catches the case where the
    // binary has been deleted (shows up as "/path (deleted)") and fuser
    // can't find it any more.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if !n.chars().all(|c| c.is_ascii_digit()) { continue; }
            let pid: i32 = match n.parse() { Ok(p) => p, Err(_) => continue };
            // exe symlink
            if let Ok(target) = std::fs::read_link(e.path().join("exe")) {
                let t = target.to_string_lossy();
                let t_stripped = t.trim_end_matches(" (deleted)");
                if t_stripped == path { pids.insert(pid); continue; }
            }
            // maps — for libraries loaded as shared objects
            if let Ok(maps) = std::fs::read_to_string(e.path().join("maps")) {
                if maps.contains(path) { pids.insert(pid); }
            }
        }
    }
    let mut v: Vec<i32> = pids.into_iter().collect();
    v.sort();
    v
}

/// SIGKILL each PID. Returns the PIDs that were successfully signalled.
pub fn kill_pids(pids: &[i32]) -> Vec<i32> {
    let mut killed = Vec::new();
    for &pid in pids {
        if pid <= 1 { continue; }  // never touch PID 1
        // Skip kernel threads (PPID==2). Killing one would do nothing
        // useful and `kill -9` on them returns EPERM anyway.
        if is_kernel_thread(pid) { continue; }
        let r = Command::new("kill").args(["-9", &pid.to_string()]).status();
        if r.map(|s| s.success()).unwrap_or(false) {
            killed.push(pid);
        }
    }
    killed
}

fn is_kernel_thread(pid: i32) -> bool {
    let stat = match std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s, Err(_) => return false,
    };
    // /proc/PID/stat: pid (comm) state ppid ...
    // comm can contain spaces — find the last ')'.
    if let Some(close) = stat.rfind(')') {
        let tail = &stat[close+1..];
        let parts: Vec<&str> = tail.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(ppid) = parts[1].parse::<i32>() {
                return ppid == 2 || ppid == 0;
            }
        }
    }
    false
}

// ══════════════════════════════════════════════════════════
// Top-level scan orchestration
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunSummary {
    pub started_at: String,
    pub completed_at: String,
    pub clamav_hits: usize,
    pub rkhunter_findings: usize,
    pub chkrootkit_findings: usize,
    pub quarantined: usize,
    pub processes_killed: usize,
    pub errors: Vec<String>,
}

/// Run every configured scanner sequentially. ClamAV first (longest
/// runner gets started while other tools could be skipped), then the
/// rootkit checks. New findings are appended to the persisted history.
///
/// Blocking — caller is expected to wrap in `tokio::task::spawn_blocking`
/// or run from a dedicated thread. Updates `state.scan_state` as it
/// progresses so the UI can show live status.
pub fn run_full_scan(state: &AntivirusState) -> ScanRunSummary {
    let started_at = now_rfc3339();
    {
        let mut s = state.scan_state.write().unwrap();
        s.running = true;
        s.started_at = Some(started_at.clone());
        s.completed_at = None;
        s.active_scanner = None;
        s.progress_message = "Starting scan…".into();
        s.last_error = None;
    }

    let cfg = state.config.read().unwrap().clone();
    let mut summary = ScanRunSummary {
        started_at: started_at.clone(),
        completed_at: String::new(),
        clamav_hits: 0,
        rkhunter_findings: 0,
        chkrootkit_findings: 0,
        quarantined: 0,
        processes_killed: 0,
        errors: Vec::new(),
    };

    // ─── ClamAV ─────────────────────────────────────────
    if cfg.run_clamav && which("clamscan").is_some() {
        {
            let mut s = state.scan_state.write().unwrap();
            s.active_scanner = Some("clamav".into());
            s.progress_message = "Running ClamAV signature scan…".into();
        }
        match run_clamav_scan(&cfg) {
            Ok(hits) => {
                summary.clamav_hits = hits.len();
                handle_clamav_hits(state, &cfg, &hits, &mut summary);
                let mut s = state.scan_state.write().unwrap();
                s.last_clamav_run = Some(now_rfc3339());
            }
            Err(e) => {
                summary.errors.push(format!("clamav: {}", e));
                let mut s = state.scan_state.write().unwrap();
                s.last_error = Some(format!("clamav: {}", e));
            }
        }
    }

    // ─── rkhunter ───────────────────────────────────────
    if cfg.run_rkhunter && which("rkhunter").is_some() {
        {
            let mut s = state.scan_state.write().unwrap();
            s.active_scanner = Some("rkhunter".into());
            s.progress_message = "Running rkhunter rootkit scan…".into();
        }
        match run_rkhunter_scan() {
            Ok(findings) => {
                summary.rkhunter_findings = findings.len();
                append_findings(state, findings);
                let mut s = state.scan_state.write().unwrap();
                s.last_rkhunter_run = Some(now_rfc3339());
            }
            Err(e) => {
                summary.errors.push(format!("rkhunter: {}", e));
                let mut s = state.scan_state.write().unwrap();
                s.last_error = Some(format!("rkhunter: {}", e));
            }
        }
    }

    // ─── chkrootkit ─────────────────────────────────────
    if cfg.run_chkrootkit && which("chkrootkit").is_some() {
        {
            let mut s = state.scan_state.write().unwrap();
            s.active_scanner = Some("chkrootkit".into());
            s.progress_message = "Running chkrootkit scan…".into();
        }
        match run_chkrootkit_scan() {
            Ok(findings) => {
                summary.chkrootkit_findings = findings.len();
                append_findings(state, findings);
                let mut s = state.scan_state.write().unwrap();
                s.last_chkrootkit_run = Some(now_rfc3339());
            }
            Err(e) => {
                summary.errors.push(format!("chkrootkit: {}", e));
                let mut s = state.scan_state.write().unwrap();
                s.last_error = Some(format!("chkrootkit: {}", e));
            }
        }
    }

    let completed_at = now_rfc3339();
    summary.completed_at = completed_at.clone();
    {
        let mut s = state.scan_state.write().unwrap();
        s.running = false;
        s.completed_at = Some(completed_at);
        s.active_scanner = None;
        s.progress_message = if summary.errors.is_empty() {
            "Scan complete.".into()
        } else {
            format!("Scan completed with {} error(s).", summary.errors.len())
        };
    }
    summary
}

/// Convert ClamAV hits into Finding records, optionally
/// quarantining + killing processes per the config.
fn handle_clamav_hits(
    state: &AntivirusState,
    cfg: &AntivirusConfig,
    hits: &[ClamHit],
    summary: &mut ScanRunSummary,
) {
    let mut new_findings: Vec<Finding> = Vec::new();
    let mut new_quarantine: Vec<QuarantineEntry> = Vec::new();
    let now = now_rfc3339();

    for hit in hits {
        let mut killed_pids: Vec<i32> = Vec::new();
        let mut action = "alert_only".to_string();
        let mut quarantine_id: Option<String> = None;

        if cfg.auto_quarantine {
            // Kill processes BEFORE moving the file so they don't get
            // weird EACCES surprises mid-syscall.
            if cfg.auto_kill {
                let pids = pids_using(&hit.path);
                if !pids.is_empty() {
                    killed_pids = kill_pids(&pids);
                    if !killed_pids.is_empty() {
                        action = "killed_processes".into();
                    }
                }
            }
            match quarantine_file(&hit.path, &hit.threat, "clamav") {
                Ok(entry) => {
                    quarantine_id = Some(entry.id.clone());
                    new_quarantine.push(entry);
                    action = if killed_pids.is_empty() {
                        "quarantined".into()
                    } else {
                        "killed_processes_and_quarantined".into()
                    };
                }
                Err(e) => {
                    summary.errors.push(format!("quarantine {}: {}", hit.path, e));
                }
            }
        }

        if !killed_pids.is_empty() {
            summary.processes_killed += killed_pids.len();
        }
        if quarantine_id.is_some() {
            summary.quarantined += 1;
        }

        new_findings.push(Finding {
            id: new_id(),
            scanner: "clamav".into(),
            severity: "critical".into(),
            title: format!("ClamAV: {}", hit.threat),
            detail: format!("Detected '{}' in {}", hit.threat, hit.path),
            path: Some(hit.path.clone()),
            threat_name: Some(hit.threat.clone()),
            detected_at: now.clone(),
            action_taken: action,
            quarantine_id,
            killed_pids,
        });
    }

    if !new_quarantine.is_empty() {
        if let Ok(mut g) = state.quarantine.write() {
            for e in new_quarantine { g.push(e); }
            let _ = save_quarantine_index(&g);
        }
    }
    append_findings(state, new_findings);
}

/// Prepend new findings to the in-memory + on-disk list, capped at
/// `MAX_FINDINGS_RETAINED`. New findings appear at the top so the
/// UI shows the latest run first.
fn append_findings(state: &AntivirusState, mut new_findings: Vec<Finding>) {
    if new_findings.is_empty() { return; }
    if let Ok(mut g) = state.findings.write() {
        new_findings.append(&mut g.clone());
        if new_findings.len() > MAX_FINDINGS_RETAINED {
            new_findings.truncate(MAX_FINDINGS_RETAINED);
        }
        *g = new_findings;
        let _ = save_findings(&g);
    }
}

// ══════════════════════════════════════════════════════════
// Scheduled scan tick (called from main.rs background loop)
// ══════════════════════════════════════════════════════════

/// If the configured schedule is due, fire a full scan in a blocking
/// thread. Returns immediately if not due or if a scan is already
/// running. Designed to be invoked from a low-cadence tokio interval
/// (e.g. every 5 minutes); the blocking work is offloaded.
pub fn maybe_run_scheduled_scan(state: std::sync::Arc<AntivirusState>) {
    let cfg = match state.config.read() { Ok(g) => g.clone(), Err(_) => return };
    if !cfg.enabled || cfg.schedule_hours == 0 { return; }
    if state.scan_state.read().map(|s| s.running).unwrap_or(false) { return; }

    // Most recent completed run across all three scanners.
    let last = {
        let s = state.scan_state.read().unwrap();
        [s.last_clamav_run.clone(), s.last_rkhunter_run.clone(),
         s.last_chkrootkit_run.clone()]
            .into_iter().flatten().max()
    };
    let due = match last {
        None => true,
        Some(ts) => {
            match chrono::DateTime::parse_from_rfc3339(&ts) {
                Ok(t) => {
                    let secs = chrono::Utc::now().signed_duration_since(t).num_seconds();
                    secs >= cfg.schedule_hours as i64 * 3600
                }
                Err(_) => true,
            }
        }
    };
    if !due { return; }

    let state_for_thread = state.clone();
    std::thread::spawn(move || {
        let _ = run_full_scan(&state_for_thread);
    });
}

// ══════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════

fn now_rfc3339() -> String { chrono::Utc::now().to_rfc3339() }

fn format_rfc3339(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.to_rfc3339()
}

fn new_id() -> String {
    // 16 hex chars from /dev/urandom — collision-resistant for our
    // workload (a few hundred quarantine entries ever).
    use std::io::Read;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn which(bin: &str) -> Option<PathBuf> {
    // Honour PATH from the environment, but always add /usr/local/sbin,
    // /usr/sbin, /sbin first because most AV/IDS binaries live there
    // and minimal shells (cron, systemd unit Environment=…) often miss
    // them.
    let mut paths: Vec<PathBuf> = vec![
        "/usr/local/sbin".into(), "/usr/sbin".into(), "/sbin".into(),
        "/usr/local/bin".into(), "/usr/bin".into(), "/bin".into(),
    ];
    if let Ok(p) = std::env::var("PATH") {
        for s in p.split(':') {
            let pb: PathBuf = s.into();
            if !paths.iter().any(|x| x == &pb) { paths.push(pb); }
        }
    }
    for p in paths {
        let candidate = p.join(bin);
        if candidate.is_file() {
            // executable check — st_mode & 0o111
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::metadata(&candidate) {
                if m.permissions().mode() & 0o111 != 0 {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn chmod_600(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn chmod_path(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

// ══════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamav_output_parsing() {
        let s = "/tmp/eicar.com: Eicar-Signature FOUND\n\
                 /var/lib/lxc/web/rootfs/tmp/x: Linux.Trojan.Kinsing FOUND\n\
                 ----------- SCAN SUMMARY -----------\n";
        let hits = parse_clamav_output(s);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].path, "/tmp/eicar.com");
        assert_eq!(hits[0].threat, "Eicar-Signature");
        assert_eq!(hits[1].path, "/var/lib/lxc/web/rootfs/tmp/x");
        assert_eq!(hits[1].threat, "Linux.Trojan.Kinsing");
    }

    #[test]
    fn rkhunter_output_parsing() {
        let s = "[13:42:00] Info: Starting test\n\
                 [13:42:01] Warning: /usr/bin/ssh-keysign property changed\n\
                 [13:42:02] Warning: Hidden file found: /etc/.pwd.lock\n\
                 [13:42:03] Info: All clean\n";
        let f = parse_rkhunter_output(s);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, "warning");
        assert!(f[0].detail.contains("ssh-keysign"));
    }

    #[test]
    fn chkrootkit_output_parsing_clean_lines_ignored() {
        let s = "Checking `aliens'... no suspicious files\n\
                 Checking `asp'... not infected\n\
                 Checking `bindshell'... INFECTED (PORTS:  31337)\n";
        let f = parse_chkrootkit_output(s);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("INFECTED"));
    }

    #[test]
    fn distro_family_resolution() {
        assert_eq!(distro_family("debian"), "debian");
        assert_eq!(distro_family("ubuntu"), "debian");
        assert_eq!(distro_family("proxmox"), "debian");
        assert_eq!(distro_family("fedora"), "redhat");
        assert_eq!(distro_family("rocky"), "redhat");
        assert_eq!(distro_family("arch"), "arch");
        assert_eq!(distro_family("cachyos"), "arch");
        assert_eq!(distro_family("opensuse-leap"), "suse");
        assert_eq!(distro_family("plan9"), "unknown");
    }

    #[test]
    fn distro_family_falls_back_to_id_like() {
        // Unknown direct ID, but ID_LIKE points at a known family.
        assert_eq!(distro_family_with_idlike("cachyos", "arch"), "arch");
        assert_eq!(distro_family_with_idlike("garuda", "arch"), "arch");
        assert_eq!(distro_family_with_idlike("almalinux", "rhel centos fedora"), "redhat");
        assert_eq!(distro_family_with_idlike("popnewdistro", "ubuntu debian"), "debian");
        // No match anywhere → unknown.
        assert_eq!(distro_family_with_idlike("solaris", "unix"), "unknown");
    }

    #[test]
    fn install_cmd_shape_per_family() {
        let pkgs = &["clamav", "rkhunter"];
        let debian = build_install_cmd_family("debian", pkgs).unwrap();
        assert_eq!(debian[0], "apt-get");
        assert!(debian.contains(&"-y".to_string()));
        let redhat = build_install_cmd_family("redhat", pkgs).unwrap();
        assert_eq!(redhat[0], "dnf");
        let arch = build_install_cmd_family("arch", pkgs).unwrap();
        assert_eq!(arch[0], "pacman");
        assert!(arch.contains(&"--noconfirm".to_string()));
        let suse = build_install_cmd_family("suse", pkgs).unwrap();
        assert_eq!(suse[0], "zypper");
        assert!(build_install_cmd_family("plan9", pkgs).is_none());
    }

    #[test]
    fn packages_for_family_excludes_arch_chkrootkit() {
        let arch_pkgs = packages_for_family("arch");
        assert!(!arch_pkgs.contains(&"chkrootkit"));
        let debian_pkgs = packages_for_family("debian");
        assert!(debian_pkgs.contains(&"chkrootkit"));
        let redhat_pkgs = packages_for_family("redhat");
        assert!(redhat_pkgs.contains(&"chkrootkit"));
    }

    #[test]
    fn shell_split_handles_quoted_comments() {
        // Real iptables-save line for one of our rules.
        let line = "-A OUTPUT -d 1.2.3.4/32 -p tcp -m tcp --dport 443 -j ACCEPT -m comment --comment \"IR-allow-av-install: deb.debian.org:443\"";
        let parts = shell_split(line).unwrap();
        // The quoted comment must be a single token.
        let comment_idx = parts.iter().position(|p| p.starts_with("IR-allow-av-install:")).unwrap();
        assert!(parts[comment_idx].contains("deb.debian.org:443"));
        // No empty tokens.
        for p in &parts { assert!(!p.is_empty()); }
    }

    #[test]
    fn shell_split_rejects_unterminated_quote() {
        assert!(shell_split("-A OUTPUT -m comment --comment \"unterminated").is_none());
    }

    #[test]
    fn extract_urls_finds_https_and_http_and_strips_port() {
        let s = "
            # comment
            deb https://download.docker.com/linux/debian bookworm stable
            deb http://archive.ubuntu.com/ubuntu jammy main
            deb https://repo.tuxcare.com/kernelcare/ubuntu jammy main
            deb https://mirror.example.com:8443/path foo bar
        ";
        let hosts = extract_urls_from(s);
        assert!(hosts.contains(&"download.docker.com".to_string()));
        assert!(hosts.contains(&"archive.ubuntu.com".to_string()));
        assert!(hosts.contains(&"repo.tuxcare.com".to_string()));
        assert!(hosts.contains(&"mirror.example.com".to_string()));
        // Comment line ignored.
        assert!(!hosts.iter().any(|h| h.starts_with("comment")));
    }

    #[test]
    fn effective_excludes_combines_defaults_and_extras() {
        let cfg = AntivirusConfig {
            extra_excludes: vec!["^/srv/big-data".into()],
            ..AntivirusConfig::default()
        };
        let ex = cfg.effective_excludes();
        assert!(ex.contains(&"^/proc".to_string()));
        assert!(ex.contains(&"^/srv/big-data".to_string()));
    }
}
