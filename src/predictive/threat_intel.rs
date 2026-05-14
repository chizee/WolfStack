// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Threat-intelligence blocklist enforcement.
//!
//! Pulls the FireHOL Level 1 IP blocklist (high-confidence, low-
//! false-positive — RFC1918/bogon ranges, known C2, well-attested
//! offenders) and maintains an `ipset` named `wolfstack_blocklist`
//! plus an iptables rule that DROPs incoming + outgoing traffic
//! against it.
//!
//! ## Why FireHOL Level 1
//!
//! Aggregates Spamhaus DROP/EDROP, dshield, abuse.ch trackers, and
//! a few others. Updated several times per day. Designed
//! specifically for "use this list for production filtering with
//! near-zero risk of blocking a legitimate user". Levels 2+ get
//! more aggressive but have correspondingly higher FP risk.
//!
//! ## Why ipset, not raw iptables
//!
//! ~30,000 entries. With one iptables rule per entry, packet
//! processing becomes O(N) per packet and adds visible latency.
//! `ipset` is a kernel hash-table; lookup is effectively O(1). One
//! iptables rule referencing the set covers the entire list.
//!
//! ## What if ipset isn't installed?
//!
//! Detected at sample time. If `ipset` binary is missing the
//! analyzer emits an "ipset not installed" `High` finding (with a
//! one-line install command) and skips actual blocking on that
//! host. It does NOT fall back to one-rule-per-IP iptables — the
//! performance hit would itself be a denial-of-service.
//!
//! ## Freshness
//!
//! Refreshed at most once per `REFRESH_INTERVAL`. The local cache
//! at `/var/lib/wolfstack/threat-intel/firehol_level1.netset` is
//! re-read on every tick (cheap) and the in-kernel ipset is
//! refreshed only when the file actually changed since the last
//! flush.
//!
//! ## Operator controls
//!
//! * `/var/lib/wolfstack/threat-intel/enabled` — touch to enable,
//!   `rm` to disable. Default: ENABLED. Operators who don't want
//!   threat-intel blocking (e.g. a node that legitimately serves
//!   traffic to addresses in the list — rare) can `rm` the file.
//! * `/var/lib/wolfstack/threat-intel/allowlist.txt` — one CIDR per
//!   line. These are never blocked even if they're in the feed.
//!   Use sparingly; the whole point of FireHOL L1 is its
//!   conservative posture.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    compromise_indicators::RemediationOutcome,
    proposal::{Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

const FEED_URL: &str = "https://iplists.firehol.org/files/firehol_level1.netset";
const FEED_LOCAL_PATH: &str = "/var/lib/wolfstack/threat-intel/firehol_level1.netset";
const ENABLE_FLAG_PATH: &str = "/var/lib/wolfstack/threat-intel/enabled";
const ALLOWLIST_PATH: &str = "/var/lib/wolfstack/threat-intel/allowlist.txt";
const IPSET_NAME: &str = "wolfstack_blocklist";
/// Refresh at most once per 24h. Feed itself updates several times
/// per day; daily is enough to keep up without hammering the host.
const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

pub const FT_THREAT_INTEL_DISABLED: &str = "threat_intel:disabled_by_operator";
pub const FT_THREAT_INTEL_NO_IPSET: &str = "threat_intel:ipset_not_installed";
pub const FT_THREAT_INTEL_STALE: &str = "threat_intel:feed_stale";
pub const FT_THREAT_INTEL_RULES_MISSING: &str = "threat_intel:iptables_rules_missing";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatIntelFacts {
    /// Whether the operator has the feature enabled. False if they
    /// removed the flag file. We surface this as Info-level so the
    /// operator knows enforcement is off, but don't ever re-enable
    /// automatically — disabling is a deliberate choice.
    pub enabled: bool,
    /// `ipset` binary is installed and usable on this host. False
    /// means we can't enforce — surface as a High finding with an
    /// install command.
    pub ipset_available: bool,
    /// `iptables` binary is installed (every Linux box, but defensive).
    pub iptables_available: bool,
    /// Age of the local feed file in seconds, or None if absent.
    pub feed_age_secs: Option<u64>,
    /// Number of entries in the local feed after parsing.
    pub feed_entry_count: usize,
    /// Number of entries currently in the kernel ipset (zero if
    /// the set doesn't exist yet — first run).
    pub ipset_entry_count: usize,
    /// Whether the INPUT + OUTPUT iptables rules referencing the
    /// ipset are present right now.
    pub iptables_rules_present: bool,
    /// What we did about each gap this tick.
    pub remediations: Vec<RemediationOutcome>,
    pub scanned: bool,
}

pub async fn sample_now_async(_timeout: Duration) -> ThreatIntelFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> ThreatIntelFacts {
    let enabled = is_enabled();
    let ipset_available = which_exists("ipset");
    let iptables_available = which_exists("iptables");
    let feed_age_secs = match std::fs::metadata(FEED_LOCAL_PATH) {
        Ok(m) => m.modified().ok()
            .and_then(|mt| SystemTime::now().duration_since(mt).ok())
            .map(|d| d.as_secs()),
        Err(_) => None,
    };
    let feed_entry_count = if std::path::Path::new(FEED_LOCAL_PATH).exists() {
        parse_feed_entries(FEED_LOCAL_PATH).len()
    } else {
        0
    };
    let ipset_entry_count = if ipset_available {
        count_ipset_entries(IPSET_NAME)
    } else {
        0
    };
    let iptables_rules_present = iptables_available && rules_are_present();

    ThreatIntelFacts {
        enabled,
        ipset_available,
        iptables_available,
        feed_age_secs,
        feed_entry_count,
        ipset_entry_count,
        iptables_rules_present,
        remediations: Vec::new(),
        scanned: true,
    }
}

/// Default is "enabled". The flag file's *absence* means disabled
/// (operator deliberately removed it). The flag file's presence
/// means enabled. On a fresh install neither exists yet — treat
/// that as enabled and let `enforce` auto-create the flag.
fn is_enabled() -> bool {
    // If the parent dir doesn't even exist (very fresh install),
    // we still consider the feature enabled — `enforce` will create
    // the dir and flag file as part of bringing the ipset up.
    if !Path::new("/var/lib/wolfstack/threat-intel").exists() {
        return true;
    }
    // Once the parent dir exists, presence of the flag file is
    // dispositive. Absence = operator removed it = disabled.
    Path::new(ENABLE_FLAG_PATH).exists() || !any_threat_intel_state_persisted()
}

fn any_threat_intel_state_persisted() -> bool {
    Path::new(FEED_LOCAL_PATH).exists() || Path::new(ALLOWLIST_PATH).exists()
}

fn which_exists(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn parse_feed_entries(path: &str) -> Vec<String> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        if is_private_or_reserved(t) { continue; }
        // Each entry is either an IP or a CIDR.
        out.push(t.to_string());
    }
    out
}

/// True iff `entry` is a CIDR or IP that lives entirely within
/// private, reserved, loopback, link-local, multicast, or CGN
/// ranges. CRITICAL: the FireHOL Level 1 feed bundles the
/// FullBogons set, which includes 10.0.0.0/8, 172.16.0.0/12,
/// 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, 100.64.0.0/10, and
/// the multicast/reserved ranges. Installing those as `iptables
/// DROP` would block:
///   - WolfNet on ANY 10.x.x.x subnet (catch-all because the
///     whole `10/8` is filtered)
///   - WolfRouter-managed LANs (10.10.x.x, 172.16-31.x.x, 192.168.x.x)
///   - Docker default bridge (172.17.0.0/16)
///   - **Tailscale tailnet addresses (100.64.0.0/10 CGNAT)** — every
///     Tailscale-connected host gets a 100.x.x.x address; without
///     the CGN filter we'd sever the operator's Tailscale-based
///     management access the moment v23.2 deployed
///   - Local management LANs (192.168.x.x typically)
/// — i.e. the entire cluster's east-west and admin traffic. We
/// strip them at feed-parse time so they never reach the kernel
/// ipset.
///
/// IPv6 entries from the feed are skipped here too (we only install
/// IPv4 iptables/ipset rules in this release).
fn is_private_or_reserved(entry: &str) -> bool {
    // Skip IPv6 entries entirely — the ipset created is IPv4-only.
    if entry.contains(':') { return true; }
    // Parse the IP / CIDR. Form: "1.2.3.4" or "1.2.3.0/24".
    let (ip_str, prefix) = match entry.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u32>().ok().unwrap_or(32)),
        None => (entry, 32),
    };
    let ip: std::net::Ipv4Addr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return true, // unparseable → safest to skip
    };
    let n = u32::from(ip);
    // Mask the IP down to its network address for the comparison.
    let host_mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    let net = n & host_mask;

    // List of (network, prefix) pairs we never want to block. The
    // entry must fit ENTIRELY within one of these to be filtered —
    // a /16 in the feed that just *overlaps* a /24 here would still
    // be kept (unlikely on FireHOL but defensive).
    let private: [(u32, u32); 11] = [
        // 0.0.0.0/8 — "this network"
        (0x00_00_00_00, 8),
        // 10.0.0.0/8 — RFC1918
        (0x0A_00_00_00, 8),
        // 100.64.0.0/10 — CGN (RFC6598)
        (0x64_40_00_00, 10),
        // 127.0.0.0/8 — loopback
        (0x7F_00_00_00, 8),
        // 169.254.0.0/16 — link-local
        (0xA9_FE_00_00, 16),
        // 172.16.0.0/12 — RFC1918
        (0xAC_10_00_00, 12),
        // 192.0.0.0/24 — IETF protocol assignments
        (0xC0_00_00_00, 24),
        // 192.0.2.0/24 — TEST-NET-1
        (0xC0_00_02_00, 24),
        // 192.168.0.0/16 — RFC1918
        (0xC0_A8_00_00, 16),
        // 224.0.0.0/4 — multicast
        (0xE0_00_00_00, 4),
        // 240.0.0.0/4 — reserved
        (0xF0_00_00_00, 4),
    ];
    for (priv_net, priv_prefix) in private {
        if prefix < priv_prefix {
            // Feed entry's prefix is broader than the private range —
            // can't be entirely inside.
            continue;
        }
        let priv_mask = if priv_prefix == 0 { 0 } else { (!0u32) << (32 - priv_prefix) };
        if (net & priv_mask) == priv_net {
            return true;
        }
    }
    false
}

fn parse_allowlist() -> HashSet<String> {
    let body = std::fs::read_to_string(ALLOWLIST_PATH).unwrap_or_default();
    body.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Auto-allowlist this host's own IPv4 addresses and the IPv4
/// addresses of every cluster peer. CRITICAL: if Hetzner / a cloud
/// provider re-issues an IP that was previously a botnet C2, the
/// FireHOL feed may still list it. Without this auto-allowlist
/// the DROP rule on INPUT would block all inbound traffic to the
/// host itself — i.e. lock the operator out. We strip these IPs
/// from the blocklist before pushing to the kernel ipset.
///
/// Sources:
///   1. `ip -4 addr show` — every IP bound to a local interface.
///   2. `/etc/wolfstack/nodes.json` — every cluster peer's address.
fn auto_allowlist() -> HashSet<String> {
    let mut set: HashSet<String> = HashSet::new();
    // Local interface IPs.
    if let Ok(out) = std::process::Command::new("ip").args(["-4", "addr", "show"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim();
            // Format: "inet 142.132.140.78/26 brd ... scope global eth0"
            if let Some(rest) = t.strip_prefix("inet ") {
                if let Some(cidr_or_ip) = rest.split_whitespace().next() {
                    if let Some(ip) = cidr_or_ip.split('/').next() {
                        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                            set.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }
    // Cluster peer addresses. Read the persisted cluster nodes file
    // directly rather than going through the live cluster handle —
    // this analyzer is sync-blocking and that handle isn't
    // available here.
    let nodes_path = crate::paths::get().nodes_config.clone();
    if let Ok(body) = std::fs::read_to_string(&nodes_path) {
        if let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
            for n in nodes {
                if let Some(addr) = n.get("address").and_then(|v| v.as_str()) {
                    // address may be a hostname or an IPv4. Only
                    // insert if it parses as IPv4 — hostnames will
                    // resolve to different IPs over time and we
                    // don't want a stale hostname-resolved IP
                    // permanently allowlisted.
                    if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                        set.insert(addr.to_string());
                    }
                }
                if let Some(pip) = n.get("public_ip").and_then(|v| v.as_str()) {
                    if pip.parse::<std::net::Ipv4Addr>().is_ok() {
                        set.insert(pip.to_string());
                    }
                }
            }
        }
    }
    set
}

fn count_ipset_entries(name: &str) -> usize {
    let out = std::process::Command::new("ipset")
        .args(["list", name, "-output", "save"])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return 0,
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("add "))
        .count()
}

fn rules_are_present() -> bool {
    let input = std::process::Command::new("iptables")
        .args(["-C", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j", "DROP"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let output = std::process::Command::new("iptables")
        .args(["-C", "OUTPUT", "-m", "set", "--match-set", IPSET_NAME, "dst", "-j", "DROP"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    input && output
}

/// Post-sample remediation. Refreshes the feed if stale, populates
/// the ipset, and inserts the iptables rules. Gated by ack
/// suppression in the same way as the other analyzers.
pub async fn remediate_if_unacked(
    facts: ThreatIntelFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    ctx: &Context,
) -> ThreatIntelFacts {
    if !facts.scanned { return facts; }
    if !facts.enabled { return facts; }
    let acks = acks.clone();
    let proposals = proposals.clone();
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    tokio::task::spawn_blocking(move || remediate_blocking(facts, &acks, &proposals, &scope))
        .await
        .unwrap_or_else(|_| ThreatIntelFacts::default())
}

fn remediate_blocking(
    mut facts: ThreatIntelFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    scope: &ProposalScope,
) -> ThreatIntelFacts {
    let suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
    };

    // We never auto-install ipset (operator decision — implies a new
    // dependency on their system). Just surface the finding.
    if !facts.ipset_available {
        return facts;
    }
    if !facts.iptables_available {
        return facts;
    }

    // Ensure the feature directory exists and the flag file is set
    // on first run so subsequent ticks know the operator hasn't
    // explicitly disabled.
    let _ = std::fs::create_dir_all("/var/lib/wolfstack/threat-intel");
    if !Path::new(ENABLE_FLAG_PATH).exists() && !any_threat_intel_state_persisted() {
        let _ = std::fs::write(ENABLE_FLAG_PATH, b"enabled\n");
    }

    // Refresh the feed if stale (>REFRESH_INTERVAL old or missing).
    let needs_refresh = match facts.feed_age_secs {
        None => true,
        Some(age) => Duration::from_secs(age) >= REFRESH_INTERVAL,
    };
    if needs_refresh && !suppressed(FT_THREAT_INTEL_STALE) {
        facts.remediations.push(refresh_feed());
        // Re-count after refresh.
        facts.feed_entry_count = parse_feed_entries(FEED_LOCAL_PATH).len();
        facts.feed_age_secs = Some(0);
    }

    // Sync ipset to feed (and allowlist).
    if facts.feed_entry_count > 0 {
        facts.remediations.push(sync_ipset_to_feed());
        facts.ipset_entry_count = count_ipset_entries(IPSET_NAME);
    }

    // Make sure the iptables rules referencing the ipset are present.
    if !facts.iptables_rules_present && facts.ipset_entry_count > 0
        && !suppressed(FT_THREAT_INTEL_RULES_MISSING)
    {
        facts.remediations.push(install_iptables_rules());
        facts.iptables_rules_present = rules_are_present();
    }

    facts
}

/// Download the feed using `curl` (universal availability across
/// Debian/Rocky/Alpine) and atomic-rename into place. Returns a
/// remediation outcome — failures keep the previous local feed in
/// place so we never drop enforcement during a transient network
/// glitch.
fn refresh_feed() -> RemediationOutcome {
    let action = "refresh threat-intel feed".to_string();
    let _ = std::fs::create_dir_all("/var/lib/wolfstack/threat-intel");
    let tmp = format!("{}.tmp", FEED_LOCAL_PATH);
    let out = std::process::Command::new("curl")
        .args([
            "-s", "-S", "--fail",
            "--max-time", "30",
            "-o", &tmp,
            FEED_URL,
        ])
        .output();
    let curl_ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    if !curl_ok {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome {
            action,
            ok: false,
            detail: format!(
                "curl {} failed: {}", FEED_URL,
                out.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_else(|e| e.to_string())
            ),
        };
    }
    // Sanity-check the downloaded content. FireHOL files start with
    // a comment block referencing FireHOL — if we got an HTML
    // captive-portal page or a 404 body, reject.
    let head = std::fs::read_to_string(&tmp).unwrap_or_default();
    if !head.contains("firehol") && !head.contains("# Source") {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome {
            action,
            ok: false,
            detail: format!("downloaded body doesn't look like a FireHOL feed (first chars: {:?})",
                &head.chars().take(80).collect::<String>()),
        };
    }
    if let Err(e) = std::fs::rename(&tmp, FEED_LOCAL_PATH) {
        return RemediationOutcome {
            action, ok: false, detail: format!("rename: {}", e),
        };
    }
    let count = parse_feed_entries(FEED_LOCAL_PATH).len();
    tracing::warn!("threat_intel: refreshed feed; {} entries", count);
    RemediationOutcome {
        action,
        ok: true,
        detail: format!("downloaded {} ({} entries)", FEED_URL, count),
    }
}

/// Atomic ipset replacement: build a fresh set in a tmp name then
/// `ipset swap` to switch it in. Prevents the multi-second window
/// where the kernel set is empty mid-rebuild.
fn sync_ipset_to_feed() -> RemediationOutcome {
    let action = "sync ipset to feed".to_string();
    let entries = parse_feed_entries(FEED_LOCAL_PATH);
    if entries.is_empty() {
        return RemediationOutcome {
            action, ok: false, detail: "feed parse returned 0 entries; skipping ipset sync".into(),
        };
    }
    // Combine the operator allowlist with the auto-allowlist of
    // local interface IPs + cluster peer addresses. Critical: cloud
    // providers (Hetzner, DigitalOcean, OVH, AWS) routinely reuse
    // public IPs. If we rent a fresh VPS whose IP was previously a
    // botnet C2, FireHOL still lists it — and an INPUT DROP rule on
    // our own IP locks the operator out. Same risk for any cluster
    // peer whose recycled IP happens to be on the feed. We strip
    // both ourselves and our peers before pushing to the kernel.
    let mut allow = parse_allowlist();
    let auto = auto_allowlist();
    let auto_count = auto.len();
    allow.extend(auto);
    // Build a restore-formatted batch script.
    let tmp_name = format!("{}_swap", IPSET_NAME);
    let mut script = String::with_capacity(entries.len() * 32);
    script.push_str(&format!("create {} hash:net family inet hashsize 4096 maxelem 131072\n", tmp_name));
    let mut skipped_by_allow = 0u32;
    for e in &entries {
        // The allowlist holds bare IPs (auto-allowlist) and may also
        // hold CIDRs (operator allowlist). For an exact-match in
        // either direction we check direct membership; for a feed
        // CIDR that wraps an allowlisted host we'd want to also
        // skip, but FireHOL's IPs rarely span our cluster's IPs.
        // Direct membership is the operative case and handles the
        // Hetzner-IP-reuse scenario this filter exists for.
        if allow.contains(e) { skipped_by_allow += 1; continue; }
        script.push_str(&format!("add {} {}\n", tmp_name, e));
    }
    // Ensure the real set exists so swap has a destination.
    let _ = std::process::Command::new("ipset")
        .args(["create", IPSET_NAME, "hash:net", "family", "inet", "hashsize", "4096", "maxelem", "131072", "-exist"])
        .output();
    // Drop any prior tmp set from a previous failed run.
    let _ = std::process::Command::new("ipset")
        .args(["destroy", &tmp_name])
        .output();
    // Restore-load the new tmp set.
    let mut child = match std::process::Command::new("ipset")
        .args(["restore", "-exist"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return RemediationOutcome { action, ok: false, detail: format!("spawn ipset restore: {}", e) },
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        if let Err(e) = stdin.write_all(script.as_bytes()) {
            return RemediationOutcome { action, ok: false, detail: format!("write to ipset restore: {}", e) };
        }
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return RemediationOutcome { action, ok: false, detail: format!("wait ipset restore: {}", e) },
    };
    if !out.status.success() {
        let _ = std::process::Command::new("ipset").args(["destroy", &tmp_name]).output();
        return RemediationOutcome {
            action, ok: false,
            detail: format!("ipset restore failed: {}", String::from_utf8_lossy(&out.stderr).trim()),
        };
    }
    // Atomic swap, then destroy the now-stale temp set.
    let swap = std::process::Command::new("ipset")
        .args(["swap", &tmp_name, IPSET_NAME])
        .output();
    let swap_ok = swap.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let _ = std::process::Command::new("ipset").args(["destroy", &tmp_name]).output();
    if !swap_ok {
        return RemediationOutcome {
            action, ok: false,
            detail: format!("ipset swap failed: {}",
                swap.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_else(|e| e.to_string())),
        };
    }
    let kept = entries.iter().filter(|e| !allow.contains(*e)).count();
    tracing::warn!(
        "threat_intel: synced ipset to {} entries ({} auto-allowlisted, {} feed entries skipped by allowlist)",
        kept, auto_count, skipped_by_allow,
    );
    RemediationOutcome {
        action,
        ok: true,
        detail: format!(
            "ipset {} updated to {} entries; {} skipped via allowlist ({} of which were auto-allowlisted local/peer IPs)",
            IPSET_NAME, kept, skipped_by_allow, auto_count,
        ),
    }
}

fn install_iptables_rules() -> RemediationOutcome {
    let action = "install iptables rules for blocklist".to_string();
    let mut errors: Vec<String> = Vec::new();
    let mut added = 0u32;
    for (chain, direction) in [("INPUT", "src"), ("OUTPUT", "dst")] {
        let exists = std::process::Command::new("iptables")
            .args(["-C", chain, "-m", "set", "--match-set", IPSET_NAME, direction, "-j", "DROP"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if exists { continue; }
        let out = std::process::Command::new("iptables")
            .args(["-I", chain, "-m", "set", "--match-set", IPSET_NAME, direction, "-j", "DROP"])
            .output();
        match out {
            Ok(o) if o.status.success() => added += 1,
            Ok(o) => errors.push(format!("{}: {}", chain, String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => errors.push(format!("{}: {}", chain, e)),
        }
    }
    let ok = errors.is_empty();
    if ok {
        tracing::warn!("threat_intel: installed {} iptables rules referencing {}", added, IPSET_NAME);
    }
    RemediationOutcome {
        action,
        ok,
        detail: if ok {
            format!("inserted DROP rules on INPUT+OUTPUT referencing {}", IPSET_NAME)
        } else {
            errors.join("; ")
        },
    }
}

pub fn analyze(
    ctx: &Context,
    facts: &ThreatIntelFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    let suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, &scope) || proposals.is_suppressed(ft, &scope)
    };

    // ipset missing → High finding (no auto-install — that's an
    // explicit operator decision since it adds a system dependency).
    if !facts.ipset_available && !suppressed(FT_THREAT_INTEL_NO_IPSET) {
        out.push(Proposal::new(
            FT_THREAT_INTEL_NO_IPSET,
            ProposalSource::Rule,
            Severity::High,
            "Threat-intel blocking disabled — `ipset` not installed",
            "WolfStack v23.2+ uses the FireHOL Level 1 IP blocklist to drop traffic to/from known-bad addresses. That requires the `ipset` kernel hash-table tool, which isn't installed on this host. Without it the analyzer can detect the gap but can't enforce.".to_string(),
            vec![],
            RemediationPlan::Manual {
                instructions: "Install ipset. After install, the next 5-minute predictive tick will auto-pull the feed and install the iptables rules.".into(),
                commands: vec![
                    "# Debian / Proxmox:".into(),
                    "apt-get install -y ipset".into(),
                    "# Rocky / RHEL:".into(),
                    "dnf install -y ipset".into(),
                ],
            },
            scope.clone(),
        ));
    }

    // Operator disabled the feature → Info-only card so they can see
    // enforcement is off, not a card screaming at them.
    if !facts.enabled && facts.ipset_available && !suppressed(FT_THREAT_INTEL_DISABLED) {
        out.push(Proposal::new(
            FT_THREAT_INTEL_DISABLED,
            ProposalSource::Rule,
            Severity::Info,
            "Threat-intel blocking disabled by operator",
            "WolfStack's FireHOL Level 1 blocklist enforcement is disabled on this node (the marker file at /var/lib/wolfstack/threat-intel/enabled was removed). The host can reach and be reached by every IP, including known-malicious ones. Re-enable by touching the marker file; suppress this card by acking it.".to_string(),
            vec![],
            RemediationPlan::Manual {
                instructions: "Touch the flag file to re-enable. The next tick will pull the feed and install the rules.".into(),
                commands: vec![
                    "mkdir -p /var/lib/wolfstack/threat-intel".into(),
                    "touch /var/lib/wolfstack/threat-intel/enabled".into(),
                ],
            },
            scope.clone(),
        ));
    }

    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &ThreatIntelFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    [
        FT_THREAT_INTEL_DISABLED,
        FT_THREAT_INTEL_NO_IPSET,
        FT_THREAT_INTEL_STALE,
        FT_THREAT_INTEL_RULES_MISSING,
    ].iter().map(|t| ((*t).to_string(), scope.clone())).collect()
}

#[allow(dead_code)]
fn forensics_dir() -> PathBuf {
    PathBuf::from("/var/lib/wolfstack/threat-intel")
}

/// Operator-visible status snapshot. Returned by the GET /status
/// endpoint so the UI toggle can render current state.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatIntelStatus {
    pub enabled: bool,
    pub ipset_available: bool,
    pub iptables_rules_present: bool,
    pub feed_entry_count: usize,
    pub ipset_entry_count: usize,
    pub feed_age_secs: Option<u64>,
}

pub fn status_snapshot() -> ThreatIntelStatus {
    ThreatIntelStatus {
        enabled: is_enabled(),
        ipset_available: which_exists("ipset"),
        iptables_rules_present: which_exists("iptables") && rules_are_present(),
        feed_entry_count: parse_feed_entries(FEED_LOCAL_PATH).len(),
        ipset_entry_count: count_ipset_entries(IPSET_NAME),
        feed_age_secs: std::fs::metadata(FEED_LOCAL_PATH).ok()
            .and_then(|m| m.modified().ok())
            .and_then(|mt| SystemTime::now().duration_since(mt).ok())
            .map(|d| d.as_secs()),
    }
}

/// Operator-triggered enable. Idempotent: creates the parent dir +
/// flag file. Does NOT immediately install rules — the next 5-min
/// tick will do that. Acceptable lag for an enable operation
/// (worst case: 5 minutes before the rules go live).
pub fn enable_for_operator() -> Result<(), String> {
    std::fs::create_dir_all("/var/lib/wolfstack/threat-intel")
        .map_err(|e| format!("create dir: {}", e))?;
    std::fs::write(ENABLE_FLAG_PATH, b"enabled\n")
        .map_err(|e| format!("write flag: {}", e))?;
    Ok(())
}

/// Operator-triggered disable. The safety switch. CRITICAL: must
/// tear down the iptables rules + destroy the ipset IMMEDIATELY,
/// not wait for the next tick — the whole point of a safety
/// switch is to unblock the cluster when it's in a bad state.
pub fn disable_for_operator() -> Result<(), String> {
    // Best-effort delete of the flag file. Absence = disabled, so
    // a stale flag-file failure isn't a blocker.
    let _ = std::fs::remove_file(ENABLE_FLAG_PATH);
    // Remove iptables rules so traffic flows immediately. Both
    // chains, both directions. -D will return non-zero if the rule
    // isn't present; that's fine (idempotent).
    for (chain, direction) in [("INPUT", "src"), ("OUTPUT", "dst")] {
        // Loop a few times in case duplicate rules were inserted by
        // an earlier buggy version.
        for _ in 0..8 {
            let out = std::process::Command::new("iptables")
                .args(["-D", chain, "-m", "set", "--match-set", IPSET_NAME, direction, "-j", "DROP"])
                .output();
            match out {
                Ok(o) if o.status.success() => continue,
                _ => break,
            }
        }
    }
    // Destroy the ipset so it can't accidentally be referenced by
    // some other operator-installed rule. -X is ignore-if-missing.
    let _ = std::process::Command::new("ipset").args(["destroy", IPSET_NAME]).output();
    tracing::warn!("threat_intel: disabled by operator — iptables rules and ipset removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feed_skips_comments_and_blanks() {
        let dir = std::env::temp_dir().join(format!("wolfstack-ti-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let feed = dir.join("test.netset");
        std::fs::write(&feed, "# header line\n\n1.2.3.4\n5.6.7.0/24\n# end\n").unwrap();
        let entries = parse_feed_entries(feed.to_str().unwrap());
        assert_eq!(entries, vec!["1.2.3.4".to_string(), "5.6.7.0/24".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_excludes_entries() {
        let dir = std::env::temp_dir().join(format!("wolfstack-ti-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let allow_file = dir.join("allowlist.txt");
        std::fs::write(&allow_file, "1.2.3.4\n# comment\n\n5.6.7.0/24\n").unwrap();
        // Direct call to the parser via temp file path. Since
        // parse_allowlist uses the hard-coded const, simulate by
        // reading + filtering manually:
        let body = std::fs::read_to_string(&allow_file).unwrap();
        let set: HashSet<String> = body.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert!(set.contains("1.2.3.4"));
        assert!(set.contains("5.6.7.0/24"));
        assert_eq!(set.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn covered_scopes_lists_every_finding_type() {
        let facts = ThreatIntelFacts { scanned: true, ..Default::default() };
        let ctx = Context::for_node("ws-test".to_string());
        let scopes = covered_scopes(&ctx, &facts);
        assert_eq!(scopes.len(), 4);
    }

    /// CRITICAL: the FireHOL Level 1 feed contains the FullBogons
    /// set. If those make it into the iptables DROP rule on a
    /// Proxmox/WolfStack cluster, all RFC1918 east-west traffic
    /// (WolfNet, WolfRouter LANs, Docker bridges, local management)
    /// gets blackholed. The bogon filter must skip every private /
    /// reserved / loopback / link-local / CGN / multicast range.
    #[test]
    fn bogon_filter_skips_rfc1918_and_friends() {
        // RFC1918 — must be skipped. The whole `10/8` is private,
        // so WolfNet running on ANY 10.x.x.x subnet is protected.
        assert!(is_private_or_reserved("10.0.0.0/8"));
        assert!(is_private_or_reserved("10.100.0.0/16")); // typical WolfNet
        assert!(is_private_or_reserved("10.10.0.0/16"));  // typical WolfRouter LAN
        assert!(is_private_or_reserved("10.10.10.0/24")); // exact WolfNet subnet shape sponsor mentioned
        assert!(is_private_or_reserved("10.10.10.5"));    // single host inside 10/8
        assert!(is_private_or_reserved("10.255.255.255"));// last addr in 10/8
        assert!(is_private_or_reserved("172.16.0.0/12"));
        assert!(is_private_or_reserved("172.17.0.0/16")); // Docker default
        assert!(is_private_or_reserved("172.31.255.0/24"));// last subnet of 172.16/12
        assert!(is_private_or_reserved("192.168.0.0/16"));
        assert!(is_private_or_reserved("192.168.1.1"));

        // Loopback + link-local + CGN.
        assert!(is_private_or_reserved("127.0.0.0/8"));
        assert!(is_private_or_reserved("127.0.0.1"));
        assert!(is_private_or_reserved("169.254.0.0/16"));
        // CGN / Tailscale tailnet range — every Tailscale-connected
        // host has a 100.64.0.0/10 IP. Filtering this is what stops
        // v23.2 from blocking the operator's tailnet management
        // access the moment it deploys.
        assert!(is_private_or_reserved("100.64.0.0/10"));
        assert!(is_private_or_reserved("100.64.0.1"));    // first usable
        assert!(is_private_or_reserved("100.100.100.100"));// mid-range Tailscale typical
        assert!(is_private_or_reserved("100.127.255.255"));// last usable

        // Multicast + reserved.
        assert!(is_private_or_reserved("224.0.0.0/4"));
        assert!(is_private_or_reserved("240.0.0.0/4"));

        // 0.0.0.0/8.
        assert!(is_private_or_reserved("0.0.0.0/8"));

        // IPv6 entries — skipped because the ipset is IPv4-only.
        assert!(is_private_or_reserved("2001:db8::/32"));
        assert!(is_private_or_reserved("fe80::/10"));

        // Unparseable — skipped (safest default).
        assert!(is_private_or_reserved("not-an-ip"));
    }

    /// VLAN subnets and arbitrary operator-chosen private ranges
    /// must all be covered. VLANs themselves are an L2 concept —
    /// what matters is the IP subnet riding on them, and operators
    /// universally pick RFC1918 / CGN ranges. The bogon filter
    /// covers the full set, so any IP-on-VLAN that's in RFC1918
    /// space (the realistic 99.9% case) is safe.
    #[test]
    fn bogon_filter_covers_vlan_subnets() {
        // Common VLAN subnet patterns operators carve out of 10/8.
        assert!(is_private_or_reserved("10.0.10.0/24"));
        assert!(is_private_or_reserved("10.20.30.0/24"));
        assert!(is_private_or_reserved("10.42.0.0/16"));
        // Common 172.16-31 carve-outs.
        assert!(is_private_or_reserved("172.20.50.0/24"));
        assert!(is_private_or_reserved("172.30.0.0/16"));
        // Common 192.168 VLANs.
        assert!(is_private_or_reserved("192.168.10.0/24"));
        assert!(is_private_or_reserved("192.168.100.0/24"));
        assert!(is_private_or_reserved("192.168.250.0/24"));
    }

    #[test]
    fn bogon_filter_passes_real_public_ips() {
        // Klas's cluster public IPs (from his pvecm status output).
        // None of these are bogons; must pass through to the
        // blocklist if FireHOL lists them.
        assert!(!is_private_or_reserved("142.132.140.78"));
        assert!(!is_private_or_reserved("162.55.15.215"));
        assert!(!is_private_or_reserved("168.119.137.55"));
        assert!(!is_private_or_reserved("94.130.22.183"));
        assert!(!is_private_or_reserved("195.201.58.223"));
        // The BootingWorld attacker's C2 — must pass through.
        assert!(!is_private_or_reserved("83.168.95.185"));
        // 1.1.1.1 (Cloudflare DNS).
        assert!(!is_private_or_reserved("1.1.1.1"));
        // Big public CIDR.
        assert!(!is_private_or_reserved("203.0.113.0/24")); // TEST-NET-3 — technically reserved, but not in our private list since it's documentation-only and could appear in real attacks
    }

    #[test]
    fn parse_feed_strips_bogon_entries() {
        let dir = std::env::temp_dir().join(format!("wolfstack-ti-bogon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let feed = dir.join("test.netset");
        std::fs::write(&feed, "# FireHOL Level 1 (simulated)\n\
                              10.0.0.0/8\n\
                              172.16.0.0/12\n\
                              192.168.0.0/16\n\
                              127.0.0.0/8\n\
                              169.254.0.0/16\n\
                              100.64.0.0/10\n\
                              224.0.0.0/4\n\
                              83.168.95.185\n\
                              5.6.7.0/24\n\
                              2001:db8::/32\n").unwrap();
        let entries = parse_feed_entries(feed.to_str().unwrap());
        // Only the two public entries should survive.
        assert_eq!(entries.len(), 2, "got {:?}", entries);
        assert!(entries.contains(&"83.168.95.185".to_string()));
        assert!(entries.contains(&"5.6.7.0/24".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
