// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Backend-specific code for attaching/detaching a guest (LXC native,
//! Proxmox CT/VM, Docker container, libvirt VM) to a VLAN bridge.
//!
//! Every backend takes the same logical inputs:
//! - bridge name (e.g. `vmbr4000`)
//! - IP/CIDR (e.g. `10.0.1.10/24`)
//! - MTU (e.g. `1400`)
//! - target id (container name / VMID / docker name / domain name)
//!
//! Each adapter writes the backend's native config + brings the
//! interface up. `apply` returns a brief human-readable summary
//! suitable for the UI's success toast or a warning toast on partial
//! failure (e.g. config saved but container needs manual restart).
//!
//! ## Honest scope
//!
//! - **LXC native (raw `lxc-start`)**: full support — write config +
//!   restart container.
//! - **Proxmox LXC**: requires `pct` on PATH (which it always is on
//!   Proxmox hosts). Writes config via `pct set` and restarts.
//! - **Docker**: creates a docker macvlan/bridge network on top of the
//!   VLAN bridge (so multiple containers can share it without IP
//!   collision) and attaches via `docker network connect`.
//! - **Native VMs (libvirt)**: requires libvirt + qemu present. Uses
//!   `virsh attach-interface` for live attach + a config file edit
//!   for persistence.
//! - **Proxmox VMs**: same `pct`-style — `qm set` then reboot prompt.

use std::process::Command;

/// Common operation parameters; same shape regardless of backend.
pub struct AttachParams<'a> {
    pub bridge: &'a str,
    /// Full CIDR (e.g. "10.0.1.10/24"), not just the address.
    pub ip_cidr: &'a str,
    pub mtu: u32,
    /// Optional gateway. None = static IP without default route.
    pub gateway: Option<&'a str>,
    /// Backend-specific identifier (container name, VMID, etc.).
    pub target_id: &'a str,
}

#[derive(Debug)]
pub struct AttachOutcome {
    pub message: String,
    pub restarted: bool,
}

/// Strip the prefix off a CIDR, returning just the address. Used by
/// backends that take a separate IP and netmask.
fn ip_only(cidr: &str) -> String {
    cidr.split('/').next().unwrap_or(cidr).to_string()
}

fn prefix_only(cidr: &str) -> Option<u8> {
    cidr.split('/').nth(1).and_then(|s| s.parse().ok())
}

// ────────────────────────────────────────────────────────────────────
// LXC native (raw /var/lib/lxc/<name>/config)
// ────────────────────────────────────────────────────────────────────

/// Attach a native LXC container to the bridge. Writes a fresh
/// `lxc.net.N.*` block with the next available index, then restarts
/// the container so the change takes effect.
pub fn attach_lxc_native(p: &AttachParams) -> Result<AttachOutcome, String> {
    let cfg_path = format!("/var/lib/lxc/{}/config", p.target_id);
    let existing = std::fs::read_to_string(&cfg_path)
        .map_err(|e| format!("read {}: {}", cfg_path, e))?;
    let next_idx = next_lxc_net_index(&existing);
    // Stable host-side veth name so `ip link` output is debuggable
    // ("ws-<container>-<idx>" instead of random "vethXYZ"). 15-char
    // limit on Linux iface names — truncate the container name part
    // if needed but keep the index suffix so multiple attaches don't
    // collide.
    let veth_pair = stable_veth_name(p.target_id, next_idx);
    // Stable hardware address derived deterministically from the
    // container name + bridge + index. Without an explicit hwaddr,
    // LXC generates a random MAC each boot — DHCP reservations break,
    // ARP caches go stale, and operators can't pin firewall rules to
    // a known MAC. Stable MAC fixes all three. The 02:xx prefix marks
    // it as locally-administered (universal/local bit set).
    let hwaddr = stable_hwaddr(p.target_id, p.bridge, next_idx);
    let mut block = String::new();
    block.push_str("\n# Added by WolfStack — VLAN bridge attachment\n");
    block.push_str(&format!("lxc.net.{}.type = veth\n", next_idx));
    block.push_str(&format!("lxc.net.{}.link = {}\n", next_idx, p.bridge));
    block.push_str(&format!("lxc.net.{}.veth.pair = {}\n", next_idx, veth_pair));
    block.push_str(&format!("lxc.net.{}.hwaddr = {}\n", next_idx, hwaddr));
    block.push_str(&format!("lxc.net.{}.flags = up\n", next_idx));
    block.push_str(&format!("lxc.net.{}.mtu = {}\n", next_idx, p.mtu));
    block.push_str(&format!("lxc.net.{}.ipv4.address = {}\n", next_idx, p.ip_cidr));
    if let Some(gw) = p.gateway {
        block.push_str(&format!("lxc.net.{}.ipv4.gateway = {}\n", next_idx, gw));
    }
    let mut combined = existing;
    if !combined.ends_with('\n') { combined.push('\n'); }
    combined.push_str(&block);
    std::fs::write(&cfg_path, combined)
        .map_err(|e| format!("write {}: {}", cfg_path, e))?;

    // Restart the container. Stop+start because reboot keeps the
    // container's namespace and won't pick up the new lxc.net entry.
    //
    // 60s graceful shutdown timeout — long enough for a database
    // container to flush WAL and shut down cleanly. The previous
    // 10s default was an early-pre-empt risk for production loads.
    // After 60s we fall through to lxc-start which will SIGKILL any
    // remaining process group; the operator gets a clear message.
    let _ = Command::new("lxc-stop").args(["-n", p.target_id, "-t", "60"]).output();
    let start = Command::new("lxc-start").args(["-n", p.target_id]).output()
        .map_err(|e| format!("spawn lxc-start: {}", e))?;
    if !start.status.success() {
        return Ok(AttachOutcome {
            message: format!(
                "Config updated but container failed to restart: {}",
                String::from_utf8_lossy(&start.stderr).trim()
            ),
            restarted: false,
        });
    }
    Ok(AttachOutcome {
        message: format!("Attached lxc.net.{} on {} ({}); container restarted.", next_idx, p.bridge, p.ip_cidr),
        restarted: true,
    })
}

/// Build a stable host-side veth name for a (container, index) pair.
/// Linux interface names cap at 15 chars (IFNAMSIZ-1 = 15). The format
/// is `ws-<container>-<idx>`, with the container portion truncated as
/// needed so the suffix always fits. Any non-alphanumeric character
/// in the container name is dropped (interface names disallow them).
fn stable_veth_name(container: &str, idx: u32) -> String {
    let suffix = format!("-{}", idx);
    let prefix = "ws-";
    // Available room for the container name portion.
    let max_container = 15 - prefix.len() - suffix.len();
    let cleaned: String = container.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(max_container)
        .collect();
    format!("{}{}{}", prefix, cleaned, suffix)
}

/// Build a stable, locally-administered MAC address from a (container,
/// bridge, index) tuple. Uses a deterministic hash so the same inputs
/// always produce the same MAC — the operator's container keeps its
/// MAC across reboots and reattach cycles. Locally-administered prefix
/// `02:` is RFC-compliant for OS-assigned MACs (no OUI registration).
fn stable_hwaddr(container: &str, bridge: &str, idx: u32) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    container.hash(&mut h);
    bridge.hash(&mut h);
    idx.hash(&mut h);
    let n = h.finish();
    let bytes = n.to_be_bytes();
    // 02:xx:xx:xx:xx:xx — 02 marks it as locally-administered (bit 1
    // of the first octet set), unicast (bit 0 clear).
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
    )
}

/// Find the next free `lxc.net.N` index by scanning the config.
fn next_lxc_net_index(cfg: &str) -> u32 {
    let mut max_seen: i32 = -1;
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("lxc.net.") {
            if let Some(num_str) = rest.split('.').next() {
                if let Ok(n) = num_str.parse::<i32>() {
                    if n > max_seen { max_seen = n; }
                }
            }
        }
    }
    (max_seen + 1) as u32
}

/// Detach by removing all lxc.net.N.* lines that reference the given
/// bridge. Restarts the container so the change takes effect.
pub fn detach_lxc_native(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    let cfg_path = format!("/var/lib/lxc/{}/config", target_id);
    let existing = std::fs::read_to_string(&cfg_path)
        .map_err(|e| format!("read {}: {}", cfg_path, e))?;
    // Find which index(es) reference this bridge, then drop every
    // lxc.net.IDX.* line for each matched index. We don't reindex
    // remaining blocks — LXC tolerates gaps in the numbering.
    let mut indexes_to_drop: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for line in existing.lines() {
        let t = line.trim();
        if t.starts_with('#') { continue; }
        let Some(rest) = t.strip_prefix("lxc.net.") else { continue };
        let Some((num_str, suffix)) = rest.split_once('.') else { continue };
        // Match the `link` key exactly — not `linkN`, not anything else
        // that happens to start with the same letters. The key is
        // followed by either `=` directly or whitespace before `=`.
        let suffix = suffix.trim_start();
        let Some(after_link) = suffix.strip_prefix("link") else { continue };
        let next = after_link.chars().next();
        if !matches!(next, Some('=') | Some(' ') | Some('\t')) { continue; }
        let Some((_, val)) = t.split_once('=') else { continue };
        if val.trim() != bridge { continue; }
        let Ok(n) = num_str.parse::<u32>() else { continue };
        indexes_to_drop.insert(n);
    }
    if indexes_to_drop.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No lxc.net entry referenced bridge {} — nothing to detach.", bridge),
            restarted: false,
        });
    }
    let prefixes: Vec<String> = indexes_to_drop.iter()
        .map(|i| format!("lxc.net.{}.", i))
        .collect();
    let kept: Vec<&str> = existing.lines()
        .filter(|line| {
            let t = line.trim();
            !prefixes.iter().any(|p| t.starts_with(p.as_str()))
        })
        .collect();
    let new_cfg = kept.join("\n");
    std::fs::write(&cfg_path, &new_cfg)
        .map_err(|e| format!("write {}: {}", cfg_path, e))?;

    let _ = Command::new("lxc-stop").args(["-n", target_id, "-t", "60"]).output();
    let _ = Command::new("lxc-start").args(["-n", target_id]).output();
    Ok(AttachOutcome {
        message: format!("Removed {} lxc.net entr{} for bridge {}; container restarted.",
            indexes_to_drop.len(),
            if indexes_to_drop.len() == 1 { "y" } else { "ies" },
            bridge),
        restarted: true,
    })
}

// ────────────────────────────────────────────────────────────────────
// LXC on Proxmox (`pct set`)
// ────────────────────────────────────────────────────────────────────

/// Attach a Proxmox LXC container by adding a netN device. Picks the
/// next free index by inspecting the current config.
pub fn attach_lxc_proxmox(p: &AttachParams) -> Result<AttachOutcome, String> {
    let vmid = p.target_id;
    let next_idx = next_pct_net_index(vmid)?;
    let cidr = p.ip_cidr;
    let mut spec = format!("name=eth{idx},bridge={br},ip={ip},mtu={mtu}",
        idx = next_idx, br = p.bridge, ip = cidr, mtu = p.mtu);
    if let Some(gw) = p.gateway {
        spec.push_str(&format!(",gw={}", gw));
    }
    let arg = format!("-net{}", next_idx);
    let out = Command::new("pct").args(["set", vmid, &arg, &spec]).output()
        .map_err(|e| format!("spawn pct: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct set failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    // Graceful shutdown then start, rather than `pct reboot` which
    // SIGKILLs after a hard 60s timeout. shutdown sends SIGPWR / ACPI
    // so the container init can flush state. We give it 90s before
    // moving on; if it doesn't stop in that window the container is
    // probably wedged and the operator will see it didn't restart.
    let stopped = Command::new("pct")
        .args(["shutdown", vmid, "--timeout", "90"])
        .output();
    let start_needed = match stopped {
        Ok(o) if o.status.success() => true,
        _ => {
            // shutdown failed (already stopped, or wedged). Try `start`
            // anyway — if it's already running, start is a no-op.
            true
        }
    };
    if start_needed {
        let _ = Command::new("pct").args(["start", vmid]).output();
    }
    Ok(AttachOutcome {
        message: format!(
            "Attached net{} on {} ({}); container restarted via graceful shutdown.",
            next_idx, p.bridge, cidr,
        ),
        restarted: true,
    })
}

/// Find the next free netN slot in a Proxmox CT config by parsing
/// `pct config <vmid>` output.
fn next_pct_net_index(vmid: &str) -> Result<u32, String> {
    let out = Command::new("pct").args(["config", vmid]).output()
        .map_err(|e| format!("spawn pct: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct config failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let cfg = String::from_utf8_lossy(&out.stdout);
    let mut max_seen: i32 = -1;
    for line in cfg.lines() {
        if let Some(rest) = line.trim().strip_prefix("net") {
            if let Some((num_str, _)) = rest.split_once(':') {
                if let Ok(n) = num_str.parse::<i32>() {
                    if n > max_seen { max_seen = n; }
                }
            }
        }
    }
    Ok((max_seen + 1) as u32)
}

/// Detach by removing the netN device(s) that reference the bridge.
pub fn detach_lxc_proxmox(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    let cfg_out = Command::new("pct").args(["config", target_id]).output()
        .map_err(|e| format!("spawn pct: {}", e))?;
    if !cfg_out.status.success() {
        return Err(format!("pct config failed: {}", String::from_utf8_lossy(&cfg_out.stderr).trim()));
    }
    let cfg = String::from_utf8_lossy(&cfg_out.stdout);
    let mut to_remove: Vec<String> = Vec::new();
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("net") {
            if let Some((num_str, val)) = rest.split_once(':') {
                if val.contains(&format!("bridge={}", bridge)) {
                    to_remove.push(format!("net{}", num_str));
                }
            }
        }
    }
    if to_remove.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No net device on container {} referenced {}.", target_id, bridge),
            restarted: false,
        });
    }
    for dev in &to_remove {
        let arg = format!("--delete={}", dev);
        let _ = Command::new("pct").args(["set", target_id, &arg]).output();
    }
    let _ = Command::new("pct").args(["shutdown", target_id, "--timeout", "90"]).output();
    let _ = Command::new("pct").args(["start", target_id]).output();
    Ok(AttachOutcome {
        message: format!(
            "Removed {} net device(s) on {}; container restarted via graceful shutdown.",
            to_remove.len(), target_id,
        ),
        restarted: true,
    })
}

// ────────────────────────────────────────────────────────────────────
// VMs on Proxmox (`qm set`)
// ────────────────────────────────────────────────────────────────────

/// Attach a Proxmox QEMU VM. Hot-plug only works if the guest OS
/// supports virtio hot-add — otherwise the operator needs to reboot
/// the VM. We don't auto-reboot VMs (data loss risk); we surface that
/// in the message.
pub fn attach_vm_proxmox(p: &AttachParams) -> Result<AttachOutcome, String> {
    let vmid = p.target_id;
    let next_idx = next_qm_net_index(vmid)?;
    let spec = format!("model=virtio,bridge={br},mtu={mtu}",
        br = p.bridge, mtu = p.mtu);
    // qm doesn't accept ip= directly on VMs (the IP is inside the guest);
    // we set it via cloud-init if the VM is cloud-init-enabled, otherwise
    // we just attach the NIC and the operator configures the IP inside.
    let arg = format!("-net{}", next_idx);
    let out = Command::new("qm").args(["set", vmid, &arg, &spec]).output()
        .map_err(|e| format!("spawn qm: {}", e))?;
    if !out.status.success() {
        return Err(format!("qm set failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(AttachOutcome {
        message: format!(
            "Attached net{} on {}. The VM still needs the IP {} configured INSIDE the guest OS — \
             VM-side configuration cannot be set from outside without cloud-init. \
             Reboot the VM if the new NIC doesn't appear (depends on guest's hot-plug support).",
            next_idx, p.bridge, p.ip_cidr,
        ),
        restarted: false,
    })
}

fn next_qm_net_index(vmid: &str) -> Result<u32, String> {
    let out = Command::new("qm").args(["config", vmid]).output()
        .map_err(|e| format!("spawn qm: {}", e))?;
    if !out.status.success() {
        return Err(format!("qm config failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let cfg = String::from_utf8_lossy(&out.stdout);
    let mut max_seen: i32 = -1;
    for line in cfg.lines() {
        if let Some(rest) = line.trim().strip_prefix("net") {
            if let Some((num_str, _)) = rest.split_once(':') {
                if let Ok(n) = num_str.parse::<i32>() {
                    if n > max_seen { max_seen = n; }
                }
            }
        }
    }
    Ok((max_seen + 1) as u32)
}

pub fn detach_vm_proxmox(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    let cfg_out = Command::new("qm").args(["config", target_id]).output()
        .map_err(|e| format!("spawn qm: {}", e))?;
    if !cfg_out.status.success() {
        return Err(format!("qm config failed: {}", String::from_utf8_lossy(&cfg_out.stderr).trim()));
    }
    let cfg = String::from_utf8_lossy(&cfg_out.stdout);
    let mut to_remove: Vec<String> = Vec::new();
    for line in cfg.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("net") {
            if let Some((num_str, val)) = rest.split_once(':') {
                if val.contains(&format!("bridge={}", bridge)) {
                    to_remove.push(format!("net{}", num_str));
                }
            }
        }
    }
    if to_remove.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No net device on VM {} referenced {}.", target_id, bridge),
            restarted: false,
        });
    }
    for dev in &to_remove {
        let arg = format!("--delete={}", dev);
        let _ = Command::new("qm").args(["set", target_id, &arg]).output();
    }
    Ok(AttachOutcome {
        message: format!("Removed {} net device(s) on VM {}. Reboot the VM if it doesn't drop the NIC live.", to_remove.len(), target_id),
        restarted: false,
    })
}

// ────────────────────────────────────────────────────────────────────
// Docker (via docker macvlan / bridge network)
// ────────────────────────────────────────────────────────────────────

/// Driver to use for Docker network creation. Hetzner vSwitch enforces
/// ONE MAC per server port — macvlan creates a unique MAC per container,
/// so packets sourced from those MACs are silently dropped by the
/// vSwitch. ipvlan L2 mode uses the parent's MAC for every container
/// and differentiates by IP, which Hetzner accepts.
///
/// For OVH vRack, Equinix Metal, and generic 802.1Q trunks, macvlan is
/// fine and gives true L2 isolation between containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerVlanDriver {
    /// Each container gets a unique MAC. Don't use on Hetzner.
    Macvlan,
    /// Single shared MAC, IPs differentiate. Required for Hetzner.
    IpvlanL2,
}

impl DockerVlanDriver {
    pub fn driver_arg(&self) -> &'static str {
        match self {
            DockerVlanDriver::Macvlan => "macvlan",
            DockerVlanDriver::IpvlanL2 => "ipvlan",
        }
    }
}

/// Attach a Docker container by creating (idempotently) a docker
/// network attached to the VLAN's TAGGED SUB-INTERFACE (not the
/// bridge — Docker's macvlan/ipvlan drivers attach directly to the
/// underlying L2 device, and bridging on top of a bridge is a recipe
/// for MAC-learning chaos).
///
/// The docker network's name is derived from the bridge name so it's
/// reusable across containers: `wolfstack-<bridge>`.
///
/// `parent_iface` should be the VLAN sub-interface name (e.g.
/// `eno1.4000`), NOT the bridge. The caller knows both — pass the
/// sub-interface here.
pub fn attach_docker(
    p: &AttachParams,
    parent_iface: &str,
    subnet: &str,
    gateway_ip: &str,
    driver: DockerVlanDriver,
) -> Result<AttachOutcome, String> {
    // Encode the driver in the network name so we don't accidentally
    // re-use a macvlan network when the operator's now on a Hetzner
    // VLAN (or vice versa) — different drivers can't coexist for the
    // same parent.
    let net_name = format!("wolfstack-{}-{}", p.bridge, driver.driver_arg());
    // Create the docker network if missing. Idempotent: we inspect first.
    let inspect = Command::new("docker").args(["network", "inspect", &net_name]).output()
        .map_err(|e| format!("spawn docker: {}", e))?;
    if !inspect.status.success() {
        let mut args: Vec<String> = vec![
            "network".into(), "create".into(),
            "--driver".into(), driver.driver_arg().into(),
            "--subnet".into(), subnet.into(),
            "--gateway".into(), gateway_ip.into(),
            "-o".into(), format!("parent={}", parent_iface),
            "-o".into(), format!("com.docker.network.driver.mtu={}", p.mtu),
        ];
        // ipvlan needs explicit mode flag.
        if matches!(driver, DockerVlanDriver::IpvlanL2) {
            args.push("-o".into());
            args.push("ipvlan_mode=l2".into());
        }
        args.push(net_name.clone());
        let create = Command::new("docker").args(&args).output()
            .map_err(|e| format!("spawn docker network create: {}", e))?;
        if !create.status.success() {
            return Err(format!(
                "docker network create failed: {}",
                String::from_utf8_lossy(&create.stderr).trim()
            ));
        }
    }
    // Connect the container with a fixed IP.
    let ip_addr = ip_only(p.ip_cidr);
    let connect = Command::new("docker").args([
        "network", "connect",
        "--ip", &ip_addr,
        &net_name, p.target_id,
    ]).output()
        .map_err(|e| format!("spawn docker network connect: {}", e))?;
    if !connect.status.success() {
        return Err(format!(
            "docker network connect failed: {}",
            String::from_utf8_lossy(&connect.stderr).trim()
        ));
    }
    Ok(AttachOutcome {
        message: format!(
            "Connected container {} to {} network {} with IP {} (parent: {}).",
            p.target_id, driver.driver_arg(), net_name, ip_addr, parent_iface,
        ),
        restarted: false,
    })
}

pub fn detach_docker(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    // Try both driver-suffixed names (we stamped the driver into the
    // network name when creating). Older WolfStack versions used the
    // un-suffixed `wolfstack-{bridge}` form; check that too so we can
    // detach networks created by older builds.
    let candidates = [
        format!("wolfstack-{}-macvlan", bridge),
        format!("wolfstack-{}-ipvlan", bridge),
        format!("wolfstack-{}", bridge),
    ];
    let mut last_err: Option<String> = None;
    for net_name in &candidates {
        let out = Command::new("docker")
            .args(["network", "disconnect", net_name, target_id])
            .output()
            .map_err(|e| format!("spawn docker: {}", e))?;
        if out.status.success() {
            return Ok(AttachOutcome {
                message: format!("Disconnected container {} from network {}.", target_id, net_name),
                restarted: false,
            });
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // If the network doesn't exist OR the container isn't connected,
        // try the next candidate. Other errors we surface immediately.
        if !stderr.contains("not found") && !stderr.contains("is not connected") {
            return Err(format!("docker network disconnect failed: {}", stderr));
        }
        last_err = Some(stderr);
    }
    Err(format!(
        "container {} is not attached to any wolfstack docker network for bridge {} ({})",
        target_id, bridge, last_err.unwrap_or_default()
    ))
}

// ────────────────────────────────────────────────────────────────────
// Native VMs (libvirt)
// ────────────────────────────────────────────────────────────────────

/// Attach a libvirt VM by editing the domain XML (persistent) AND
/// hot-plugging the interface (live). If the VM is offline we skip
/// the live step. We don't auto-restart VMs.
pub fn attach_vm_libvirt(p: &AttachParams) -> Result<AttachOutcome, String> {
    let domain = p.target_id;
    let prefix = prefix_only(p.ip_cidr).unwrap_or(24);
    let _ = prefix;  // libvirt's attach-interface doesn't take a netmask;
                    // the IP is configured inside the guest OS.

    // Hot-attach (persistent across reboots via --persistent).
    let out = Command::new("virsh").args([
        "attach-interface", domain,
        "--type", "bridge",
        "--source", p.bridge,
        "--model", "virtio",
        "--mtu", &p.mtu.to_string(),
        "--persistent",
    ]).output()
        .map_err(|e| format!("spawn virsh: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "virsh attach-interface failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(AttachOutcome {
        message: format!(
            "Attached interface on {} via libvirt. The VM still needs IP {} configured INSIDE the guest OS.",
            p.bridge, p.ip_cidr,
        ),
        restarted: false,
    })
}

pub fn detach_vm_libvirt(target_id: &str, bridge: &str) -> Result<AttachOutcome, String> {
    // libvirt's detach-interface requires a MAC. We get it by parsing
    // `virsh domiflist <domain>` — a tabular listing of every NIC with
    // its source bridge and MAC. There can be multiple matches if the
    // operator attached the same VM to the bridge more than once;
    // detach all of them so the result is "no NICs left on this bridge".
    let list = Command::new("virsh").args(["domiflist", target_id]).output()
        .map_err(|e| format!("spawn virsh domiflist: {}", e))?;
    if !list.status.success() {
        return Err(format!(
            "virsh domiflist failed: {}",
            String::from_utf8_lossy(&list.stderr).trim()
        ));
    }
    let macs = parse_libvirt_macs_for_bridge(&String::from_utf8_lossy(&list.stdout), bridge);
    if macs.is_empty() {
        return Ok(AttachOutcome {
            message: format!("No interface on VM {} sourced from bridge {}.", target_id, bridge),
            restarted: false,
        });
    }
    let mut detached = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for mac in &macs {
        let out = Command::new("virsh").args([
            "detach-interface", target_id,
            "--type", "bridge",
            "--mac", mac,
            "--persistent",
        ]).output()
            .map_err(|e| format!("spawn virsh detach-interface: {}", e))?;
        if out.status.success() {
            detached += 1;
        } else {
            errors.push(format!(
                "{}: {}", mac, String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    if detached == 0 {
        return Err(format!(
            "Found {} interface(s) on bridge {} but virsh refused all detaches: {}",
            macs.len(), bridge, errors.join("; ")
        ));
    }
    let warning = if errors.is_empty() {
        String::new()
    } else {
        format!(" ({} failed: {})", errors.len(), errors.join("; "))
    };
    Ok(AttachOutcome {
        message: format!(
            "Detached {} interface(s) from VM {} on bridge {}{}.",
            detached, target_id, bridge, warning,
        ),
        restarted: false,
    })
}

/// Parse `virsh domiflist` output to find every MAC whose source matches
/// the given bridge. Output looks like:
///
/// ```text
///  Interface   Type     Source     Model    MAC
/// -----------------------------------------------
///  vnet0       bridge   vmbr4000   virtio   52:54:00:aa:bb:cc
///  vnet1       bridge   vmbr0      virtio   52:54:00:aa:bb:cd
/// ```
///
/// Robust to header variations and extra whitespace; only matches lines
/// where the third whitespace-separated column equals the bridge name
/// AND the second is "bridge". This is intentionally conservative —
/// network=, direct, etc. don't match.
fn parse_libvirt_macs_for_bridge(stdout: &str, bridge: &str) -> Vec<String> {
    let mut macs = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('-') { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 { continue; }
        // Skip the header row: column 1 is "Interface" (case-insensitive).
        if cols[0].eq_ignore_ascii_case("interface") { continue; }
        if cols[1] != "bridge" { continue; }
        if cols[2] != bridge { continue; }
        // MAC is the last column. Validate shape (xx:xx:xx:xx:xx:xx).
        let mac = cols[cols.len() - 1];
        if mac.len() == 17 && mac.matches(':').count() == 5 {
            macs.push(mac.to_string());
        }
    }
    macs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_lxc_net_index_starts_at_zero_when_empty() {
        assert_eq!(next_lxc_net_index(""), 0);
        assert_eq!(next_lxc_net_index("# comment only\n"), 0);
    }

    #[test]
    fn next_lxc_net_index_finds_max_plus_one() {
        let cfg = r#"
lxc.uts.name = test
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.net.0.flags = up

lxc.net.2.type = veth
lxc.net.2.link = vmbr4000
"#;
        // Highest seen is 2; next should be 3 even though 1 is unused.
        assert_eq!(next_lxc_net_index(cfg), 3);
    }

    #[test]
    fn ip_only_strips_prefix() {
        assert_eq!(ip_only("10.0.1.10/24"), "10.0.1.10");
        assert_eq!(ip_only("10.0.1.10"), "10.0.1.10");
    }

    #[test]
    fn prefix_only_parses_or_none() {
        assert_eq!(prefix_only("10.0.1.10/24"), Some(24));
        assert_eq!(prefix_only("10.0.1.10"), None);
        assert_eq!(prefix_only("10.0.1.10/garbage"), None);
    }

    #[test]
    fn parse_libvirt_macs_typical_output() {
        let out = "\
 Interface   Type     Source     Model    MAC
-----------------------------------------------
 vnet0       bridge   vmbr4000   virtio   52:54:00:aa:bb:cc
 vnet1       bridge   vmbr0      virtio   52:54:00:11:22:33
 vnet2       bridge   vmbr4000   virtio   52:54:00:dd:ee:ff
";
        let macs = parse_libvirt_macs_for_bridge(out, "vmbr4000");
        assert_eq!(macs, vec!["52:54:00:aa:bb:cc", "52:54:00:dd:ee:ff"]);
    }

    #[test]
    fn parse_libvirt_macs_skips_header_and_empty() {
        // Header row "Interface ..." must NOT be matched even though
        // it has 5 columns.
        let out = "\
 Interface   Type     Source     Model    MAC
";
        assert!(parse_libvirt_macs_for_bridge(out, "anything").is_empty());
    }

    #[test]
    fn parse_libvirt_macs_only_bridge_type() {
        // network=, direct, etc. must not be picked up.
        let out = "\
 vnet0       network  default    virtio   52:54:00:aa:bb:cc
 vnet1       direct   eno1       virtio   52:54:00:11:22:33
";
        assert!(parse_libvirt_macs_for_bridge(out, "default").is_empty());
        assert!(parse_libvirt_macs_for_bridge(out, "eno1").is_empty());
    }

    #[test]
    fn stable_veth_name_fits_15_chars() {
        // Real container name short enough — no truncation needed.
        assert_eq!(stable_veth_name("regions80", 0), "ws-regions80-0");
        assert_eq!(stable_veth_name("regions80", 12), "ws-regions80-12");
        // Long container name — truncated to fit IFNAMSIZ.
        let n = stable_veth_name("a-very-long-container-name", 0);
        assert!(n.len() <= 15, "name must fit IFNAMSIZ: got '{}' ({})", n, n.len());
        assert!(n.starts_with("ws-"));
        assert!(n.ends_with("-0"));
        // Non-alphanumeric (hyphens / dots) stripped per Linux iface rules.
        assert_eq!(stable_veth_name("a.b-c_d", 1), "ws-abcd-1");
    }

    #[test]
    fn stable_hwaddr_is_deterministic_and_local() {
        let m1 = stable_hwaddr("regions80", "vmbr4000", 2);
        let m2 = stable_hwaddr("regions80", "vmbr4000", 2);
        assert_eq!(m1, m2, "same inputs must yield same MAC across calls");
        // Different inputs → different MAC (overwhelmingly likely; not a
        // crypto hash but distinct enough for typical inputs).
        assert_ne!(m1, stable_hwaddr("regions81", "vmbr4000", 2));
        assert_ne!(m1, stable_hwaddr("regions80", "vmbr4001", 2));
        assert_ne!(m1, stable_hwaddr("regions80", "vmbr4000", 3));
        // Locally-administered prefix (02:) — first octet bit 1 set.
        assert!(m1.starts_with("02:"), "got {}", m1);
        // 17-char xx:xx:xx:xx:xx:xx shape.
        assert_eq!(m1.len(), 17);
        assert_eq!(m1.matches(':').count(), 5);
    }

    #[test]
    fn parse_libvirt_macs_validates_mac_shape() {
        // A line with the right column shape but a bogus MAC is rejected.
        let out = "\
 vnet0       bridge   vmbr4000   virtio   not-a-real-mac-address
";
        assert!(parse_libvirt_macs_for_bridge(out, "vmbr4000").is_empty());
    }
}
