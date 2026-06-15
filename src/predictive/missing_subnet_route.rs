// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Missing WolfNet subnet-route detector.
//!
//! Symptom: peers reachable (you can ping `10.100.10.30`), but the VMs /
//! LXC containers / Docker containers behind those peers aren't (you
//! cannot ping `172.17.0.5` on the peer's `docker0`). The WolfRouter
//! reconciliation loop happily applies every subnet_route the operator
//! configured, but nothing currently checks that the configured set is
//! *complete* — i.e. that every workload subnet on every remote peer
//! has a subnet_route from this node pointing at the right gateway.
//!
//! This analyzer closes the loop. Each peer now ships its
//! `workload_subnets` in `StatusReport` (see `agent::Node`); we read
//! those, intersect with this node's WolfRouter `subnet_routes`, and
//! emit a high-severity finding for every remote workload subnet that
//! has no route from this node.
//!
//! klasSponsor 2026-05-11: his klnet-12gb VPS can ping all three
//! peers but cannot ping any of the VMs / LXCs / Dockers behind them.
//! He has one route (`10.10.0.0/16 via 10.100.10.30`) and is missing
//! all the others. This finding tells him exactly which CIDR + gateway
//! to add via WolfRouter so the reconciler can apply it.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

/// Finding type emitted by this analyzer.
pub const FINDING_TYPE: &str = "missing_wolfnet_subnet_route";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingRoute {
    /// Peer name from /etc/wolfnet/config.toml (typically the peer's
    /// hostname).
    pub peer_name: String,
    /// Peer's WolfNet IP (the gateway value that a subnet_route would
    /// need to point at).
    pub peer_wolfnet_ip: String,
    /// The workload subnet on the peer that this node has no route to.
    pub subnet_cidr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MissingSubnetRouteFacts {
    pub missing: Vec<MissingRoute>,
    /// Set to false when we couldn't read either /etc/wolfnet/config.toml,
    /// the cluster nodes file, or the WolfRouter config — in any of those
    /// cases we don't know enough to emit OR clear findings, so the
    /// analyzer no-ops cleanly.
    pub scanned: bool,
}

pub async fn sample_now_async(_timeout: Duration) -> MissingSubnetRouteFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> MissingSubnetRouteFacts {
    let peers = crate::networking::get_wolfnet_peers_list();
    if peers.is_empty() {
        return MissingSubnetRouteFacts::default();
    }

    let nodes = match load_nodes_from_disk() {
        Some(n) => n,
        None => return MissingSubnetRouteFacts::default(),
    };

    let cfg = crate::networking::router::RouterConfig::load();
    let configured: Vec<(String, String)> = cfg.subnet_routes.iter()
        .filter(|r| r.enabled)
        .map(|r| (r.subnet_cidr.clone(), r.gateway.clone()))
        .collect();

    let mut missing = Vec::new();
    for peer in &peers {
        let peer_ip_only = peer.ip.split('/').next().unwrap_or(&peer.ip).to_string();
        if peer_ip_only.is_empty() { continue; }

        // Find the cluster Node for this peer. Match by hostname first
        // (most reliable — wolfnet peer names ARE hostnames in every
        // observed deployment). Fall back to matching by an interface
        // IP if the peer's record carries it.
        let node = nodes.iter().find(|n| n.hostname == peer.name);
        let workload_subnets = match node {
            Some(n) => &n.workload_subnets,
            None => continue,
        };
        if workload_subnets.is_empty() { continue; }

        for sub in workload_subnets {
            // WolfStack's subnet-route feature is IPv4-only: apply_subnet_route
            // (src/networking/router/mod.rs) validates an IPv4 gateway and
            // installs `ip route add <cidr> via <gw>`. Flagging an IPv6 workload
            // subnet would hand the operator a broken `ip route add <v6> via
            // <v4>` command (iproute2: "inet6 address is expected rather than
            // …") and a finding that can never auto-resolve, because the
            // reconciler can't apply it. Skip v6 until first-class v6 subnet
            // routing exists. (CodeBangZoom, 2026-06-15.)
            if !is_ipv4_cidr(sub) { continue; }
            if subnet_already_covered(sub, &peer_ip_only, &configured) { continue; }
            missing.push(MissingRoute {
                peer_name: peer.name.clone(),
                peer_wolfnet_ip: peer_ip_only.clone(),
                subnet_cidr: sub.clone(),
            });
        }
    }

    MissingSubnetRouteFacts { missing, scanned: true }
}

/// Load the persisted cluster nodes (workload_subnets included since the
/// v22.13.0 schema bump). Same path as `ClusterState::save_nodes`.
fn load_nodes_from_disk() -> Option<Vec<crate::agent::Node>> {
    let path = &crate::paths::get().nodes_config;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Vec<crate::agent::Node>>(&data).ok()
}

/// True iff the configured routes already cover `target_subnet` through a
/// gateway equal to `peer_ip`. Coverage is satisfied by either an exact
/// CIDR match OR by any configured route that's a strict superset of
/// `target_subnet` and uses the same gateway — e.g. a configured
/// `10.0.0.0/8 via X` covers a peer's `10.0.3.0/24` workload.
fn subnet_already_covered(target_subnet: &str, peer_ip: &str, configured: &[(String, String)]) -> bool {
    let target = match parse_cidr(target_subnet) {
        Some(t) => t,
        None => return false, // unparseable — leave it alone, don't flag
    };
    for (route_cidr, route_gw) in configured {
        if route_gw.trim() != peer_ip { continue; }
        let route = match parse_cidr(route_cidr) {
            Some(r) => r,
            None => continue,
        };
        // Configured route's prefix must be at least as wide as the target
        // (i.e. numerically less or equal). Then check the target's
        // network falls inside the route's mask.
        if route.1 > target.1 { continue; }
        let mask: u32 = if route.1 == 0 { 0 }
            else { 0xFFFF_FFFFu32.checked_shl(32 - route.1).unwrap_or(0) };
        if (target.0 & mask) == route.0 {
            return true;
        }
    }
    false
}

/// True only for a well-formed IPv4 CIDR. The subnet-route feature is
/// IPv4-only (see the skip in `sample_blocking`), so this gates what the
/// analyzer flags — IPv6 CIDRs (which contain `:`) and anything unparseable
/// are excluded.
fn is_ipv4_cidr(cidr: &str) -> bool {
    // Require an explicit `/prefix` (split_once, not split) so a bare IP
    // isn't mistaken for a CIDR — workload subnets are always CIDRs.
    cidr.split_once('/')
        .and_then(|(ip, _)| ip.parse::<Ipv4Addr>().ok())
        .is_some()
}

fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 { return None; }
    let mask = if prefix == 0 { 0 }
        else { 0xFFFF_FFFFu32.checked_shl(32 - prefix).unwrap_or(0) };
    Some((u32::from(ip) & mask, prefix))
}

pub fn analyze(
    ctx: &Context,
    facts: &MissingSubnetRouteFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    // Dedup: a peer with five workload subnets could otherwise produce
    // five separate cards in the inbox — collapse to one finding per peer.
    let mut seen_peers: HashSet<String> = HashSet::new();
    for m in &facts.missing {
        if !seen_peers.insert(m.peer_wolfnet_ip.clone()) { continue; }
        let peer_missing: Vec<&MissingRoute> = facts.missing.iter()
            .filter(|r| r.peer_wolfnet_ip == m.peer_wolfnet_ip)
            .collect();
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", m.peer_wolfnet_ip)),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_proposal(&peer_missing, &scope));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &MissingSubnetRouteFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    // Cover every peer's WolfNet IP — including ones with no missing
    // routes — so when the operator adds the route the finding clears.
    // Done from the (also scanned) peers list rather than just the
    // missing rows so we don't keep stale findings open.
    let peers = crate::networking::get_wolfnet_peers_list();
    peers.iter().filter_map(|p| {
        let ip = p.ip.split('/').next()?.to_string();
        if ip.is_empty() { return None; }
        Some((FINDING_TYPE.to_string(), ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", ip)),
        }))
    }).collect()
}

fn build_proposal(missing: &[&MissingRoute], scope: &ProposalScope) -> Proposal {
    let first = missing[0];
    let title = if missing.len() == 1 {
        format!(
            "WolfNet peer `{}` — workload subnet `{}` is unreachable from this node",
            first.peer_name, first.subnet_cidr,
        )
    } else {
        format!(
            "WolfNet peer `{}` — {} workload subnets are unreachable from this node",
            first.peer_name, missing.len(),
        )
    };

    let subnet_list = missing.iter()
        .map(|m| format!("  • `{}`", m.subnet_cidr))
        .collect::<Vec<_>>()
        .join("\n");

    let why = format!(
        "Peer `{name}` ({gw}) reports {n} workload subnet(s) on its Docker / LXC / VM bridges:\n\n\
         {list}\n\n\
         …but this node has no WolfRouter subnet_route entry whose gateway is `{gw}` covering them. \
         The peer's host is reachable (its WolfNet IP answers), but packets sent to a VM or \
         container on the listed subnets have nowhere to go from here — the kernel doesn't know \
         that those CIDRs live behind `{gw}` until you tell WolfRouter. \
         \n\nThis is the \"peers ping fine, workloads behind them don't\" symptom — adding the \
         route below and waiting one tick for the reconciler is the full fix.",
        name = first.peer_name,
        gw = first.peer_wolfnet_ip,
        n = missing.len(),
        list = subnet_list,
    );

    let evidence: Vec<Evidence> = vec![
        Evidence {
            label: "Peer".into(),
            value: format!("{} ({})", first.peer_name, first.peer_wolfnet_ip),
            detail: Some("Reachable — the missing piece is routing to its workloads.".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "Missing subnets".into(),
            value: missing.iter().map(|m| m.subnet_cidr.clone()).collect::<Vec<_>>().join(", "),
            detail: Some("Advertised via cluster gossip from the peer's local bridges (Docker / LXC / VM).".into()),
            links: Vec::new(),
        },
    ];

    let routes_to_add = missing.iter()
        .map(|m| format!("  subnet_cidr = \"{}\", gateway = \"{}\"", m.subnet_cidr, m.peer_wolfnet_ip))
        .collect::<Vec<_>>()
        .join("\n");

    let instructions = format!(
        "Open WolfRouter on this node, go to Subnet Routes, and add one entry per missing \
         CIDR — gateway always `{}` (the peer's WolfNet IP). Concretely:\n\n{}\n\n\
         The route reconciler from v22.10.6 will apply each `ip route add` within ~60s and \
         the finding will auto-resolve on the next tick. If you'd rather not configure the \
         routes (the peer's workloads aren't supposed to be cluster-reachable), dismiss this \
         finding — it'll stay dismissed.",
        first.peer_wolfnet_ip,
        routes_to_add,
    );

    let commands = missing.iter().map(|m| format!(
        "ip route add {} via {} dev wolfnet0   # one-off; WolfRouter is the canonical place",
        m.subnet_cidr, m.peer_wolfnet_ip,
    )).collect();

    Proposal::new(
        FINDING_TYPE,
        ProposalSource::Rule,
        Severity::High,
        title,
        why,
        evidence,
        RemediationPlan::Manual { instructions, commands },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_already_covered_exact_match() {
        let configured = vec![("10.10.0.0/16".into(), "10.100.10.30".into())];
        assert!(subnet_already_covered("10.10.0.0/16", "10.100.10.30", &configured));
    }

    #[test]
    fn ipv4_cidr_filter_excludes_ipv6_and_garbage() {
        // The subnet-route feature is IPv4-only; v6 workload subnets must be
        // skipped so the analyzer never emits a broken `ip route add <v6> via
        // <v4>` command (CodeBangZoom, 2026-06-15).
        assert!(is_ipv4_cidr("10.10.10.0/24"));
        assert!(is_ipv4_cidr("192.168.1.0/24"));
        assert!(!is_ipv4_cidr("fc42:5009:ba4b:5ab0::/64"));
        assert!(!is_ipv4_cidr("fd00::/8"));
        assert!(!is_ipv4_cidr("not-a-cidr"));
        // A bare IP (no /prefix) is not a CIDR.
        assert!(!is_ipv4_cidr("10.0.0.1"));
    }

    #[test]
    fn subnet_covered_by_wider_route_same_gateway() {
        // Klas's case: he has `10.10.0.0/16 via 10.100.10.30` configured.
        // A peer workload at `10.10.10.0/24` (LAN subnet) IS covered by
        // that wider /16 — should NOT be flagged as missing.
        let configured = vec![("10.10.0.0/16".into(), "10.100.10.30".into())];
        assert!(subnet_already_covered("10.10.10.0/24", "10.100.10.30", &configured),
            "a /24 inside a configured /16 with the same gateway is covered");
    }

    #[test]
    fn subnet_not_covered_by_narrower_route() {
        // A configured /24 does NOT cover a /16 — the operator only has
        // a slice of what's needed.
        let configured = vec![("10.10.10.0/24".into(), "10.100.10.30".into())];
        assert!(!subnet_already_covered("10.10.0.0/16", "10.100.10.30", &configured));
    }

    #[test]
    fn subnet_not_covered_when_gateway_differs() {
        // The route exists but points at a DIFFERENT peer — the workload
        // is still unreachable from this node.
        let configured = vec![("172.17.0.0/16".into(), "10.100.10.20".into())];
        assert!(!subnet_already_covered("172.17.0.0/16", "10.100.10.30", &configured),
            "same subnet but wrong gateway must still flag as missing");
    }

    #[test]
    fn analyze_emits_one_finding_per_peer_even_for_multiple_subnets() {
        let facts = MissingSubnetRouteFacts {
            missing: vec![
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "172.17.0.0/16".into() },
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "10.0.3.0/24".into() },
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "10.0.10.0/24".into() },
            ],
            scanned: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1, "one card per peer regardless of subnet count");
        assert!(out[0].title.contains("ninni"));
        assert!(out[0].title.contains("3 workload subnets"));
        // All three subnets must appear in the body.
        assert!(out[0].why.contains("172.17.0.0/16"));
        assert!(out[0].why.contains("10.0.3.0/24"));
        assert!(out[0].why.contains("10.0.10.0/24"));
    }

    #[test]
    fn analyze_separate_findings_for_different_peers() {
        let facts = MissingSubnetRouteFacts {
            missing: vec![
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "172.17.0.0/16".into() },
                MissingRoute { peer_name: "lillamy".into(), peer_wolfnet_ip: "10.100.10.20".into(),
                    subnet_cidr: "172.17.0.0/16".into() },
            ],
            scanned: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|p| p.title.contains("ninni")));
        assert!(out.iter().any(|p| p.title.contains("lillamy")));
    }

    #[test]
    fn scanned_false_yields_no_proposals() {
        let facts = MissingSubnetRouteFacts {
            missing: vec![MissingRoute {
                peer_name: "x".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                subnet_cidr: "172.17.0.0/16".into(),
            }],
            scanned: false,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        assert!(analyze(&ctx, &facts, &acks, &proposals).is_empty());
    }
}
