use actix_web::{web, HttpResponse};
use crate::wolfhost::AppState;
use crate::wolfhost::api::servers::{wolfstack_api, wolfstack_post_pub};
use serde::Deserialize;
use std::sync::Arc;

/// One `dns`-role nameserver, as the fan-out needs it.
struct DnsTierNode {
    id: String,
    is_self: bool,
}

/// The nodes carrying the `dns` role, from the WolfStack cluster view.
/// Empty vec = no DNS tier configured yet → callers fall back to applying
/// locally (single-node WolfHost keeps working exactly as before — Golden
/// Rule). `None` = couldn't reach the WolfStack API at all.
async fn dns_tier_nodes() -> Option<Vec<DnsTierNode>> {
    let data = wolfstack_api("/api/nodes").await.ok()?;
    // GET /api/nodes returns {version, nodes:[...], tls_enabled}, NOT a bare
    // array — read the `nodes` field (matches servers.rs).
    let arr = data.get("nodes").and_then(|v| v.as_array())?;
    let mut out = Vec::new();
    for n in arr {
        // Only real WolfStack nodes can run PowerDNS — a Proxmox-type node
        // can't serve a DNS RPC even if mis-tagged.
        let is_ws = n.get("node_type").and_then(|v| v.as_str()).unwrap_or("wolfstack") == "wolfstack";
        if !is_ws { continue; }
        let roles = n.get("roles").and_then(|r| r.as_array());
        let is_dns = roles.map(|r| r.iter().any(|x| x.as_str() == Some("dns"))).unwrap_or(false);
        if !is_dns { continue; }
        if let Some(id) = n.get("id").and_then(|v| v.as_str()) {
            out.push(DnsTierNode {
                id: id.to_string(),
                is_self: n.get("is_self").and_then(|v| v.as_bool()).unwrap_or(false),
            });
        }
    }
    Some(out)
}

/// Apply one DNS op to every `dns`-role node (self directly, remotes via the
/// node proxy). `local_path` runs on this node; the proxy rewrites it per
/// remote. Returns (applied_ok, errors). When no DNS tier exists, applies
/// once locally so single-node installs are unchanged.
async fn dns_tier_fanout(local_path: &str, body: &serde_json::Value) -> (usize, Vec<String>) {
    let nodes = dns_tier_nodes().await;
    // No tier (or WolfStack unreachable) → apply locally, preserving the
    // original single-node behaviour.
    let nodes = match nodes {
        Some(n) if !n.is_empty() => n,
        _ => {
            return match wolfstack_post_pub(local_path, body).await {
                Ok(_) => (1, Vec::new()),
                Err(e) => (0, vec![format!("local: {}", e)]),
            };
        }
    };
    let mut ok = 0usize;
    let mut errs = Vec::new();
    for node in nodes {
        let path = if node.is_self {
            local_path.to_string()
        } else {
            // Node proxy strips the `/api` prefix and forwards the rest.
            format!("/api/nodes/{}/proxy{}", node.id, local_path.trim_start_matches("/api"))
        };
        match wolfstack_post_pub(&path, body).await {
            Ok(_) => ok += 1,
            Err(e) => errs.push(format!("{}: {}", node.id, e)),
        }
    }
    (ok, errs)
}

/// GET /dns/status — check if PowerDNS is running
pub async fn status(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    let running = crate::wolfhost::provisioning::dns::is_pdns_running();
    let zones = if running {
        crate::wolfhost::provisioning::dns::list_zones().unwrap_or_default()
    } else {
        vec![]
    };

    HttpResponse::Ok().json(serde_json::json!({
        "running": running,
        "zone_count": zones.len(),
        "zones": zones.iter().map(|z| z["name"].as_str().unwrap_or("")).collect::<Vec<_>>(),
    }))
}

/// POST /dns/install — install PowerDNS on the host
pub async fn install(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    tokio::task::spawn_blocking(|| {
        crate::wolfhost::provisioning::dns::install_powerdns()
    }).await.unwrap_or_else(|e| Err(format!("Task failed: {}", e)))
    .map(|_| HttpResponse::Ok().json(serde_json::json!({"status": "installed"})))
    .unwrap_or_else(|e| HttpResponse::InternalServerError().json(serde_json::json!({"error": e})))
}

/// GET /dns/zones — list all DNS zones
pub async fn list_zones(_state: web::Data<Arc<AppState>>) -> HttpResponse {
    match crate::wolfhost::provisioning::dns::list_zones() {
        Ok(zones) => HttpResponse::Ok().json(zones),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /dns/zones/{domain} — get records for a zone
pub async fn get_zone(path: web::Path<String>) -> HttpResponse {
    let domain = path.into_inner();
    match crate::wolfhost::provisioning::dns::get_zone_records(&domain) {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct CreateZoneRequest {
    pub domain: String,
    pub host_ip: String,
}

/// POST /dns/zones — create a zone for a domain. Fans the zone out to every
/// `dns`-role nameserver (all ≥3 NS servers get it); falls back to local
/// PowerDNS when no DNS tier is configured (single-node WolfHost unchanged).
pub async fn create_zone(state: web::Data<Arc<AppState>>, body: web::Json<CreateZoneRequest>) -> HttpResponse {
    let branding = state.config.get_branding();
    let ns1 = if branding.ns1.is_empty() { "ns1.example.com".to_string() } else { branding.ns1 };
    let ns2 = if branding.ns2.is_empty() { "ns2.example.com".to_string() } else { branding.ns2 };

    let payload = serde_json::json!({
        "domain": body.domain, "host_ip": body.host_ip, "ns1": ns1, "ns2": ns2,
    });
    let (ok, errs) = dns_tier_fanout("/api/wolfhost-dns/apply-zone", &payload).await;
    dns_fanout_response(ok, errs, "created", &body.domain)
}

/// DELETE /dns/zones/{domain} — delete a zone from every `dns`-role node.
pub async fn delete_zone(path: web::Path<String>) -> HttpResponse {
    let domain = path.into_inner();
    let payload = serde_json::json!({ "domain": domain });
    let (ok, errs) = dns_tier_fanout("/api/wolfhost-dns/delete-zone", &payload).await;
    dns_fanout_response(ok, errs, "deleted", &domain)
}

/// Shared fan-out result → HTTP: success when at least one nameserver applied
/// the change, but the response always reports how many nodes took it and
/// names any that failed, so a partially-applied zone is never silent.
fn dns_fanout_response(ok: usize, errs: Vec<String>, status: &str, domain: &str) -> HttpResponse {
    if ok == 0 {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("no DNS node applied the change: {}", errs.join("; ")),
        }));
    }
    HttpResponse::Ok().json(serde_json::json!({
        "status": status,
        "domain": domain,
        "applied_nodes": ok,
        "errors": errs,
    }))
}

#[derive(Deserialize)]
pub struct SetRecordRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub content: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_ttl() -> u32 { 3600 }

/// PUT /dns/zones/{domain}/records — add/update a record on every `dns` node.
pub async fn set_record(path: web::Path<String>, body: web::Json<SetRecordRequest>) -> HttpResponse {
    let domain = path.into_inner();
    let payload = serde_json::json!({
        "domain": domain, "name": body.name, "type": body.rtype,
        "content": body.content, "ttl": body.ttl, "delete": false,
    });
    let (ok, errs) = dns_tier_fanout("/api/wolfhost-dns/record", &payload).await;
    dns_fanout_response(ok, errs, "updated", &domain)
}

#[derive(Deserialize)]
pub struct DeleteRecordRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
}

/// DELETE /dns/zones/{domain}/records — delete a record from every `dns` node.
pub async fn delete_record(path: web::Path<String>, body: web::Json<DeleteRecordRequest>) -> HttpResponse {
    let domain = path.into_inner();
    let payload = serde_json::json!({
        "domain": domain, "name": body.name, "type": body.rtype, "delete": true,
    });
    let (ok, errs) = dns_tier_fanout("/api/wolfhost-dns/record", &payload).await;
    dns_fanout_response(ok, errs, "deleted", &domain)
}
