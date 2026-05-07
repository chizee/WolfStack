# XCP-ng / Xen Orchestra integration

WolfStack drives XCP-ng pools through Xen Orchestra's REST API, the
same way it drives Proxmox VE through `pveproxy`. This document
covers the architecture, the surface we wrap, the rationale for
specific choices, and the WolfNet considerations that come up when
WolfStack itself runs *inside* XCP-ng VMs.

## Why XCP-ng / Xen Orchestra at all

A common service-provider deployment is:

- SP runs **WolfStack** as their internal/admin platform
- SP rents **VMs** to customers, provisioned via Xen Orchestra 6 on top of XCP-ng
- Each customer wants their **own WolfStack cluster** running on the rented VMs
- SP wants **one pane of glass** across every customer cluster

The XO integration is the bottom half of that stack — it lets the
SP's WolfStack discover, inspect, and (P2+) drive the actual VMs.
The tenant federation (separate doc, P4) is the top half.

## Architecture

Two layers, each running real WolfStack — no fake "lite" customer
mode:

```
┌─ SP WolfStack (master) ──────────────────────────────────────┐
│   XO Pools page (this integration):                          │
│     • register XO instances by URL + bearer token            │
│     • read pools / hosts / VMs / templates                   │
│     • lifecycle actions on VMs (P2)                          │
│     • provision-VM-from-template + cloud-init bootstrap (P3) │
│                                                              │
│   Tenants page (separate, federation):                       │
│     • per-customer WolfStack cluster of those VMs            │
│     • aggregator dashboard, SSO drill-in                     │
└──┬─────────────────────────────────────────────────────────┬─┘
   │ XO REST + bearer token                                  │ tenant token
   ▼                                                         ▼
┌─ XCP-ng pool (1..N hosts) ──────┐         ┌─ Customer cluster ─┐
│   bare metal, Xen kernel        │ creates │   3 WolfStack VMs  │
│   stores VMs                    │ via XO  │   with full LXC    │
└─────────────────────────────────┘         └────────────────────┘
```

## Why XO REST and not raw XAPI

XCP-ng hosts speak XAPI (XML-RPC) natively — that's the underlying
control plane. Talking XAPI directly avoids depending on XO running
at all. We chose XO REST because:

- **Object model is friendlier**: XO normalises pools / hosts / VMs
  / templates / SRs into a coherent REST resource tree. XAPI
  exposes the raw OCaml objects with hundreds of fields per type.
- **Auth is simpler**: XO mints user tokens through its UI; XAPI
  needs a session login per request.
- **Live websocket option**: when we want push updates instead of
  polling, XO has a websocket subscription channel; XAPI doesn't.
- **Same path the operator already uses**: most XCP-ng installs
  already have XO running for the UI, so requiring it isn't
  imposing a dependency the operator doesn't already have.

The trade-off is one extra moving part (XO daemon) in the chain.
If a customer runs XCP-ng without XO, they'd need to install
`xen-orchestra` from sources or use the Vates appliance.

## What changes vs the Proxmox integration

XCP-ng is a **Type-1 hypervisor**. There is no host-level LXC.
With Proxmox we get LXC for free at the hypervisor level (PVE
hosts CTs natively); here the LXC layer lives one VM down, inside
guest VMs running WolfStack.

So the "takeover" pattern works at two layers, not one:

| Layer | Proxmox path | XCP-ng path |
|---|---|---|
| Hypervisor | WolfStack drives PVE; PVE hosts CTs and VMs | WolfStack drives XO; XO drives XCP-ng pools; pools host VMs only |
| Containers | LXC at hypervisor level | LXC inside WolfStack VMs (one VM deeper) |

## XO REST surface we wrap

`src/xo/mod.rs` mirrors `src/proxmox/mod.rs` shape:

| WolfStack-side | XO endpoint |
|---|---|
| `XoClient::new(url, token)` | n/a — token from XO Settings → Tokens |
| `test_connection()` | `GET /rest/v0` |
| `list_pools()` | `GET /rest/v0/pools?fields=…` |
| `list_hosts()` | `GET /rest/v0/hosts?fields=…` |
| `list_vms()` | `GET /rest/v0/vms?fields=…` |
| `vm_action(uuid, action)` | `POST /rest/v0/vms/{uuid}/actions/{action}` |
| `full_inventory()` | parallel fan-out of the above |

Reference: <https://docs.xen-orchestra.com/restapi>

## Token storage

Tokens are XOR'd with a fixed prefix and base64'd before going to
disk in `/etc/wolfstack/xo_pools.json`. This is the same scheme
WolfStack uses for the rest of its at-rest secrets — it's *not*
encryption (the key is hard-coded in the binary), it's a
"`cat` won't spill it" safeguard. The actual access control is
filesystem permissions on `/etc/wolfstack/`.

Token is never sent back to the frontend. After registration it
stays server-side until the operator unregisters the instance.

## WolfNet considerations when WolfStack runs inside VMs

When the SP provisions 3 WolfStack VMs for a customer, the
customer's cluster runs WolfNet inside those VMs. Three things
matter:

### 1. Topology — do they actually need WolfNet?

| Case | Recommendation |
|---|---|
| All 3 VMs on the same XCP-ng pool / same L2 network | WolfNet works but is over-engineered. The VMs already see each other on the bridge. Recommend: skip WolfNet, point the cluster at native LAN IPs. |
| VMs spread across pools / sites / WAN | WolfNet is exactly what it's for. Each VM gets a `10.10.10.x` address, traffic encrypted, NAT-traversal handled by wireguard's keepalive. |

The provisioning template (P3) defaults to **WolfNet on** so the
customer gets a stable cluster address space even if they later
split VMs across pools.

### 2. MTU

XCP-ng's default VM MTU is 1500. Wireguard adds ~80 bytes overhead
→ effective payload 1420. If those VMs then run LXC containers
with their own WolfNet (nested cluster), the inner overlay drops
to 1340. Default cluster WolfNet MTU is set to **1380** in the
provisioning template to leave headroom for the nested case.

### 3. Tenant isolation

Each customer cluster has its own WolfNet — different wireguard
keys, no peer relationships across customers. Customer A's
`10.10.10.0/24` and Customer B's `10.10.10.0/24` don't conflict
because they're separate wireguard networks.

The SP's WolfStack does **not** join either WolfNet. It talks to
each customer cluster via federation REST tokens over the
management network. Customer data never leaves the customer's
WolfNet.

## Phased delivery

| Phase | Ships | Status |
|---|---|---|
| **P1: Read-only inventory** | XO instance registration, pools / hosts / VMs read, status pills | **shipped** |
| **P2: VM lifecycle** | Start / stop / reboot / hard-halt / suspend / resume buttons in the VM table. Confirmations on destructive ops. VNC console proxy intentionally deferred — needs websocket forwarding which is its own engineering problem. | **shipped** |
| **P3: Provision + cloud-init** | "+ Provision VM" button on each pool card opens a wizard: template select, name, CPUs, memory, optional auto-install of WolfStack via cloud-init. The cloud-init payload sets the hostname, runs setup.sh, configures WolfNet at MTU 1380, joins/creates a cluster, and (optionally) registers federation back with the SP. | **shipped** |
| **P4: Tenant federation** | New `🏢 Tenants` tile in the Apps & Tools drawer. SP-side: register / list / refresh / delete tenant clusters. Customer-side: `/api/federation/status` endpoint and `/api/federation/tokens` CRUD. Roll-up dashboard showing tenant count, host count, VM count, container count, aggregate memory across every customer cluster. | **shipped** |
| **Future**: VNC console proxy | Forward XO's noVNC websocket through wolfstack so the operator can console into a VM without leaving the WolfStack UI. | not started |
| **Future**: SP→tenant SSO drill-in | One-click into a tenant's WolfStack UI as an operator role rather than just opening the URL in a tab. | not started |

## Storage, files, and routes

- **State**: `/etc/wolfstack/xo_pools.json` — list of registered
  XO instances. Path overridable via `paths.xo_pools_config`.
- **Backend**: `src/xo/mod.rs` — XoClient + XoPool + XoStore.
- **Routes** in `src/api/mod.rs`:
  - `GET /api/xo/pools`
  - `POST /api/xo/pools`
  - `DELETE /api/xo/pools/{id}`
  - `POST /api/xo/pools/{id}/test`
  - `GET /api/xo/pools/{id}/inventory`
- **Frontend**: drawer tile `🦊 XO Pools` → `selectView('xopools')`
  → `renderXoPools()` in `web/js/app.js`. Page mount point is
  `#page-xopools` in `web/index.html`.

## Tenant federation (P4) — the customer-side surface

Each customer cluster ships the same WolfStack binary as the SP.
The federation endpoint is one of the routes that binary exposes:

```
GET /api/federation/status       Authorization: Bearer <token>
```

Returns this JSON:

```json
{
  "host_count": 3,
  "vm_count": 0,
  "container_count": 12,
  "mem_total_mb": 16384,
  "mem_used_mb": 4892,
  "cpu_pct": 12.4,
  "wolfstack_version": "22.9.38",
  "timestamp": "2026-..."
}
```

Tokens live in `/etc/wolfstack/federation_tokens.json` — a flat
JSON array of strings. The customer's admin manages them via:

```
GET    /api/federation/tokens          → list (first 8 chars only)
POST   /api/federation/tokens          → mint a new one
DELETE /api/federation/tokens/{prefix} → revoke by 8-char prefix
```

When a token is created, the full string is returned **once** and
never again. The customer copies it and gives it to the SP.

The SP-side flow:

1. SP enters customer URL + token in the Tenants tab "Register"
   modal.
2. SP-side WolfStack probes `GET /api/federation/status` with the
   bearer token. If anything but a 200 with parseable JSON comes
   back, the registration is rejected and nothing is saved.
3. On every refresh (manual or future auto-poll), the SP re-hits
   the status endpoint and updates the tenant row.

## Cloud-init payload (P3 detail)

The auto-install payload generated by `xo::cloud_init::build_wolfstack_user_data`
is plain cloud-config YAML. Verbatim shape:

```yaml
#cloud-config
hostname: <provided>
package_update: false
package_upgrade: false
runcmd:
  - hostnamectl set-hostname <provided>
  - curl -fsSL https://wolfstack.org/setup.sh | sudo bash -s -- --quiet
  - systemctl enable --now wolfstack || true
  - mkdir -p /etc/wolfnet
  - "[ -f /etc/wolfnet/config.toml ] || echo 'mtu = 1380' > /etc/wolfnet/config.toml"
  - <cluster join or init, if cluster_secret was supplied>
  - <federation register, if federation_url + federation_token were supplied>
final_message: "..."
```

Three things to know:
- `package_update: false` — DA-style preseeding can take 10+ minutes
  with apt; we skip it on first boot. The setup.sh handles its own
  package installs.
- WolfNet MTU baked at 1380 (1500 - wireguard overhead - nested
  wireguard headroom).
- Federation register is best-effort (`|| true`) — if the SP's
  endpoint is down at first-boot, the cluster still comes up
  healthy and the SP can register manually later.

The VM template needs cloud-init guest tools installed to consume
the payload. The Vates and upstream XO templates include them; if
a customer rolls their own template, they need
`apt install cloud-init` in it.

## What's intentionally NOT in P1-P4

- **VNC console proxy**. XO's noVNC websocket needs a proxy on our
  side (websocket → websocket forwarding with bearer-token auth).
  Listed under Future.
- **SP→tenant SSO drill-in**. Right now "Open" on a tenant card
  opens the customer's WolfStack URL in a new tab — the operator
  has to know the customer's admin login. A signed one-time URL
  that auto-logs the SP in as an operator role is Future.
- **Pool-scoped XO registration**. Right now one XO instance
  exposes all of its pools. Future refinement: register a single
  pool when the SP has many customers sharing one XO.
- **Auto-poll of tenant status**. P4 ships with manual refresh per
  tenant. A 30s background poll is a small follow-up — the
  scheduler exists, just need to wire it in.
