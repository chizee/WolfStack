# Fleet Logs — design & roadmap

**Status:** **Phase 1 IMPLEMENTED in v24.41.0** (2026-06-13) — build green, 8 unit
tests + full suite (1198) passing, two independent code-review passes (4 blockers
found and fixed). NOT yet committed (awaiting go-word) and NOT yet runtime-tested
on a live multi-node cluster. Built: native store (`src/loghub/{mod,store,query,
shipper}.rs`), hub/shipper roles, retention janitor + disk circuit-breaker, ingest
/search/cluster-search/stats/config/entitlement endpoints (Enterprise-gated),
redaction-at-source, and the cluster-scoped "Fleet Logs" SPA view (search, live
tail, storage stats, settings). Sources shipped: journald (host), Docker
(`docker logs --since`), LXC (`lxc-attach … journalctl -o json`). Deferred to
later phases (NOT stubbed): AI layer (Phase 2), inverted index / multi-hub
(Phase 3), syslog receiver for non-WolfStack hosts. Author: Shadow, 2026-06-13.
**Origin:** klasSponsor (2026-06-13) — "log retention and aggregation for places
with 20-300 servers ... all the tools available need a lot of time to setup and
monitor ... add AI monitoring to the mix."
**Decision taken:** build-own (native WolfStack log store, no third-party
dependency). Architecture chosen by Paul over orchestrate/hybrid.

---

## 1. The problem & why it's a fit

The 20-300-server SMB segment is a genuine gap:

- Too big for "SSH in and `grep`".
- Too small / too cost-sensitive for Datadog / Splunk per-GB pricing, or for a
  dedicated observability hire.
- Loki / ELK / Graylog are powerful but are *themselves* a part-time job to
  stand up and babysit (collectors per node, storage sizing, retention,
  dashboards, upgrades).

WolfStack already **manages these exact fleets**. Adding "…and it keeps,
searches, and *explains* every server's logs with zero extra setup" is a clean
**Enterprise-tier** upsell. The differentiator is not storage — it's that we can
put the AI we already ship on top of it (Loki won't tell you *what's wrong*).

### What already exists that we reuse (verified in-tree, 2026-06-13)

| Capability | Location | Reuse |
|---|---|---|
| Fleet transport (10s poll, node-proxy `/api/nodes/{id}/proxy/{path}`, shared-secret auth) | `agent/mod.rs`, `api/mod.rs` | Ship + fan-out search ride this; **no new transport** |
| Node enumeration | `ClusterState::get_all_nodes() -> Vec<Node>` (`agent/mod.rs:564`) | Source of truth for "which servers" |
| Continuous journald tail (blocking thread, `journalctl --follow`, auto-restart, dedup) | `auth/log_monitor.rs` (`start_monitor`/`tail_journal_loop`) | **Template for the shipper** — generalise from auth-only to all units |
| Per-source log readers | `storage::read_system_logs` (journalctl+unit+search), `containers::docker_logs`/`lxc_logs`, `kubernetes::get_pod_logs`, `vms::api::vm_logs`, firewall logs | On-demand backfill + non-journald sources |
| AI assistant + KB | `ai/mod.rs` (~4.5k lines, Claude/Gemini), `wolfagents/dispatch.rs::tool_read_log` | Phase 2 — the agent can already read logs as a tool |
| Threshold alerting + email | `alerting.rs` (~1.3k lines) | Extend to log-pattern alerts |
| Cluster fan-out + 30s aggregation cache pattern | `predictive_cluster_cache`, `/api/gateways/cluster`, `federation` | **Exact model** for `/api/logs/search` fleet fan-out |
| Data-dir / config conventions | `paths.rs` (`/var/lib/wolfstack/...` data, `/etc/wolfstack/*.json` config, all override-able via `paths.json` + Settings) | Store + config slot straight in |
| Tier gate | `PatreonTier::is_paying()` / `PatreonTier::Enterprise` (`patreon.rs`) | Enterprise paywall already present |

**Net:** the hard, scary parts of a log platform — moving data between hundreds
of nodes, reading every log source, the AI, the paywall — are done. The missing
middle is **continuous collection → retention store → fleet-wide search.**

---

## 2. Architecture (build-own)

```
   ┌─────────────── every WolfStack node (the "shipper") ──────────────┐
   │  log_shipper thread (one per node, generalised auth log_monitor)   │
   │    journalctl --follow  ─┐                                          │
   │    docker/lxc logs       ├─► normalise → LogEvent → local spool ───┐│
   │    app/unit logs         ┘   (ring buffer, backpressure-safe)      ││
   └───────────────────────────────────────────────────────────────────┘│
                                                                          │ batched POST
                                                                          ▼ (existing secret auth)
   ┌──────────────────────────── hub node (one per cluster) ────────────────────────┐
   │  POST /api/logs/ingest  → append to active segment                              │
   │  Store:  /var/lib/wolfstack/loghub/<node>/<YYYY-MM-DD>/<unit>.<seq>.jsonl.zst   │
   │  Index:  per-segment min/max ts + unit + level + line count (sidecar .idx)      │
   │  Janitor: retention (age + total-bytes cap), compaction, disk-pressure shedding │
   │  Query:  GET /api/logs/search  (time + node + unit + level + text)              │
   └────────────────────────────────────────────────────────────────────────────────┘
                                   ▲
                                   │ fan-out for multi-hub / federated sites
   any node a user logs into ──────┘  GET /api/logs/cluster/search → proxy to hub(s)
```

### Why this shape

- **Shipper = generalised `auth/log_monitor.rs`.** That module already proves the
  pattern: a named blocking thread running `journalctl --follow --since=now`,
  auto-restarting with backoff, dedup-windowed, exiting silently if journalctl
  is absent. We widen the unit filter from `sshd/pve*` to "everything (or an
  operator allow/deny list)", add docker/lxc tails, and instead of feeding the
  lockout system we batch `LogEvent`s to the hub.
- **Hub = one node per cluster**, operator-designated (default: the node the
  feature is enabled on; re-assignable). Not every node stores — that would
  300× the disk. The hub is the only role that needs the big disk.
- **Store = compressed daily JSONL segments**, because that's already the
  WolfStack idiom (referrers, searches, config backups are all JSONL/day) and it
  keeps the single-binary ethos — no embedded DB, no Lucene. `zstd` per closed
  segment. A tiny sidecar `.idx` (segment min/max timestamp, unit, level
  histogram, line count) lets search skip segments without decompressing them.
- **Search = segment pruning + streaming scan.** Resolve the query window →
  list candidate segments from `.idx` → decompress+grep only those → merge by
  timestamp → cap result count. Brute-force but bounded; correct and cheap to
  build. (If volume ever outgrows this, the `.idx` is where a real inverted
  index would later go — explicitly out of MVP scope, **not** stubbed.)

### Data model (`LogEvent`)

```rust
// src/loghub/mod.rs
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct LogEvent {
    pub ts: i64,            // unix millis, hub-normalised
    pub node: String,       // ClusterState node id
    pub source: LogSource,  // journald | docker | lxc | k8s | file
    pub unit: String,       // systemd unit / container name / path
    pub level: LogLevel,    // emerg..debug, best-effort parsed; Unknown allowed
    pub msg: String,        // the line (post-redaction)
    #[serde(default)] pub fields: BTreeMap<String, String>, // structured extras
}
```

`#[serde(default)]` on every optional field (Golden Rule: old hub data must keep
parsing across upgrades). `level`/`source` are `snake_case` enums per repo serde
convention.

---

## 3. Components & code touchpoints

1. **`src/loghub/mod.rs`** (new) — `LogHubState` (segments index, active writers,
   retention config), `LogEvent`, segment writer/reader, janitor. Field on
   `AppState`: `pub loghub: Arc<loghub::LogHubState>` (follows every other
   `Arc<…>` state field).
2. **`src/loghub/shipper.rs`** (new) — generalised from `auth/log_monitor.rs`.
   Blocking threads (`wolfstack-logship-*`) tail journald + docker/lxc; batch to
   hub via the existing inter-node client with `X-WolfStack-Secret`. Local spool
   ring buffer with a hard cap so a slow/absent hub can never grow unbounded on
   the shipping node (drops oldest, increments a dropped-counter surfaced in UI).
3. **`src/loghub/store.rs`** (new) — segment path layout, `zstd` open/close,
   `.idx` sidecar read/write, append, retention/compaction janitor.
4. **`src/loghub/query.rs`** (new) — parse query, prune via `.idx`, stream-scan,
   merge, cap.
5. **`src/api/mod.rs`** — endpoints (see §4) + route registration in
   `configure()`. Tier-gate with `is_paying()`/`Enterprise`.
6. **`src/main.rs`** (~230-825 background-task block) — spawn the shipper on every
   node when enabled; spawn the janitor on the hub.
7. **`src/paths.rs`** — `default_loghub_dir() -> "/var/lib/wolfstack/loghub"`,
   `default_loghub_config() -> "/etc/wolfstack/loghub.json"`. Override-able via
   `paths.json` + Settings, exactly like backups/s3.
8. **`web/js/app.js`** — "Fleet Logs" view (cluster-scoped): live tail, search,
   per-node/unit/level filters, retention/hub settings panel. Visible feedback
   on every action (ARIA), no console-only errors.
9. **`web/index.html`** — nav entry, Enterprise-gated.

---

## 4. API (all under existing cookie auth; inter-node uses `X-WolfStack-Secret`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/logs/ingest` | Shipper → hub batch ingest (secret auth, not cookie) |
| GET | `/api/logs/search` | Query **this hub's** store: `?from&to&node&unit&level&q&limit` |
| GET | `/api/logs/cluster/search` | Fan-out to hub(s) across multi-hub/federated sites, merge (mirrors `/api/gateways/cluster`, 30s cache) |
| GET | `/api/logs/tail` | WebSocket live tail (filtered) — reuses console.rs WS plumbing |
| GET/PUT | `/api/logs/config` | Hub assignment, retention days, disk cap, unit allow/deny, redaction rules |
| GET | `/api/logs/stats` | Disk used, segment count, oldest event, per-node ingest rate, dropped-event counters |

Search response is capped (default 1000 lines) and paginated by timestamp
cursor; the UI says plainly when results were truncated (no silent caps —
matches the project rule).

---

## 5. Retention, disk safety & back-pressure (the part everyone underestimates)

A durable store at 300-server volume is the one genuinely hard piece. Designed
against from day one:

- **Two retention limits, both enforced by the janitor:** max age (days) **and**
  max total bytes. Whichever trips first deletes oldest *closed* segments. Never
  delete the active segment.
- **Hard disk cap with headroom check.** Before opening a new segment the janitor
  checks free space on the store filesystem; under threshold it sheds oldest
  segments first, and if still under, **stops ingesting and raises an alert**
  rather than filling the disk and taking the host down. Degrade, don't die.
- **Shipper-side bounded spool.** If the hub is slow/down, the shipper's local
  ring buffer caps (configurable, default e.g. 50 MB/node); oldest dropped,
  counter surfaced. A backlogged hub can never OOM a shipping node.
- **Batching + compression** keep network and disk sane: events batched (size or
  time flush), segments `zstd`-compressed on close.
- **Bench before we promise numbers.** I will *not* quote ingest/GB-per-day
  figures until measured on a representative load. The closing summary will state
  what was and wasn't benchmarked.

---

## 6. Security & privacy (logs are the most sensitive data we'd hold)

- **Opt-in, off by default.** No node ships or stores anything until an operator
  enables Fleet Logs and designates a hub. (Golden Rule + least surprise.)
- **Redaction at the shipper, before transmit.** Built-in patterns (passwords,
  API keys, bearer tokens, `Authorization:` headers, common secret formats) +
  operator-defined regexes. Redact at source so secrets never hit the wire or
  disk. Ties into the existing `secret_audit.rs` posture.
- **Never auto-ship log contents to an external LLM.** Phase-2 AI analysis is
  explicit, operator-invoked, and redaction-aware — same rule as "status pages
  are public / no auto external notifications". Local/self-hosted model path
  documented for the privacy-strict.
- **Access control.** Fleet Logs view + APIs require auth *and* Enterprise tier;
  ingest requires the cluster secret. (OWASP A01 — authorise this user for this
  action, not just "logged in".)
- **No leakage on error/stat surfaces** (A09/A10) — stats and errors never echo
  log line contents.

---

## 7. AI layer (Phase 2 — the moat, klas's second message)

Built on `ai/mod.rs` + `wolfagents` `tool_read_log` (already exists):

- **Natural-language fleet search:** "auth failures on the db servers last night"
  → structured query against `/api/logs/cluster/search`.
- **Anomaly / what-broke summaries:** periodic or on-demand digest — "across the
  fleet in the last hour: X new error classes, host Y OOM-killed Z, …".
- **AI-drafted incident summaries** from a time window, for tickets/post-mortems.
- **Log-pattern alerts** (extends `alerting.rs`): alert on novel error signatures
  or rate spikes, not just metric thresholds.

All opt-in, redaction-aware, cost-visible (token usage surfaced; batching to
control spend). Local-model option for privacy.

---

## 8. Tier gating & packaging

- Enterprise-only feature via `PatreonTier::is_paying()` + an `Enterprise` check
  (pattern already at `api/mod.rs:29339`). A specific `requires_enterprise`
  helper is the clean addition.
- Free/lower tiers: feature visible but locked with an upgrade prompt (don't hide
  — show the value). Existing per-node on-demand log viewing stays free
  (non-breaking — we add aggregation, we don't paywall what's free today).

---

## 9. Golden-Rule / upgrade-safety checklist

- Entirely **additive & opt-in** — a node that upgrades and never enables Fleet
  Logs behaves exactly as before. No new always-on background work, no new disk
  use, no behaviour change to existing per-node log endpoints.
- All new serialized structs carry `#[serde(default)]`; hub data from an older
  build keeps parsing.
- New paths are `paths.rs` defaults (config-driven), not compiled constants baked
  into existing-config paths — fresh installs get them, existing installs are
  untouched until they opt in.

---

## 10. Phased roadmap

- **Phase 0 — spike (small):** generalise `auth/log_monitor.rs` into a shipper
  that tails all journald units and writes `LogEvent` JSONL locally (no hub yet).
  Proves the collection half on one box. *Exit:* events land on disk, journalctl
  absent = silent no-op.
- **Phase 1 — MVP (the real build):** hub role, ingest endpoint, compressed
  segmented store + `.idx`, retention/disk-cap janitor, `/api/logs/search` +
  cluster fan-out, "Fleet Logs" SPA view (search + live tail + settings),
  Enterprise gate, redaction. *Exit:* multi-node cluster ships → hub stores →
  searchable in UI; disk caps proven to shed not fill.
- **Phase 2 — AI moat:** NL search, anomaly/what-broke summaries, AI incident
  summaries, log-pattern alerts. *Exit:* "what's wrong across my fleet?" answered
  from real data, redaction-aware.
- **Phase 3 — scale (only if needed):** real inverted index in `.idx`, multi-hub
  sharding, longer cold-tier retention (e.g. offload old segments to the existing
  S3/storage layer). Explicitly deferred; **not stubbed** in earlier phases.

---

## 11. Open decisions for Paul

1. **Hub model:** one hub per cluster (simplest, my default) vs. operator picks N
   hubs for HA/sharding from the start?
2. **Non-WolfStack sources:** MVP assumes every server runs WolfStack (true for a
   managed fleet). Do we also want a **syslog/journald receiver** so servers
   *without* the agent can forward in? (Bigger surface; I'd defer to Phase 3.)
3. **Retention defaults:** starting age (e.g. 14 days) + per-hub disk cap default?
4. **Enterprise boundary:** is per-node on-demand viewing definitely staying free,
   with only *aggregation + retention + AI* behind Enterprise? (My assumption.)
5. **Pricing shape** (your call, not eng): flat Enterprise add-on vs. tiered by
   server count / retention.

---

## 12. Honest risk register

- **Store performance at volume** is the make-or-break; §5 designs for safety
  (degrade, cap, shed) but real numbers need benchmarking before we market them.
- **Disk fills** is the classic log-platform outage; the headroom check +
  stop-ingest-and-alert behaviour is mandatory, not optional.
- **Secrets in logs** are inevitable; redaction-at-source is mandatory, not a
  nice-to-have, and must be tested.
- **AI cost/privacy** must be opt-in and visible or it becomes a surprise bill or
  a data-exfil path.
- **Scope creep into "build Splunk"** — the JSONL+prune+scan store is deliberately
  modest; resist the inverted-index/sharding pull until Phase 3 demand is real.
