# Traffic E2E Code Organization

Read the backend-engineering
[code-organization reference](../plugins/ai-software-engineering/skills/backend-engineering/references/code-organization.md)
for the generic boundary, naming, cohesion, dependency-direction, refactoring,
and size rules. This file contains only traffic-e2e-specific package and module
ownership.

## Package Shape

Keep this repository as one Rust crate while the companion `traffic-e2e` and
`backend-rewrite` binaries share the same engine and coordinator library.
Introduce a workspace only when independently versioned packages or a real
package dependency boundary appears. Ask before creating one when the boundary
is unclear.

## Current Boundaries

- Supported dependency protocols are peer domains: MySQL, Redis, Memcached,
  Kafka, and Motan. Do not group protocols by a presumed business use such as
  cache or RPC.
- Top-level `mysql`, `redis`, `memcached`, `kafka`, and `motan` modules own
  reusable protocol parsing and encoding only. They do not own recording or
  replay.
- Top-level `http` owns reusable HTTP forwarding policy. `proxy/http` and
  `gateway/http` own their respective runtimes, while `recorder/http` owns
  recorded HTTP case persistence.
- `recorder/<protocol>` owns capture-time protocol adapters, while
  `replay/<protocol>` owns matching and response behavior for recorded
  evidence. Both may depend on the top-level protocol module, never the
  reverse.
- `main.rs` owns the `traffic-e2e` engine CLI bootstrap only.
- `bin/backend-rewrite/` owns the AI-facing coordinator CLI bootstrap only.
- `lib.rs` owns application wiring, shared state, and stable exports;
  `recording_runtime` owns the Recorder application's listener supervision,
  stop triggers, graceful drain, and finalization lifecycle.
- Proxy and gateway modules own connection and request orchestration.
- Protocol and semantic modules own parsing, encoding, and interpretation.
- Recorder event, run, writer, and summary modules own capture, persistence,
  and reporting.
- Replay modules own recorded dependency matching and replay lifecycle.
- `rewrite` owns migration sequencing, the single coordinator state with
  API-scoped AI work slices, the serialized recording/Replay/comparison runtime
  lease, bounded action/evidence projection, rule routing, and the whole-target
  completion gate. It consumes public traffic operations and must not move
  rewrite state or completion semantics into Recorder, Replay, comparison, or
  `e2e_run`.
- Within `rewrite`, `mod.rs` remains the atomic coordinator-transition facade,
  `action.rs` keeps the exhaustive action/command projection, and `recording.rs`
  keeps the managed recording request/start/worker lifecycle. `worker.rs` owns
  dedicated API-subagent identity binding and dispatch/resume confirmation.
  `inventory.rs` owns the API inventory state machine: stable installation,
  bounded activation and parking, requeueing, and summary/detail views.
  Together, these files are intentionally cohesive near the review threshold;
  status projection and the traffic lease are separate modules, and further
  splitting should follow a real responsibility boundary rather than divide
  one transaction, action contract, or inventory transition.
- Config, TLS, DNS, and process lookup remain focused infrastructure concerns.

Prefer these boundaries while they remain accurate. When implementation proves
that a current parent no longer expresses ownership, make the smallest
feature-local adjustment and preserve observable contracts.

## Repository Check

After the final Rust product-code edit and before commit, run the checker
bundled with `backend-engineering`:

```bash
plugins/ai-software-engineering/skills/backend-engineering/scripts/check-code-organization
```

Before an MR, set `CODE_ORG_BASE` to the target branch. Use `--all` only for an
explicit repository-wide audit.
