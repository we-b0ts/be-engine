# Traffic E2E Code Organization

Read the backend-engineering
[code-organization reference](../plugins/ai-software-engineering/skills/backend-engineering/references/code-organization.md)
for the generic boundary, naming, cohesion, dependency-direction, refactoring,
and size rules. This file contains only traffic-e2e-specific package and module
ownership.

## Package Shape

Keep this repository as one Rust crate while the companion `traffic-e2e`,
`backend-rewrite`, and `backend-rewrite-admin` binaries share the same engine
and coordinator library.
Introduce a workspace only when independently versioned packages or a real
package dependency boundary appears. Ask before creating one when the boundary
is unclear.

## Current Boundaries

- Supported dependency protocols are peer domains: MySQL, Redis, Memcached,
  Kafka, and Motan. Do not group protocols by a presumed business use such as
  cache or RPC.
- Top-level `mysql`, `redis`, `memcached`, and `kafka` modules own reusable
  protocol parsing and encoding only. Top-level `motan` is a traffic-e2e
  adapter over the local `../breeze/motan` `motan-protocol` and `motan-codec`
  path dependencies; reusable Motan framing, encoding, and request-envelope
  semantics stay in that companion repository. None of these modules owns
  recording or replay.
- Top-level `http` owns reusable HTTP forwarding policy. `proxy/http` and
  `gateway/http` own their respective runtimes, while `recorder/http` owns
  recorded HTTP case persistence.
- `gateway/motan` owns primary Motan request admission, fixed-response routing,
  matched-source forwarding, and primary-case persistence orchestration for
  both Motan1 and Motan2.
- `recorder/<protocol>` owns capture-time protocol adapters, while
  `replay/<protocol>` owns matching and response behavior for recorded
  evidence. Both may depend on the top-level protocol module, never the
  reverse.
- `main.rs` owns the `traffic-e2e` engine CLI bootstrap only.
- `bin/backend-rewrite/` owns the AI-facing coordinator CLI bootstrap only.
- `bin/backend-rewrite-admin/` owns explicit administrator repair CLI bootstrap
  only; administrator behavior remains in the library owner for that contract.
- `lib.rs` owns application wiring, shared state, and stable exports;
  it remains one crate façade above the 800-line review threshold because its
  flat exports and shared application-state composition have the same crate-root
  compatibility owner. Feature implementations remain in their owned modules;
  split the façade only when a distinct package or composition lifecycle exists.
  `recording_runtime` owns the Recorder application's listener supervision,
  stop triggers, graceful drain, and finalization lifecycle.
- Proxy and gateway modules own connection and request orchestration.
- Protocol and semantic modules own parsing, encoding, and interpretation.
- Recorder event, run, writer, and summary modules own capture, persistence,
  and reporting.
- Replay modules own recorded dependency matching and replay lifecycle.
- `startup` owns the source-compatible target startup declaration,
  initialization-owned snapshot lifecycle, and Docker environment-file
  projection. Its `snapshot` child owns stopped-source inspection,
  declared-path capture, atomic local persistence, and content-integrity
  validation. Target container and Platform runtimes consume this contract;
  they do not rediscover startup inputs.
  `platform/startup.rs` owns the shell-runtime projection of that snapshot.
- `e2e_run/config.rs` remains the cohesive strict project-schema lifecycle:
  initialization rendering, load/validation, and runtime path resolution must
  agree on one contract. `e2e_run/admin_startup.rs` projects the validated
  project startup declaration into the administrator-owned snapshot recapture
  operation without adding mutation to the ordinary coordinator CLI.
- `internal_runtime` owns the canonical `.traffic-e2e/local/runtime` path used
  by engine-managed mutable state. The directory is inspectable but not a
  stable API; coordinator commands remain the primary interface and all state
  mutation stays with the owning engine module.
- `rewrite` owns migration sequencing, the single coordinator state with
  API-scoped AI work slices, the serialized recording/Replay/comparison runtime
  lease, bounded action/evidence projection, rule routing, and the whole-target
  completion gate. It consumes public traffic operations and must not move
  rewrite state or completion semantics into Recorder, Replay, comparison, or
  `e2e_run`.
- Within `rewrite`, `mod.rs` remains the atomic coordinator-transition facade,
  `action.rs` keeps the exhaustive action/command projection, and `recording.rs`
  keeps the managed recording request/start/worker lifecycle. `worker.rs` owns
  the complete dedicated API-subagent identity lifecycle: dispatch,
  confirmation, explicit ownership transfer, and their state-machine tests;
  it does not own worktrees or the task runtime. `model.rs` owns the single
  persisted and public coordinator serialization contract so state
  compatibility and action-schema changes remain reviewable together.
  `inventory.rs` owns the API inventory state machine: stable installation,
  bounded activation and parking, deferred revalidation, and summary/detail
  views. `revalidation.rs` owns the coordinator's explicit early-validation
  request boundary and projection for deferred API status.
  Together, these files are intentionally cohesive near the review threshold;
  status projection and the traffic lease are separate modules, and further
  splitting should follow a real responsibility boundary rather than divide
  one transaction, action contract, or inventory transition.
- Within `rewrite`, `target_quality.rs` owns the coordinator quality-gate
  transaction. Its `target_replay_isolation` child owns the mandatory,
  deterministic scan that prevents production Rust source from consuming
  Replay-only hostnames, fake addresses, private runtime state, or recording
  artifacts. Keep this product-policy gate separate from the generic
  code-organization checker. Configured repository gates extend it; an empty
  configured gate list does not disable it.
- Config, TLS, DNS, and process lookup remain focused infrastructure concerns.
- `platform/mod.rs` owns one managed subprocess composition boundary: it maps
  validated project/recorder state into the staged shell runtime and collects
  its result. Protocol evidence validation stays in `platform/preflight.rs`,
  and business-input presentation stays in the separately staged
  `preflight-business-input.sh` asset.
- `config/repository_protocol.rs` owns typed, idempotent recorder protocol
  convergence for initialized repositories. Native and gateway protocol
  endpoints remain recorder-owned and this module must not project them into
  project configuration.

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
