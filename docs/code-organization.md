# Traffic E2E Code Organization

These requirements apply to every traffic-e2e product-code change:

- A changed unit and its parent must keep one clear owner and primary reason to
  change. Adjust the smallest relevant boundary when new behavior no longer
  fits that owner.
- Names must describe the current responsibility. Do not add catch-all
  `common`, `utils`, `helpers`, `manager`, or equivalent ownership for unrelated
  behavior.
- Keep protocol parsing separate from persistence, configuration loading
  separate from runtime behavior, adapters separate from caller lifecycle, and
  production startup separate from test or Replay support.
- Preserve observable contracts and keep unrelated legacy cleanup outside the
  change.
- A touched Rust product source file over 1000 lines must have the touched
  responsibility extracted before new behavior is added.

The remainder of this file defines traffic-e2e-specific package and module
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
  adapter over `motan-protocol` and `motan-codec` from the Breeze Motan Git
  dependency pinned to `v0.0.4`; reusable Motan framing, encoding, and
  request-envelope semantics stay in that companion repository. None of these
  modules owns recording or replay.
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
  it remains one large crate façade within the hard limit because its flat
  exports and shared application-state composition have the same crate-root
  compatibility owner. Feature implementations remain in their owned modules;
  split the façade only when a distinct package or composition lifecycle exists.
  `recording_runtime` owns the Recorder application's listener supervision,
  stop triggers, graceful drain, and finalization lifecycle.
- Proxy and gateway modules own connection and request orchestration.
- Protocol and semantic modules own parsing, encoding, and interpretation.
- Recorder event, run, writer, and summary modules own capture, persistence,
  and reporting.
- Replay modules own recorded dependency matching and replay lifecycle.
- `source_snapshot` owns one-time Kubernetes Pod discovery, immutable source
  image resolution, effective environment capture, supported volume capture,
  local integrity validation, and the normalized managed-source runtime
  projection.
- `startup` owns the source-compatible target startup declaration,
  initialization-owned target-mount snapshot lifecycle, and merged source plus
  override Docker environment projection. Its `snapshot` child copies declared
  paths from the source snapshot or immutable source image, persists them
  atomically, and validates content integrity. Target container and Platform
  runtimes consume these contracts; they do not rediscover startup inputs.
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
- `runtime_output` owns validated application-output declarations and the
  stable host-location projection for retained, run-scoped writable output
  mounts. `target_container/runtime_outputs.rs` prepares Replay-owned host
  directories, while `platform/runtime_outputs.rs` projects the same validated
  contract into managed Record source and Comparison source/target runtimes.
  Runtime outputs are never startup inputs or image build inputs.
- `target_container/build.rs` owns target Dockerfile validation, Docker build
  execution, immutable-image validation, and bounded build-failure diagnostics.
  Its `ssh_agent` child owns the repository-local target-build agent socket,
  stale-agent recovery, default-identity loading, and projection of that exact
  socket into BuildKit. It never owns or persists private-key material.
- `rewrite` owns migration sequencing, the single coordinator state with
  API-scoped AI work slices, the serialized recording/Replay/comparison runtime
  lease, bounded action/evidence projection, rule routing, and the whole-target
  completion gate. It consumes public traffic operations and must not move
  rewrite state or completion semantics into Recorder, Replay, comparison, or
  `e2e_run`.
- `e2e_run/result.rs` owns the one terminal E2E result contract: verification
  gates, response-difference clustering, representative selection, and bounded
  lifecycle diagnosis are derived together from the finalized run state. It
  remains one cohesive module near the 1000-line hard limit so callers cannot
  observe gate and diagnosis projections computed from different rules; move
  tests out or extract a complete diagnostic sub-contract before adding a new
  responsibility.
- `verification_progress` owns the unified business progress transaction across
  recording completion and terminal verification. Its ignored local ledger
  keeps pending batches, idempotency, and irreversible failure barriers;
  `verification_progress/public.rs` owns only the compact committed
  `.traffic-e2e/progress.yaml` projection and migration parser.
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
  views. `case_patterns.rs` owns the low-frequency post-recording pattern
  identification gate, persistent canonical API catalog, and add-only policy
  application; it does not mutate recorded cases or delegate this gate to API
  workers. `process_output_model.rs` and `process_outputs.rs` own the separate
  process-output inventory, comparison scheduling, issue projection, and final
  target-fingerprint revalidation. Root `process_output.rs` owns validated
  capture configuration and immutable source/target file evidence.
  `revalidation.rs` owns the coordinator's explicit early-validation
  request boundary and projection for deferred API status.
  Together, these files are intentionally cohesive near the 1000-line hard limit;
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
- `config/source_traffic_policy.rs` owns the canonical, whole-file YAML contract
  for source-traffic evidence acquisition and classification policy. Static
  recorder fields remain embedded in `.traffic-e2e/project.yaml`; planners
  validate both documents and atomically replace only
  `.traffic-e2e/source-traffic-policy.yaml`.
- Config, TLS, DNS, and process lookup remain focused infrastructure concerns.
- `platform/mod.rs` owns one managed subprocess composition boundary: it maps
  validated project/recorder state into the staged shell runtime and collects
  its result. Protocol evidence validation stays in `platform/preflight.rs`,
  and business-input presentation stays in the separately staged
  `preflight-business-input.sh` asset.
- `config/repository_protocol.rs` owns typed, idempotent recorder protocol
  convergence for initialized repositories. Native and gateway protocol
  endpoints remain owned by the embedded `recorder` section of project YAML;
  this module must not duplicate them in project settings.

Prefer these boundaries while they remain accurate. When implementation proves
that a current parent no longer expresses ownership, make the smallest
feature-local adjustment and preserve observable contracts.

## Repository Check

After the final Rust product-code edit and before commit, run the bundled
checker:

```bash
plugins/ai-software-engineering/skills/backend-rewrite/scripts/check-code-organization
```

Before an MR, set `CODE_ORG_BASE` to the target branch. Use `--all` only for an
explicit repository-wide audit.

- `mysql/sql.rs` owns conservative SQL token/value identity shared by replay and
  narrow MySQL ownership selectors. `replay/mysql/session_setup.rs` owns builtin
  initialization recognition; `sql_match.rs` owns text/prepared correlation.
  `config/process_owned_dependencies/mysql.rs` owns MySQL rule validation and
  matching, while `config/background_mysql_feedback.rs` owns immutable-evidence
  planning and atomic configuration application.
