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
- `replay/redis/matching` owns exact command selection and source-lane order
  diagnostics. `replay/redis/connection_scope` distinguishes ordinary pool
  reuse from recorded stateful lanes and owns their exclusive target connection
  claims; runtime Redis I/O and session setup remain in `replay/redis/mod.rs`.
- `http/rewrite/json_urls` owns JSON Pointer URL substitution and discovered
  HTTP routes. Recorder configuration owns concise rule validation and the
  source-traffic-policy overlay; no application-specific sandbox plugin is
  required.
- `cli/interception/egress_counters` owns read-only firewall command parsing.
  `replay/egress_counter` owns bounded sampling and per-case counter differences;
  `e2e_run/result/egress` projects this evidence only for failed verification.
  Counter observations never become dependency mismatches or gate inputs.
- `rewrite/ip_capture` owns IP defect preflight, `response_url_evidence` owns
  bounded recorded-response correlation, and `recorder_capture/http_response`
  owns planning/applying acquisition rules through the existing refresh
  lifecycle. Its `review` child owns mandatory path-review responses, while
  `rules` owns selector equality and consolidation by mechanical path coverage.
  Target decides whether source paths contain dynamic IDs; the engine does not
  infer path similarity. `config/source_traffic_policy/http_response` owns the
  compact authority / method-path / pointer / review-note document and its
  recorder projection. `evidence/rule_guidance` owns rule discovery commands.
- `source_snapshot` owns initial and explicit administrator-requested Kubernetes
  Pod capture, immutable source image resolution, effective environment capture,
  supported volume capture, rollback-safe local replacement, integrity
  validation, and the normalized managed-source runtime projection.
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
  `e2e_run/admin_source.rs` coordinates an administrator-confirmed source image
  upgrade with the existing project declaration and derived startup snapshot;
  it does not rerun initialization or rewrite tracked configuration.
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
- Within `rewrite`, `mod.rs` is the public coordinator facade and `advance.rs`
  owns the atomic verification transition. `action.rs` projects actions and
  commands; `coordination.rs` projects executable `pending` and the expanded
  ready/waiting breakdown from the native workflow gate before worker selection.
  `repair.rs` owns revision readiness and the API-scoped permission to replay an
  accepted system repair. `fingerprint/engine.rs` caches the executable digest
  within a process and invalidates it when the file identity changes.
  `recording.rs` owns managed recording execution.
  `execution.rs` owns detached Next/quality launch, completion, failure, and
  recovery without moving verification semantics out of their existing owners.
  `worker.rs` owns persistent dedicated identity, confirmation, and transfer;
  `worker/model.rs` owns worker serialization, `worker/runtime.rs` validates task
  observations and handoffs, and `worker/scheduler.rs` selects executable work
  across current and parked scopes. `worker/events.rs` owns the independent
  durable feedback transaction; `store.rs` folds newer feedback into coordinator
  snapshots on both load and save. These modules never manufacture task-runtime
  handles or manage worktrees. `model.rs` owns the remaining persisted state and
  public action contract and reexports the worker contract for compatibility.
  `inventory.rs` owns the API inventory state machine: stable installation,
  activation and parking, deferred revalidation, and summary/detail
  views. `case_patterns.rs` owns the low-frequency post-recording pattern
  identification gate, persistent canonical API catalog, and add-only policy
  application; it does not mutate recorded cases or delegate this gate to API
  workers. `process_output_model.rs` and `process_outputs.rs` own the separate
  process-output inventory, comparison scheduling, issue projection, and final
  target-fingerprint revalidation. Root `process_output.rs` owns validated
  capture configuration and immutable source/target file evidence.
  `revalidation.rs` owns the coordinator's explicit early-validation
  request boundary and projection for deferred API status.
  Status projection and the traffic lease remain separate owners. Further
  splitting must follow a responsibility boundary rather than divide one
  transaction, action contract, or inventory transition.
  `transition.rs` applies each batch's frozen Comparison requirement and leaves
  parked-slice completion scheduling to the root coordinator. `progress_publication.rs`
  owns the durable first-completion latch for future recording batches alongside
  its existing final delivery publication gate.
  `evidence/overview` owns issue overview identity and projection, including
  process-output diagnostics. `evidence` owns read-only query access, work-item
  resolution, and worker-confirmation checks. Action serialization retains
  scheduling facts and one evidence entrypoint; diagnostic payloads stay in
  evidence reports. Persisted issue payloads retain their evidence contract.
  `configuration_commit` owns the separate persistent-configuration Git commit
  boundary for `status` and `next`; it detects pending configuration before
  dispatch or verification without committing files or treating routine progress
  updates as configuration changes.
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
  narrow MySQL ownership selectors. Its `projection` child resolves bounded
  single-table SELECT fields, aliases and row-selection clauses without owning
  recorded evidence. `replay/mysql/projection.rs` validates evidence and maps
  result columns and cells onto the target projection; the matcher retains
  identity, policy and exchange-consumption decisions.
  `replay/mysql/session_setup.rs` owns builtin
  initialization recognition; `sql_match.rs` owns text/prepared correlation.
  `replay/mysql/sql_match/predicate` uses sqlparser's MySQL grammar and owns
  bounded pure-predicate equivalence; `sql_match/cache` owns Replay-local
  compiled templates, constant normalization and fresh parameter binding.
  `sql_match/predicate/in_list` owns scalar/flat-tuple list shapes, per-component
  type checks, atomic multiset normalization and bounded partial-row PREPARE
  matching. Tuple fields are never normalized as independent sets.
  These do not change shared SQL normalization or ownership/policy selectors.
  The matcher checks live scope, dynamic policy and finite exchange availability
  on every call, while `replay/mysql/projection` validates and projects the
  delivered resultset and PREPARE metadata.
  `mysql/autocommit` recognizes single literal session assignments shared by
  Replay protocol handling and evidence classification.
  `replay/mysql/optional_session` classifies optional transaction setup and
  cleanup from immutable connection sequence/status evidence; its `read` child
  owns the bounded SELECT effect allowlist, and its `autocommit` child proves
  setup omission over the loaded read-only span. Recorder's MySQL semantic
  tracker owns before-command status continuity and final resultset status
  capture. Neither infers transaction
  boundaries from HTTP responses or ORM names.
  `config/process_owned_dependencies/mysql.rs` owns MySQL rule validation and
  matching, while `config/background_mysql_feedback.rs` owns immutable-evidence
  planning and atomic configuration application.

- `rewrite/dependency_rule/planner.rs` owns protocol selector conversion and
  construction of engine evidence plans; its parent owns coordinator rule
  lifecycle and state transitions. `config/process_owned_dependencies/mysql/evidence.rs`
  owns correlation of bounded MySQL report summaries with complete immutable
  exchanges, shared by planning and `replay/report/background_overlay/mysql.rs`.
  That Replay adapter owns reversible MySQL report reclassification only; its
  parent reads immutable case dependencies once for all protocol projections.
  `config/process_owned_dependencies/mysql/tables.rs` owns physical table selector
  validation, matching, and intersection independently of SQL template expansion.
- `rewrite/case_dependencies` owns bounded, read-only per-target dependency
  projections. Its `mysql` child owns query, parameter, connection, and response
  facts for diagnosis; it does not infer process ownership or implement rule
  planning. The shared summary/detail command flow also serves Redis and Memcached.

- `replay/policy/matcher/mysql_values` owns explicit SQL time-slot validation
  across text and prepared calls. It reuses `replay/mysql/sql_match` value
  materialization; the MySQL matcher retains identity and finite consumption.
  `replay/policy/sql_template` owns pure bounded template extraction, and
  `replay/policy/config/mysql` owns rule-schema validation. Its sibling
  `config/mysql_time` owns compact time defaults and legacy syntax conversion;
  the policy document renderer keeps SQL value maps on one line.
  `replay/policy/feedback/mysql_time` owns atomic policy plan/apply; its evidence
  child correlates immutable writes. Coordinator dependency rules persist the plan
  and invalidate validation without changing dependency ownership.

- `request_rules` owns explicit inbound-request transformation policy and the
  per-send runtime. Its `jwt` child owns compact HMAC JWT verification and
  relative NumericDate translation; `keys` resolves private references to
  target startup inputs, and `policy` projects/edits only `request_rules`.
  `request_headers` remains encryption-only. `e2e_run/jwt_evidence` projects
  bounded historical request-time facts; `rewrite/jwt_rule` owns their
  coordinator plan/apply transaction and global revalidation. Its `discovery`
  child projects existing startup inspection contracts without secret values.
  These modules never make expected responses available to request execution.

- `replay/policy/response/json_pointer` owns JSON response selector validation,
  array expansion, evidence matching, and subtree overlap checks. The assertion
  comparator owns value comparison and rule applicability using those resolved
  locations; feedback keeps plan/apply evidence validation and persistence.
- `replay/policy/response/time_rule` owns explicit timestamp-format and duration-unit
  contracts. `replay/assertion/time` owns numeric parsing and fixed five-second
  request-relative validation; artifact adapters supply captured request times.

- `replay/http/cross_case` owns finite HTTP sharing, source-run traversal and
  post-failure request correlation. Its `recording` child streams immutable
  evidence inside one finalized run; `evidence` owns bounded discovery and its
  disposable cache. `replay/policy/feedback/http_cross_case` owns strict policy
  plan/apply. Coordinator dependency rules own dispatch, source proof and
  verification invalidation; neither matcher nor evidence loader changes
  recorded files, target state, or coordinator completion.
