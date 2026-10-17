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

- `policy/schema` owns the strict self-contained `traffic-policy/v1` document.
  `policy/compiler` owns typed capability validation, field ownership and
  semantic effect fingerprints; neither module reads evidence or changes runtime
  state. `value_contract/time` owns exact timestamp arithmetic and trusted-clock
  relations. `value_contract/json` composes field contracts with strict remainder
  comparison and bounded whole-element multiset pairing; `value_contract/delivery`
  writes only explicitly authorized timestamps in derived copies. These pure
  owners never claim protocol exchanges or mutate recorded evidence.
- `policy_evidence` owns authenticated private payload witnesses, complete
  coverage accounting, sealing and publication of their relative artifacts.
  Public reports retain role/identity/digest metadata without payload bodies.
  Protocol adapters supply independent observed clocks and original exchange
  identities. Assertion and request adapters map the same compiled contracts
  into their existing status, lane, admission and consumption lifecycles.
  Its versioned observation graph separates immutable Source observations,
  independently identified Target requests, derived deliveries and authenticated
  candidate references. Content sharing never merges physical request identities.
  Offline discovery and preflight expand these references through the evidence
  reader; runtime candidate search does not copy complete payload pairs.
  `replay/assertion/native/header_jwt` owns unique header carrier selection;
  `assertion/jwt/url` owns strict URL remainder and signed nonce echoes. Body and
  header adapters reuse the same private key snapshots and JWT verifier. Header
  ownership never implies a JSON body codec or a response-status exemption.

- `replay/report/global_evidence` owns durable, source-bound shared Global report
  inventories and lazy detail projection. Its artifact child owns atomic private
  storage and portable publication; protocol children supply immutable report rows
  and sparse visibility changes using their existing consumption semantics.
  Generic Pub/Sub notifications retain Source-confirmed lane identities and their
  own sparse delivery state. These inventories are evidence, separate from the
  disposable dependency-index cache. Case reclassification remains a reversible
  report overlay. The report layer never grants matching or consumption permission.
  `replay/global_source` supplies a read-only projection view and Source-only
  preparation through the same protocol adapters. Recorder's preparation child
  invokes it after its writers and native indexes are sealed, without a Target,
  Case response oracle, CA or listener. `global_evidence/preparation` owns portable
  source/policy/version binding and prewarm import; failure remains explicit and
  does not change Recorder's original completion contract.
- `value_codec` prepares immutable typed decoding plans and bounded schema reuse;
  decoded Source values may be shared within a comparison. The pure value kernel
  still evaluates every applicable permission and supplied clock independently.
  `replay/policy/request_contract/mysql_selection` owns immutable SQL selector
  preparation and bounded raw-token reuse; bound parameters and live applicability
  never belong in that cache.

- `config/api_trigger` owns API-origin process-rule schema, SQL identity slots and bounded key-template
  validation; `api_trigger` owns immutable origin evidence and disposable index
  persistence. Its `same_resource` child owns report-only read eligibility for
  requests referencing an origin identity, separate from live ordering and
  transaction proof. Its `plan` child owns the shared stale-safe policy transaction;
  `mysql_plan` adapts bounded SELECT/UPDATE selectors. `mysql_transaction` owns
  complete wire-sequence provenance; its `tail` child attributes only a direct
  successful UPDATE-to-COMMIT handoff when the prefix is missing. `redis_script` owns adjacent script-probe
  association. Optional MySQL record locations and SQL prefilter facts belong to `dependency_index/mysql`
  and are built only for configured API-origin discovery. MySQL literal
  INSERT parsing belongs to `mysql/sql/insert`. The existing report overlay owns
  unused-only reclassification and provenance, while Recorder retains idle
  candidates without changing active case ownership or Redis snapshots. Status
  remains a summary/fingerprint reader and never invokes origin discovery.
  `replay/redis/api_origin` applies that same immutable proof to foreign-case
  command ordering before listeners are ready; stateful lanes stay strict and
  recording attribution and finite consumption remain unchanged.

- `engine_binary` resolves companion executables and Linux reexec paths for a
  replaced running engine. Replay, coordinator workers and local interception
  share that resolver; process lifecycle remains with each caller.

- `recording_api/methods` owns the optional per-route method metadata codec and
  lookup. Recorder run finalization projects its existing observed API set into
  the recording manifest once; coordinator execution summaries only read it.

- `verification_progress/revision` owns logical-run scope merging shared by
  publication and revision preflight. Partial prepared inventories retain
  unfinished recording coverage; `e2e_run/progress` compares that merged view
  before permitting focused evidence revision.

- `rewrite/engine_retry` owns per-method retry eligibility and durable consumption
  after an engine Git revision change, including an inventory-only final-route
  fallback that treats Complete/RevalidationPending/Skipped siblings as
  nonblocking without changing their verification status.
  `rewrite/replay_admission` combines exact
  method permits without releasing unaccepted route siblings; `rule_replay` owns
  rule-application requests. `rewrite/verification` owns reservation, Replay and
  result-transition cleanup. E2E state/result publication preserves the actual
  executor revision; `build_info` exposes its build-time constant without status I/O.

- `rewrite/review/batch` owns selected delivery export, private batch documents,
  exact workflow/recording/dispatch binding and generated review commands.
  It reuses `review/candidate` admission and the complete review pipeline;
  export does not run quality checks, reserve handoffs or mutate workflow state.
  The review CLI adapts route selection and batch-file input without rebuilding
  identity or deciding which deliveries belong in an integration assignment.

- `case_group/discovery` validates and retains raw recorded HTTP path identity;
  shared `path_pattern` validation separates exact HTTP paths from canonical
  wildcard patterns. Recording inventories, static groups and regression selectors
  retain exact trailing/repeated separators without aliasing; wildcard matching
  and dynamic source-route grammar stay strict. Unrelated valid noncanonical
  requests cannot block inventory discovery or finalized recording adoption.
  `case_group/snapshot` reads prepared membership for read-only projections
  without discovering recording cases. `e2e_run/reclassify/status` owns the
  query-scoped shared-session snapshot and compact report classification codec;
  `reclassify/session` retains the common identity/membership checks and full
  execution preflight. Coordinator status scopes snapshots to one query.
  `rewrite/case_patterns` canonicalizes persisted recording observations while
  pattern identification waits; `rewrite/regression_scope/recording` validates
  the pin and selectors against that adopted snapshot without rediscovery.

- `config/mysql_tables` owns shared bounded physical-table selection for
  process-owned reads, SQL-time rules and dynamic identity captures. `replay/policy/sql_template/table`
  binds whole table identifiers and qualifiers and checks template intersections; matcher and
  evidence planning retain source/target physical-table equality. CLI table
  bounds live in `bin/backend-rewrite/dependency_rule/mysql_tables`.
  Runtime table-series matching keeps numeric bounds and canonical zero-padding
  without expanding physical names. `replay/policy/matcher/mysql_selectors`
  owns immutable per-policy SQL selector compilation shared by observation,
  PREPARE metadata, request-value validation and response-time selection; case
  scope, request anchors, parameter values and consumption remain live state.
  `replay/policy/matcher/mysql_values` owns pure scalar-slot extraction, binding
  the Source physical table before extracting Target values for dynamic runtime,
  immutable planning evidence and binding-audit restoration.

- `dependency_index` owns disposable semantic evidence locations, source identity,
  atomic index persistence, cancellation and immutable byte caching. Protocol
  matching and sharing eligibility remain in `replay/<protocol>`. Recorder summary
  persistence builds per-file fragments before publication. `replay/loading` owns
  startup inventories; `replay/deferred` owns case preparation and immutable reads;
  `replay/snapshot` projects session state into reports. E2E execution owns the
  separate index preparation deadline and phase publication.
  `dependency_index/evidence` owns complete Source file membership and reusable
  content identities; Recorder seals its catalog after finalization.
  `dependency_index/proof` owns compact exchange selectors and checksum-verified
  original-record reads. The native Source policy owner decides applicability
  and validates every matching record. The rewrite manifest and focused attempt
  summary require exact active-group coverage without requiring unrelated APIs
  to have reached preparation. Full-run completeness remains with execution.

  `dependency_index/global` projects portable Global metadata and groups generic
  notification locations. Sealed fragments from trusted immutable completed
  recordings survive ordinary copies by matching source size and nanosecond
  mtime, then binding the current full file stamp in memory; their relative pages
  remain under the sealed recording root. Local rebuild caches still require the
  full stamp. `pages`, `stream` and `reference` own disk pages,
  immutable traversal and shared original-byte reads. `replay/global` registers
  these inventories through protocol-owned evidence adapters. Redis Pub/Sub's
  `inventory` owns session consumption and its `notifications` child owns ordered
  scheduling. `replay/report/global_evidence` publishes and queries complete
  unused Global pages; runner Replay publication carries them into snapshots.

- Supported dependency protocols are peer domains: MySQL, Redis, Memcached,
  Kafka, and Motan. Do not group protocols by a presumed business use such as
  cache or RPC.

- `redis/wire` owns generic RESP2 Pub/Sub framing; `redis/socketio_rpc` owns the
  bounded Redis-adapter JSON codec without application semantics.
  `recorder/redis/pubsub` owns confirmed subscription state and its `capture`
  child persists generic frames; its `evidence` child retains subscription
  confirmations and same-command Global mirrors without changing Case ownership.
  `recorder/redis/rpc` retains RPC admission
  across connections independently of application events. `recorder/redis/events`
  projects connection/exchange records. `replay/redis/pubsub` owns finite push
  evidence, subscription routing and delivery; its `adapter` child owns
  Socket.IO Redis-adapter identity correlation, while `subscription_evidence`
  resolves exact recording-level anchors and canonical single-use aliases.
  Payload semantics remain with
  the application. Source acquisition and Replay do not consume HTTP oracles.
- Top-level `mysql`, `redis`, `memcached`, and `kafka` modules own reusable
  protocol parsing and encoding only. Top-level `motan` is a traffic-e2e
  adapter over `motan-protocol` and `motan-codec` from the Breeze Motan Git
  dependency pinned to `v0.0.4`; reusable Motan framing, encoding, and
  request-envelope semantics stay in that companion repository. None of these
  modules owns recording or replay.
- Top-level `http` owns reusable HTTP forwarding policy. `proxy/http` and
  `gateway/http` own their respective runtimes, while `recorder/http` owns
  recorded HTTP case persistence.
- `replay/policy/request_contract` owns explicit dependency request selectors,
  atomic comparison decisions, case-local time/nonce state and protected failed
  request witnesses. Its config and overlap children validate ownership; its
  `key` child owns bounded Redis key-window derivation, shaped key captures,
  declared JSON/key identity references, atomic case-local bindings and their
  fingerprint-only planning/audit projection. This is request comparison policy;
  protocol lanes and finite consumption remain with the Redis matcher. Its
  evidence child validates immutable recording witnesses. Redis matching and
  HTTP matching call it only for case-owned exchanges. `replay/http/multipart`
  owns bounded multipart parsing; `replay/http/matching` owns HTTP selection.
  Generated-value feedback and coordinator adapters keep the existing
  evidence/plan/apply/fresh-Replay transaction. Replay control supplies an
  independent inbound request anchor; protocol arguments cannot choose it.
  Its `script` child validates explicit Lua digests and bounded KEYS/ARGV
  envelopes without evaluating Lua. Redis compares dynamic-identity copies
  before disjoint request-time contracts; overlapping field ownership is rejected.
  Its `time` child adapts request-specific source format and calendar constraints
  to `value_contract/time`. Explicit clock groups retain a strict shared default;
  request sequence state carries group observations across commands.
  `redis/publish/json` owns UUID-only JSON comparison copies for composition with time contracts; `redis/matching/request` commits their bindings only after all request checks pass. Planning uses the same copies without mutating recorded evidence. `http_json` owns JSON body stable-field pairing and time comparisons
  using dependency-local clocks, and `evidence/http_json` protects and verifies
  failed target witnesses before planning.
  `replay/policy/case_condition` owns bounded scalar conditions on immutable
  inbound Source JSON. Runtime adapters retain matching rule IDs, and evidence
  planners freeze the same request artifact before admitting a conditional
  rule; dependency payloads cannot choose their own inbound branch.
  `dynamic_values/redis_json` owns exact first-capture JSON projection and
  bounded identity/key reference templates. `feedback/generated_values/redis_time`
  adapts an identity capture and inherited Redis time selector into the existing
  atomic policy transaction, using protected whole-request evidence owned by
  `request_contract/evidence`. CLI and coordinator adapters retain their ordinary
  plan, apply, recovery and fresh-Replay lifecycle.
- `e2e_run/assertion_publication` owns staging-time retargeting of assertion
  details, summary references and their fingerprints for both ordinary terminal
  publication and focused method projections. Store owns atomic directory
  replacement; published consumers never need the transient active directory.
  `e2e_run/replay_publication` stages the original Replay report and dependency
  sidecar into that same snapshot and retargets aggregate report references.
  `replay/report/aggregate/runner` validates runner-selected report locations,
  session identity and complete shared-session coverage while preserving the
  public recording report discovery boundary. `e2e_run/final_evidence` selects
  the prepared recording witnesses for every case in that session before
  recomputing method evidence. `replay/report/background_overlay/original_evidence`
  owns reversible overlay restoration shared by reclassification and ownership
  planners, so interrupted applies can resume from original unused witnesses.
  `e2e_run/reclassify/session` selects exact shared-session method projections and
  owns revision checkpoints for snapshot, index, and progress publication.
  `rewrite/background_reclassification` projects those results into matching
  coordinator slices; `rewrite/fingerprint` separates executed behavior identity
  from process-owned traffic classification when reusing Replay responses.
  `rewrite/plan_recovery` retires a pending rule with unavailable Replay evidence
  and requests fresh verification while returning its selector and source proof.
- `replay/assertion/time` adapts response time configuration and diagnostics to
  the shared `value_contract/time` formats, fixed windows and precision rules.
  `replay/policy/http_headers` owns typed selectors/schema validation, its
  matcher child selects/accounts for rules, and its feedback child owns
  evidence-backed plan/apply. `replay/http/request_headers` owns post-match
  audit evidence; its time-reference child resolves dependency-local recorded or
  completion-minus-duration clocks internally. Its
  timestamp-evidence child verifies immutable witnesses.
  `rewrite/evidence/rule_guidance/http_header_timestamp` projects bounded
  candidates without proving source semantics. The coordinator model and HTTP
  The unified rule transaction owns authoring; protocol children own only their
  typed domain behavior and command projection.
- `gateway/motan` owns primary Motan request admission, fixed-response routing,
  matched-source forwarding, and primary-case persistence orchestration for
  both Motan1 and Motan2.
- `recorder/<protocol>` owns capture-time protocol adapters, while
  `replay/<protocol>` owns matching and response behavior for recorded
  evidence. Both may depend on the top-level protocol module, never the
  reverse.
- `mysql/wire/continuation` owns MySQL logical-message assembly, physical packet
  splitting and continuation sequence validation. Recorder's query tracker
  feeds complete messages to semantic parsing and response completion while
  retaining physical packets for forwarding and debug capture. Replay response
  delivery advances sequence IDs by the physical packets actually written.
- `main.rs` owns the `traffic-e2e` engine CLI bootstrap only.
- `bin/backend-rewrite/` owns the AI-facing coordinator CLI bootstrap only.
- `bin/backend-rewrite-admin/` owns explicit administrator repair CLI bootstrap
  only; administrator behavior remains in the library owner for that contract.
- `record_service` owns the standalone Source/Recorder supervision and recording
  lifecycle. Its `options` child projects optional Recorder configuration while
  retaining HTTP rules; `coordination` owns optional Redis discovery/leases;
  `proxy` owns direct or reservation-aware request forwarding and completion;
  `source` owns fixed-identity process startup, trust, isolation and cleanup.
  Redis primitives stay in the gateway SDK. CLI bootstrap initializes encryption
  before starting Tokio threads. There is one public Source recording command.
- `local_interception` owns reusable fixed-identity firewall setup/cleanup and
  diagnostics; CLI entry points delegate to it. `command_output` owns shared
  broken-pipe-safe diagnostic output for those library and CLI callers.
- `lib.rs` owns application wiring, shared state, and crate exports.
  `replay_exports` owns the public Replay contract façade, separating its growing
  policy/assertion/diagnostic API from application-state composition. Feature
  implementations remain in their owned modules.
  `recording_runtime` owns the Recorder application's listener supervision,
  stop triggers, graceful drain, and finalization lifecycle.
- Proxy and gateway modules own connection and request orchestration.
- `recorder/connections` owns registration and snapshot shutdown of live dependency
  sockets; its transport child retains registration through HTTP upgrades and TLS.
  Protocol adapters register their connected socket pairs and keep semantic capture
  responsibilities. `gateway/http/recovery` owns timeout diagnostics, dependency
  reset and Source completion supervision; the response child preserves the pending
  upstream operation and the lifecycle child returns the downstream timeout while
  supervision continues. `active_case/recovery` owns recovery admission, dependency
  quiet and refusal to admit new cases when recovery cannot finish safely.
- `http/termination` observes downstream EOF/reset without initiating a close.
  `recorder/http/dependency` retains HTTP evidence and dependency admission
  ownership across service cancellation. `replay/http/transport` owns HTTP/TLS
  delivery and `replay/http/termination` validates and completes zero-response
  exchanges. `tcp_gateway/recording` owns gateway evidence persistence.
- Protocol and semantic modules own parsing, encoding, and interpretation.
- Recorder event, run, writer, and summary modules own capture, persistence,
  and reporting.
- Replay modules own recorded dependency matching and replay lifecycle.
- `replay/policy/evidence_policy` owns the shared policy fingerprint check for
  rule evidence. `e2e_run/evidence` reads runner-selected Replay report identity;
  `rewrite/evidence/policy_freshness` projects read-only diagnostics and routes
  refresh through the existing coordinator command and gates.
- `replay/policy/config/document.rs` owns the common dependency rule list codec;
  runtime rule families are partitioned internally without a separate binding section.
- `replay/policy/dynamic_values` owns bounded case-local MySQL/Redis/HTTP capture and
  correlation; its SQL, HTTP and string adapters normalize comparison copies.
  Redis captures reuse `replay/redis/key_selector` for exact/affix/numeric key
  schema and matching; capture comparison retains complete key equality, while
  generated-value feedback selects exact recording witnesses for broad rules.
  Its audit child owns binding fingerprints and planner reconstruction.
  Its `path_segment` child owns bounded HTTP path templates, shaped fields and
  shared timestamp validation; `path_candidates` owns mechanical path witnesses.
  `replay/json_order/decode` owns shared bounded, duplicate-rejecting JSON
  decoding for Redis values and dynamic identities.
  `replay/policy/response_headers` owns header date selectors and validation;
  `replay/assertion/headers/date` owns parameter/date comparison and candidates.
  `replay/policy/feedback/generated_values` owns immutable witness checks and
  policy edits, with separate identity and header evidence children.
  `rewrite/rule/generated_values` owns coordinator plan/apply adaptation,
  `rewrite/evidence/rule_guidance/generated_values` owns diagnostic hints, and
  `bin/backend-rewrite/rule_args` owns the corresponding CLI inputs.
- `replay/redis/matching` owns command selection and source-lane order
  diagnostics. `replay/redis/connection_scope` distinguishes ordinary pool
  reuse (including server-side script execution and cache operations) from
  recorded stateful lanes and owns their exclusive target connection
  claims; runtime Redis I/O and session setup remain in `replay/redis/mod.rs`.
  `replay/redis/cross_case` owns finite sharing of source-proven Redis reads
  across cases in one completed recording; policy feedback owns promotion of
  the corresponding time-shift rule.
- `http/rewrite/json_urls` owns JSON Pointer URL substitution and discovered
  HTTP routes. Recorder configuration owns concise rule validation and the
  typed Source-policy overlay; no application-specific sandbox plugin is
  required.
- `local_interception/egress_counters` owns read-only firewall command parsing.
  `replay/egress_counter` owns bounded sampling and per-case counter differences;
  `e2e_run/result/egress` projects this evidence only for failed verification.
  Counter observations never become dependency mismatches or gate inputs.
- `local_interception/dns` owns fixed-UID DNS redirects and the corresponding
  conntrack-zone rule lifecycle. Its `conntrack` child owns bounded native
  netlink enumeration and exact entry deletion for the reserved DNS zone;
  it never owns general host connection-table maintenance.
- `rewrite/ip_capture` owns IP defect preflight, `response_url_evidence` owns
  bounded recorded-response correlation, and `recorder_capture/http_response`
  owns planning/applying acquisition rules through the existing refresh
  lifecycle. Its `review` child owns mandatory path-review responses, while
  `rules` owns selector equality and consolidation by mechanical path coverage.
  Target decides whether source paths contain dynamic IDs; the engine does not
  infer path similarity. `config/source_traffic_policy/http_response` owns the
  compact authority / method-path / pointer / review-note document and its
  recorder projection. `evidence/rule_guidance` owns rule discovery commands.
- `source_snapshot` owns initialization capture from Kubernetes Pods and local
  Docker containers, explicit administrator-requested Kubernetes Pod upgrades,
  immutable source image resolution, effective environment capture,
  supported volume capture, rollback-safe local replacement, integrity
  validation, and the normalized managed-source runtime projection. Its
  `provider` module owns source selection and typed provenance; `kubernetes`
  and `container` own provider-specific discovery and capture. `image` owns
  immutable-image validation, local archive recovery, and image path copying;
  `environment` owns shared target-environment name filtering. Container
  capture normalizes effective image launch configuration into its committed
  image, so downstream runtimes do not branch on provider type.
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
  `e2e_run/delivery.rs` resolves target-relative managed delivery directories
  and their opt-in named build contexts without moving runtime ownership away
  from the target.
- `internal_runtime` owns the canonical `.traffic-e2e/local/runtime` path used
  by engine-managed mutable state. The directory is inspectable but not a
  stable API; coordinator commands remain the primary interface and all state
  mutation stays with the owning engine module.
- `runtime_output` owns validated application-output declarations and the
  stable host-location projection for retained, run-scoped writable output
  mounts. `target_container/runtime_outputs.rs` prepares Replay-owned host
  directories, while `platform/runtime_outputs.rs` projects the same validated
  contract into diagnostic-preflight source runtime.
  Runtime outputs are never startup inputs or image build inputs.
- `target_container/build.rs` owns target Dockerfile validation, projection of
  configured managed directories into BuildKit named contexts, Docker build
  execution, immutable-image validation, and bounded build-failure diagnostics.
  Its `ssh_agent` child owns the repository-local target-build agent socket,
  stale-agent recovery, default-identity loading, and projection of that exact
  socket into BuildKit. It never owns or persists private-key material.
- `rewrite` owns migration sequencing, the single coordinator state with
  API-scoped AI work slices, the serialized Replay verification
  lease, bounded action/evidence projection, rule routing, and the whole-target
  completion gate. It consumes public traffic operations and must not move
  rewrite state or completion semantics into Recorder, Replay, or
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
  Its `api_scope` child excludes concrete members already covered by a
  same-method pattern in the progress inventory; local history remains intact.
- Within `rewrite`, `mod.rs` is the public coordinator facade and `advance.rs`
  owns the atomic verification transition. `action.rs` projects actions and
  commands; `coordination.rs` projects executable `pending` and the expanded
  ready/waiting breakdown from the native workflow gate and selected action.
  `scheduling.rs` owns gated API revalidation selection and resumable system-repair blocking;
  `waiting.rs` owns bounded read-only waits and the return to external task-event
  reconciliation. Neither implements a task-runtime adapter.
  `repair.rs` owns revision readiness and the API-scoped permission to replay an
  accepted system repair. `rule_replay` owns the API-scoped one-shot Replay
  admission after successful verification-rule application; it does not own
  worker delivery or bypass quality gates. `fingerprint/engine.rs` caches the executable digest
  within a process and invalidates it when the file identity changes.
  `recording.rs` owns invalidation for externally produced recording evidence.
  `recording_input` binds completed conventional batches; `recording_action`
  observes external publication without owning its process or allocating IDs.
  `execution.rs` owns detached Next and legacy quality-receipt operations, completion, failure, and
  recovery without moving verification semantics out of their existing owners.
  `next.rs` owns invocation intent, structured selection of the existing action,
  and optional continuation after fresh passing Replay or terminal results within
  an unfinished revalidation round. It reuses global
  scheduling between atomic steps; execution markers retain mode and retry scope.
  `configuration_commit.rs` owns persistent-configuration commit gates only.
  `expert.rs` owns assistance for the last unfinished API with a running
  implementer after two hours without a code integration, one-time expert identity,
  serialized batch reservation, per-API report-delivery acknowledgement, and
  engine-directed expert closure after API verification;
  `expert/model.rs` owns its serialized
  contract. It uses the worker feedback transaction and never owns task-runtime
  dispatch, API implementation, or traffic acceptance.
  `worker.rs` owns persistent dedicated identity, confirmation, and transfer;
  `worker/identity.rs` resolves runtime handles and validates delivery report
  identity; `worker/model.rs` owns worker serialization, `worker/runtime.rs` validates task
  observations, handoffs and the admitted code-integration clock, and `worker/scheduler.rs` selects executable work
  across current and parked scopes. `worker/events.rs` owns the independent
  durable feedback transaction and normalizes binding keys before merging the
  newest per-route callback; `store.rs` folds feedback into coordinator snapshots
  on both load and save. These modules never manufacture task-runtime
  handles or manage worktrees. `model.rs` owns the remaining persisted state and
  public action contract and reexports the worker contract for compatibility.
  `recording_api/scope` owns exact route/canonical pattern selector grammar and
  identity shared by coordinator commands and local regression configuration. `api_selector`
  owns executable route-to-method inventory selection and worker scope projection.
  `api_batch` owns grouped preparation
  and method-slice transitions for one route acceptance. `e2e_run/focused_batch`
  owns terminal method evidence publication from a shared Replay session; it
  never alters recorded cases or moves rewrite scheduling into E2E execution.
  `inventory.rs` owns the API inventory state machine: stable installation,
  activation and parking (in `inventory/selection.rs`) and deferred revalidation.
  Its `revalidation_round` child owns persisted sweep membership, the all-accepted
  or confirmed-gap start gate, and consumption independently of fingerprint freshness.
  `inventory/views` owns the read-only route summary and route-item projection
  with per-method verification details; the persisted ledger remains method-keyed.
  Its `inventory/source_route` child owns source-route binding,
  correction of unused invalid bindings, and validated binding retention across
  recording batches, reusing case-group route validation.
  `case_patterns.rs` owns the low-frequency post-recording pattern
  identification gate, persistent canonical API catalog, and add-only policy
  application; it does not mutate recorded cases or delegate this gate to API
  workers. `work_scope.rs` owns the API worker scope identity.
  `revalidation.rs` owns the coordinator's explicit verification request
  boundary and projection for deferred API status. Requests and scoped Next obey
  the same round gate and cannot turn stale successes into first-pass work.
  Status projection and the traffic lease remain separate owners. Further
  splitting must follow a responsibility boundary rather than divide one
  transaction, action contract, or inventory transition.
  `purpose` owns the read-only `pr_base` purpose boundary for status/next and
  direct worker/traffic dispatch. `regression` owns authorized purpose entry,
  automatic work-branch creation, old-round archival through `store`, external
  recording adoption and Replay initialization. `initialization` owns construction
  of a new rewrite workflow, shared by ordinary advance and purpose entry. Entry requires
  an actual current-coordinator runtime query declaring zero active child sessions;
  this is independent of engine bindings and historical sessions. Old-worker
  cleanup is not an entry prerequisite. Each API can bind once in the new workflow;
  subsequent worker transfer retains its separate authorization contract. `e2e_run/branch` requires a work branch.
  `regression_scope` owns selected recording adoption and reversible API exclusion
  at coordinator load/advance boundaries.
  Its `recording` child validates explicit recording selection and resets batch
  state; `artifacts` retains ownership of manifest and recorded-case validation.
  `config/regression` owns the separate ignored YAML schema, route-level matching
  and defaults, using the shared scope grammar without depending on rewrite state.
  `transition.rs` classifies Replay results and leaves parked-slice completion
  scheduling to the root coordinator. `progress_publication.rs` owns
  the final delivery publication gate for the selected regression scope.
  `evidence/overview` owns issue overview identity and projection, including
  current worker context outside evidence hashes.
  `evidence/access` owns read-only assignment/opaque-query resolution and
  worker-confirmation checks; `evidence` owns bounded API diagnostic queries.
  `bin/backend-rewrite/evidence` owns CLI selector parsing for that read-only
  contract. Action serialization retains scheduling facts and coordinator
  commands; diagnostic payloads and detail queries stay in evidence reports.
  Persisted issue payloads retain their evidence contract.
  `configuration_commit` owns the separate persistent-configuration Git commit
  boundary for `status` and `next`; it detects pending configuration before
  dispatch or verification without committing files or treating routine progress
  updates as configuration changes.
- Within `rewrite`, `quality.rs` owns delivery-time isolation and explicit worker,
  integration and final pre-revalidation receipt scope and policy identities.
  Worker and ordinary integration stages run source/isolation checks without
  mandatory repository commands. The final stage owns full fmt/test/Clippy
  execution with real command outcomes/logs, not skill-attested shell results.
  `quality/commands` derives project-local Cargo commands and their relative
  working directories, runs them serially with private logs, and binds command
  inventory plus cwd into receipt validation and policy identity.
  Worker receipts cannot satisfy integration admission; ordinary integration
  receipts cannot satisfy the final gate. Historical command DTOs remain readable
  but do not grant current admission. `target_quality.rs` is a
  compatibility boundary for validation of an
  already admitted receipt; it never executes repository checks. The
  `target_replay_isolation` module, owned by `quality`, owns the mandatory,
  deterministic scan that prevents production Rust source from consuming
  Replay-only hostnames, fake addresses, private runtime state, or recording
  artifacts. Keep this product-policy gate separate from the generic
  code-organization checker. Repository instructions may add development checks
  but cannot replace or disable this engine standard.
- `rewrite/source_diff.rs` owns the Git source-diff boundary shared by Replay
  isolation and source review, including committed/worktree/untracked files and
  rename handling. Its `layout` child maps a target project nested below the Git
  repository root onto the corresponding directory in worker and integration
  worktrees, validates managed-file access, and owns conversion between
  target-relative and Git tree paths. Source diff expands over the target plus
  configured same-repository managed directories and rejects tracked candidate
  changes outside that delivery scope.
  Its `cache` child reuses successful Git identity/history reads and PR-base
  resolution only within a status/inventory query, keyed by directory and exact
  arguments. Other Git commands invalidate those reads; later queries inspect
  Git again.
  `rewrite/review` owns the complete worker/integrator review
  pipeline, spawn evidence, handoff admission, and quality rework routing. Its `scan`
  child owns Rust syntax findings and complete-file line limits; `evidence`
  validates AI-provided locations and lifecycle explanations without claiming
  call-graph proof. `candidate` owns cross-worktree candidate identity, frozen
  canonical check context, and publication receipt admission without check
  execution. `integrated` owns ordinary freshness, action projection and
  unchanged-purpose baseline admission. Its baseline comparison uses
  `fingerprint::matches_revision` to include tracked/untracked source and
  configuration changes while excluding traffic policy, private runtime and
  progress publication. Ordinary review fingerprints use the same policy
  exclusion; traffic verification fingerprints retain configured traffic policy.
  `review/pre_revalidation` owns the final state-machine gate, exact-candidate
  check reuse and admission, preserved system-repair slices, and the complete
  post-admission sweep. It binds durable sweep progress to the accepted report's
  SHA256 identity, preserving crash recovery without inheriting an earlier
  candidate's consumed membership. Its `inputs` child hashes Cargo manifests,
  lockfiles, Cargo configuration and Rust toolchain files from each managed
  project through its repository ancestors, and enforces tracked build-input
  commits. Final checking/admission also requires committed target/managed code.
  Final proof binds canonical inputs, check policy, verification policy,
  inventory and immutable recording; progress-only publication can reuse a
  matching receipt without another suite execution. `repair`
  returns quality findings to existing API worker ownership,
  including fresh unpublished candidate reports without admitting failed code.
  Review does not create traffic failures or a second migration state machine.
- `config/source_traffic_policy.rs` owns the canonical, whole-file YAML contract
  for source-traffic evidence acquisition and classification policy. Static
  recorder fields remain embedded in `.traffic-e2e/project.yaml`; planners
  validate both documents and atomically replace only
  the unified file named by `project.policy`.
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
  bounded pure-predicate equivalence for single-table SELECTs and strict-envelope
  direct-table JOIN SELECTs; `sql_match/cache` owns Replay-local
  compiled templates, constant normalization and fresh parameter binding.
  `sql_match/query_in` owns bounded full-AST list-order compatibility inside
  correlated `EXISTS` branches and supported `UNION ALL` read trees with joins,
  derived tables, inline windows, and computed projections. Every surrounding
  query node remains strict.
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
  owns bounded query classification with common locking/side-effect exclusions,
  independently of SQL equivalence. It owns compact immutable Global read-span
  tails used to classify a case's leading transaction end, and keeps case-to-case
  transaction inference out of the loader. SELECT expressions do not require per-shape
  registration. Its `autocommit` child checks setup omission over the loaded
  read-only span. `replay/mysql/cleanup_selection` gives a required transaction
  end precedence over identical optional cleanup only after its immediately
  preceding recorded exchange has been consumed. Recorder's MySQL semantic
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
  `config/mysql_tables.rs` owns physical table selector
  validation, matching, and intersection independently of SQL template expansion.
- `rewrite/case_dependencies` owns bounded, read-only per-target dependency
  projections. Its `mysql` child owns query, parameter, connection, and response
  facts, including captured before/after server-status flags, for diagnosis;
  it does not infer process ownership or implement rule
  planning. The shared summary/detail command flow also serves Redis and Memcached.
  `rewrite/evidence/mysql_diagnosis` owns investigation guidance for unconsumed
  MySQL calls. It distinguishes call-consumption facts from unresolved source
  ownership and rule discovery; matching and omission decisions remain with Replay.

- `replay/policy/matcher/mysql_values` owns explicit scalar and exact nested-JSON
  SQL time-location validation across text and prepared calls. It shares the fixed
  request-relative timestamp comparator in `replay/assertion/time` through
  `replay/policy/value`, and consumes the case anchors owned by
  `replay/policy/request_contract`. Snapshot case reports publish the captured
  request times for evidence-backed planning. It reuses
  `replay/mysql/sql_match` value
  materialization; the MySQL matcher retains identity and finite consumption.
  SQL time metadata previews allow unbound placeholders only during prepare;
  execution retains time and stable-value validation for SELECT and writes.
  `replay/mysql/sql_match` also proves exact bound-token equality between two
  prepared forms independently of semantic predicate support; projection owns
  materialized result-column metadata and delivery adaptation.
  `replay/policy/sql_template` owns pure bounded template extraction, and
  `replay/policy/config/mysql` owns rule-schema validation. Its sibling
  `config/mysql_time` owns compact relative-time defaults and legacy syntax conversion;
  the policy document renderer keeps SQL value maps on one line.
  `replay/policy/feedback/mysql_time` owns atomic policy plan/apply; its evidence
  child correlates immutable writes. Coordinator dependency rules persist the plan
  and invalidate validation without changing dependency ownership.
  `feedback/generated_values/mysql_time` jointly proves explicitly selected
  identity and time locations in one immutable exchange. It reuses the existing
  identity normalization and relative-time contracts, then publishes both rules
  through the same atomic generated-value plan transaction.
  MySQL identity captures share the bounded table selectors and
  `matcher/mysql_values` pair extraction: bind the Source physical table before
  extracting Target values. Runtime capture, evidence planning and binding-audit
  restoration use that same operation. `sql_template/table` owns declaration
  intersection across complete table ranges for policy admission.
  `rewrite/rule/generated_values` freezes the engine's file witnesses across
  coordinator plan/apply commands. `e2e_run` supplies the active-attempt guard
  independently of report availability; `rewrite/plan_recovery` retires legacy
  or stale file/signature proofs and requests fresh Replay.
  `replay/mysql/time_shift` translates selected datetime result cells on delivery
  copies. `replay/policy/config/mysql_response` owns bounded result selectors;
  `matcher/mysql_response` selects rules and accounts for successful delivery.
  `feedback/generated_values/mysql_response` proves matched immutable result
  evidence and reuses the generated-value plan/apply transaction. None of these
  owners authorizes request SQL differences or changes recorded result payloads.

- `request_rules` owns explicit inbound-request transformation policy and the
  per-send runtime. Its `jwt` child owns compact HMAC JWT verification,
  Bearer-header or named-query selection, and relative NumericDate translation;
  `keys` resolves private references to
  target startup inputs, and `policy` projects/edits only `request_rules`.
  `request_headers` remains encryption-only. `e2e_run/jwt_evidence` projects
  bounded historical request-time facts; `rewrite/jwt_rule` owns their
  coordinator plan/apply transaction and global revalidation. Its `discovery`
  child projects existing startup inspection contracts without secret values.
  These modules never make expected responses available to request execution.
  Its pure `jwt/contract` child compares signed headers, stable claims,
  request-relative NumericDate offsets and explicitly selected nonces;
  response assertions and Redis write assertions share that validator.
  Its `nonce` child owns legacy/typed nonce declarations and bounded canonical
  UUID/base64url representation checks. Its `url_query` child owns bounded URL
  validation, raw query-value extraction and format-only candidate discovery;
  it never resolves signing inputs or rewrites recorded requests.
- `json_value` owns bounded strict JSON decoding with duplicate-member
  rejection. Replay JSON normalization and signed-token validation share it;
  selector expansion and collection normalization stay in Replay.
- `replay/policy/response/jwt` owns explicit JWT response selectors, response-only
  algorithms, typed public/startup key references and companion time fields.
  Its `key_source` child validates exact recorded MySQL selectors; `input`
  provides bounded field-specific CLI diagnostics. `replay/assertion/jwt/keys`
  resolves startup keys or one immutable case-local recorded public key;
  `rsa` authenticates RS256 signatures without request transformation, and
  `companions` validates signed iat/exp and TTL derivations. The shared pure
  claims validator retains stable-claim, time and nonce checks for both families.
  The JSON comparator selects owned fields of a composite JWT rule;
  related array indexes stay scoped to the same response item. Generated-value feedback's
  `response_evidence` child owns protected response observation admission;
  `response_jwt` owns signed witness validation and atomic plan/apply through
  the existing coordinator rule transaction. JSON subtree ownership remains
  in `response/json_validation` and the shared pointer-overlap validator.

- `replay/policy/response/json_pointer` owns JSON response selector validation,
  array expansion, evidence matching, and subtree overlap checks. The assertion
  comparator owns value comparison and rule applicability using those resolved
  locations; feedback keeps plan/apply evidence validation and persistence.
- `replay/policy/response/time_rule` owns explicit timestamp-format, comparison-mode and duration-unit
  contracts. `value_contract/time` owns numeric parsing and fixed five-second
  request-relative validation; artifact adapters supply captured request times.
  `feedback/time_plan` preflights proposed response time rules with this same
  comparator and freezes actual case/response witnesses before plan/apply.
  `rewrite/plan_recovery` retires unavailable or policy-stale pending plans
  without applying them. SQL-time recovery mirrors the dynamic-binding policy
  admission condition and requests fresh Replay only for the plan's owner slice.
- `replay/assertion/docx` owns bounded OPC ZIP expansion and DOCX part comparison.
  ZIP timestamps, compression choices, entry order, and offsets are container
  metadata; configured XML timestamp elements reuse request-relative time
  validation, while unselected decompressed parts remain exact.
  `replay/policy/feedback/response_body/docx_plan` owns evidence-backed DOCX
  plan construction, while the sibling `plan_apply` owns shared atomic apply
  and offline re-verification for every structured response-body codec.

- `replay/http/recording` owns bounded standard-run HTTP evidence traversal;
  `replay/http/selector` owns exact dependency endpoint selection, and
  `replay/http/identity` owns request fingerprints and canonical JSON identity.
  `replay/http/cross_case` owns finite HTTP sharing and
  post-failure request correlation. Its `evidence` child owns bounded discovery and its
  disposable cache. `replay/policy/feedback/http_cross_case` owns strict policy
  plan/apply. Coordinator dependency rules own dispatch, source proof and
  verification invalidation; neither matcher nor evidence loader changes
  recorded files, target state, or coordinator completion.
  `replay/http/request_headers` owns post-match outbound request-header auditing,
  its built-in exclusions, and protected difference observations. It does not
  select exchanges or change response delivery. `request_headers` retains
  encryption ownership, including dependency-header decryption; dependency
  reports and aggregation own dirty propagation and bounded diagnosis.

- `replay/http/unordered` owns explicit request JSON array normalization and
  bounded order-only witnesses; its `evidence` child verifies those witnesses
  against finalized Replay and immutable source exchanges. It never shares
  exchanges or changes ownership. `replay/policy/http_json` owns its YAML
  contract, `matcher/http_json` previews policy usage, and
  `feedback/http_unordered` owns stale-safe plan/apply. Worker discovery remains
  in `rewrite/evidence/rule_guidance`; the coordinator owns fresh verification.

- `replay/redis/value` owns whole-string write value decoding and comparison;
  its `selector` child defines endpoint/key/field selection and its `evidence`
  child captures bounded order witnesses and verifies immutable source evidence.
  `replay/policy/redis_value` validates the YAML contract, its matcher adapter
  commits selected rule usage, and `feedback/redis_unordered` owns stale-safe
  plan/apply. Redis matching continues to own source lanes and consumption.
  `bin/backend-rewrite/dependency_rule/redis` owns Redis CLI conversion, while
  coordinator dependency-rule and evidence owners retain lifecycle and discovery.
- `replay/json_order` owns shared dependency JSON object identity and explicit
  array normalization; HTTP identity and Redis values consume it.
  `replay/recording_evidence` owns standard-run evidence file boundaries shared
  by protocol-specific visitors. `replay/assertion/protobuf/wire` owns bounded
  binary decoding; its `unordered_evidence` sibling exposes typed order witnesses
  without authorizing a schema or a rule.

- `replay/redis/time_shift` owns explicit relative-time translation of matched
  read-response copies. Its `config` child validates GET/HGET selection and
  timestamp fields; `timestamp` owns Unix integer and RFC3339 string validation
  and translation; `evidence` verifies source-selected immutable exchanges
  against a finalized API attempt without heuristic discovery. Redis delivery
  owns the send-time anchor and successful-use observations; finite matching
  remains unchanged. `policy/feedback/redis_time_shift` owns stale-safe policy
  plan/apply, with source proof retained in coordinator plan records.
  `replay/redis/key_selector` owns compact and legacy-compatible key/hash-field
  byte selectors; `replay/redis/json` owns bounded duplicate-rejecting JSON
  decoding shared by request-value comparison and response transformation.

- `replay/redis/lock` owns bounded token positions and case/resource-local nonce
  bindings. Its evidence child owns token-only witnesses and immutable
  acquisition/reference validation; script interpretation and target lock
  behavior remain outside Replay matching. `policy/redis_value` owns the compact
  `redis.lock` schema and overlap validation, its matcher projects runtime rules,
  and `policy/feedback/redis_lock` owns stale-safe plan/apply. The Redis lock CLI
  child projects explicit host/port/key selectors; coordinator evidence exposes
  conditional hints and fresh-Replay planners through the existing lifecycle.

- `replay/redis/publish` owns bounded textual UUID positions and publisher
  identity bindings inside opaque PUBLISH payloads. Its evidence child owns
  UUID-only mismatch witnesses and immutable exchange verification. No message
  deserializer is executed. `policy/redis_value` owns `redis.publish` schema and
  overlap checks; `policy/feedback/redis_publish` owns stale-safe plan/apply.
  The Redis CLI publish child projects exact endpoint/channel/UUID positions or
  bounded ASCII field markers.
  Redis matching owns lane ordering and finite consumption; connection scope
  retains whole-lane stateful affinity, including publishers in such lanes.

- `replay/command_matching` separates lane-order admission from final response
  consumption. Case-scoped Redis claims satisfy request order while Responding,
  so pooled sockets cannot race successful delivery bookkeeping. Unclaimed,
  failed and client-termination exchanges remain blockers; final success and
  policy usage are still committed only after delivery. Other protocols keep
  their existing consumption-based admission.


## Unified policy responsibilities

- `policy/{schema,native,native_compile,strict_map,capability}` owns closed typed
  contracts, Source scope and pure validation. Unknown combinations reject before
  replay; adapter admission and runtime construction share typed projections.
- `policy/authoring` owns document revision context, rule-local proof inheritance,
  named contract abbreviations and readable YAML rendering. Its closed traversal
  expands only typed contract locations, preserving business literals and the
  complete rule/proof IR used by compilation, plans and evidence. Rendering
  verifies compiled equality after a parse round trip.
- `value_contract/{json,encoded,time,generated,delivery}` owns pure values, whole
  element pairing, microsecond relationships, conditional fields and staged
  nonces/templates. Keys are borrowed immutable inputs; bytes and plaintext do
  not enter errors or reports.
- `replay/policy/native_projection` translates typed effects to existing domain
  data. Its SourceSession exercises a complete immutable Source trace in private
  state; it cannot claim live Target work or certify Target correctness.
- Protocol adapters keep envelope/session/lane/transaction/claim/delivery and
  termination responsibility. They call shared value contracts only for selected
  slots. SQL generated parameters bind atomically with scalar/JSON comparisons.
- `config/native_policy` owns acquisition, API origin, process ownership, finite
  sharing obligations and lossless whole-policy updates. `unified_policy_path`
  resolves the sole Target-root-relative `project.policy` path.
- `rewrite/unified_rule/{manifest,preflight,discovery}` owns complete protected
  evidence, Source/Target role distinctions, reviewable plan/apply and recovery.
  `manifest/primary` freezes each selected Case's original primary-response oracle
  and published assertion/Target artifacts, including inline binary bodies, even
  for dependency-only rules. `preflight/{api,dependency,session,source}` delegates
  payload, native envelope, stateful Source trace and whole-recording proof to
  their existing owners. Whole-recording Source effects explicitly enumerate
  their broader inventory; ordinary payload rules retain their prepared API scope.
  Coordinator admission preserves write intents and fresh real verification
  obligations across crashes. Bounded hints never substitute for full coverage.
- Historical feedback DTOs may remain as domain data or journal recovery inputs.
  Their old authoring entrypoints reject and production loaders accept only
  `traffic-policy/v1`. Test-only explicit fixture migration is not a reader
  fallback and cannot produce project proof.
