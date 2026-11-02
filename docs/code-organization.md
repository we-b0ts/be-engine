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

- `protocol_contract` owns closed protocol, role and native-version identities.
  `primary_protocol` adapts immutable HTTP/Motan inputs to genuine native
  execution and independent observations; `e2e_run/primary_driver` owns caller
  lifecycle and assertion inputs. The executor never reads expected outputs.
  `replay/adapters` resolves original finite dependency references and delegates
  real delivery state to native owners. It cannot manufacture consumption.

- `value_contract/plan` owns executable rule, index and evidence requirements.
  `policy/capability/coverage` admits supported protocol/role/carrier/codec
  combinations before execution, with explicit unsupported reasons. Stateful
  native effects retain their real native executor rather than a no-op generic
  implementation. `value_contract/json/pointers` indexes concrete field positions
  once per comparison; wildcard selection retains Source array-shape checks and
  original declaration order, before the comparator validates the strict remainder.
  `value_contract/global/field_composition` expands Source selections once while
  combining global and authored fields, preserving duplicate, overlap and
  declaration-order behavior before that comparison.

- `replay/preparation` binds an immutable Source scope and applicable contracts
  into a Case execution plan after native registration. `replay/native_index`
  owns ordered postings and immutable lane membership; HTTP, Redis and MySQL
  candidate adapters retain their protocol keys. Live admission, ordering and
  protocol eligibility remain with native matchers; the shared runtime owns
  finite claim transitions. Deferred loading registers appended
  ranges, and candidate lookup does not enumerate unrelated Cases.
  `replay/candidate_selection` owns bounded hypothesis uniqueness; ambiguity or
  an exhausted search cannot produce a selected candidate. Native hypothesis
  executors retain their own guards and complete attempted-rule evidence.

- `replay/admission/request` owns the generic request execution flow. Native
  `DependencyRequestAdapter` hooks supply observations, protocol selection and
  required barriers; they do not implement independent wait/retry loops.
  `replay/admission` owns finite tickets, actual wire progress, once-only
  commit/failure, cancellation and lost-wakeup-safe notification. Admission and
  delivered-value barriers are distinct. `order` owns physical Target arrival
  indexes independently of response completion. Redis/MySQL/Memcached retain
  native framing, session constraints and response rendering, and use the shared
  execution contracts for ordinary finite dependencies. Explicit repeat or
  coalescing operators retain named native claims and their own proof guards.

- `value_limits` owns the shared 64 MiB value ceiling used by Redis carriers,
  JSON/Protobuf codecs and derived-value rendering; business code owns actual
  payload sizes. Protocol validation and aggregate evidence budgets stay with
  their existing owners.

- `value_contract/time` owns standard temporal recognition, representation,
  relative-clock comparison and elapsed timestamp budgets with a two-second
  clock allowance. `value_contract/json` supplies the independent API starts
  and current comparison clocks; the kernel accepts no delivery-speed flag or
  guessed business generation anchor. `policy/time_defaults`
  owns the project-wide civil offset. Callers supply dependency request or
  response-event clocks through `AnchorClocks`; explicit request and delivery
  provenance remain separate. Protocol adapters retain native value framing.
  Built-in validation never supplies positive coverage for an authored rule.
  `replay/contract_value` renders stored time counterparts only with authenticated
  preceding write/read proofs, including recognized textual times; recognition
  alone still permits comparison without generating delivery translations.

- `replay/mysql/session_setup` recognizes narrow successful nonsemantic driver
  observations. Native registration and Source transaction/read-span proof use
  that same boundary; business SQL, AUTOCOMMIT, errors and status-changing or
  unknown session effects retain their existing finite contracts.

- `replay/redis/pubsub/ingress` owns the finite inverse RPC relationship between
  a Global Socket.IO request notification and its original Case callback.
  `preparation` proves immutable identity, clocks and subscription slots;
  `causal` proves preceding same-session native emits from Source dependency
  requests, and requires both their real consumption and metadata from actual
  Target WebSocket events. `driver` waits for those prerequisites, Case admission
  and an independently observed live SID, then queues the original notification
  without changing Global ownership. `control/native_event` admits bounded
  metadata from the trusted transport driver within the active request epoch;
  `interaction/replay/feedback` carries that observation interface separately
  from protocol parsing and control transport. No expected output enters the
  input executor, and recorded ACK payloads retain their existing references.
  `replay/global/notifications` exposes authenticated Unattributed notification
  slots to these native input proofs without admitting unowned outgoing commands
  or changing Source ownership. Such slots have no subscription-age timer fallback;
  physical record order is retained across separate Source ownership views.
  Ordinary native notification clocks also admit bounded same-namespace client
  events with ACK IDs. `interaction/replay/socketio/native_receipts` correlates
  actual sent inputs and received ACK metadata independently of business
  completion and fast timing; the native clock retains Source windows, original
  subscription ownership and the current request epoch. An input without an ACK
  or an explicit close ends the notification prefix, rather than invalidating
  preceding notifications. That boundary also limits delivery lifetime; later
  actual ACK identities remain admissible without extending the prefix. Native
  plan cardinality is bounded by the original finite notification inventory;
  long recordings retain paged payload references and bounded delivery queues.
  RESP delivery retains wire consumption and Case cancellation checks; the
  adapter and request contracts retain strict callback result comparison.
  `replay/redis/pubsub/namespace_sessions` owns SID-directed emit correspondence:
  it selects only unique namespace identities from original Source protocol
  observations, then binds them to CONNECT receipts from the actual Target
  transport within the current Case request epoch. The input executor receives
  no expected response. Adapter comparison copies may translate only that
  proven room identity; business rooms, payloads, namespaces, process identity
  bijections and finite delivery remain strict. Case transitions and cleanup
  retire the live correspondence.
  `replay/assertion/interaction/client_ack` separately owns original client
  request provenance and exact native reply pairing for fast replay. It pairs
  only contiguous plain ACK runs whose unique namespace/id request identities
  have no direct or transitive completion ordering, with transport/namespace
  boundaries retained. Payload contracts and all business event positions stay
  strict; no expected output enters the input executor.

- `dependency/termination` owns protocol-independent peer observations, monotonic
  termination time and explicit transport FIN/RST control. Recorder connection
  registration marks engine-owned cleanup before socket shutdown. Protocol
  adapters retain framing, session/request correlation and timed response-prefix
  materialization. `replay/exchange` owns shared termination timing and validation.
  Redis's ordered recording writer mirrors peer closes only before authenticated
  recorder cleanup; pending exchanges still retain their incomplete-capture facts.
  Protocol delivery owns claims, consumption and dirty reporting. See
  [dependency termination](dependency-termination.md).
  `replay/mysql/wire_diagnostics` owns opt-in connection-local protocol envelopes
  and request counters. It exposes packet lengths, sequence numbers and leading
  tags separately from transport flush results, without SQL or response values.
  Protocol encoding and delivery remain in their existing owners.

- `interaction/model` owns versioned input programs and independent output
  observations. `policy` validates protocol completion profiles and bounded
  execution budgets; `lifecycle`, `socketio`, `stream` and `observation` own pure
  framing, completion correlation and monotonic case decisions. They do not read
  expected evidence, persist recordings or own dependency cleanup.
  `interaction/artifact` prepares plaintext output artifacts without duplicating
  the raw stream body. `interaction/private` reads historical encrypted input
  and output envelopes; its old writers exist only as compatibility test fixtures.
  New initial and upgrade request headers reuse Recorder's configured header capture.
  `interaction/replay/timing` owns the replay timing choice, monotonic Source-offset
  mapping and metadata feedback interface. `replay/control/input_timing` admits
  active-case timing queries from immutable inputs and finite dependency facts;
  its Source reader never opens expected outputs. Redis adapters project exact
  response/native references and publish successful wire-delivery facts separately
  from matching and RPC completion. Supported native clocks reuse the same mapping;
  unsupported protocol delivery or recording timing retains original offsets.
  Independently proven individual Redis delivery prefixes still gate Auto business inputs
  without requiring compression coverage; ACKs, heartbeat and cancellation keep
  their own native scheduling. Prefixes exclude future Source completions and
  never infer handler completion.
  Native coalescing/retiming retains native ownership; successful native completion
  projects exact covered Source references into the delivery journal for compression.
  `heartbeat` records and validates the input program's causal PING/PONG bindings;
  `interaction/replay/socketio/heartbeat` schedules those responses from actual
  Target PING packets, separately from business completion barriers. Explicit
  peer Close observations retain pending business identities without inventing
  completion or accepting unobserved transport truncation.
  `interaction/websocket_transport` owns bounded raw-frame boundary and real
  peer FIN/RST observations without retaining payloads. Its continuous read tap
  preserves read-ahead and unfinished fragmentation, independently of decoded
  message observation and application completion. Typed client transport-end
  inputs retain their original clocks and unfinished business identities.
  `gateway/http/interaction` owns primary transport forwarding, session admission,
  recording and close orchestration. Its `ordinary` child forwards finite HTTP
  frames independently of case-owned capture, drain and publication.
  `active_case` retains dependency attribution through the fixed post-response
  window or API-origin selected-activity observation and accepted in-flight drain;
  its `observation` child owns race-safe selected request reservations and the
  absolute tail deadline. Its `stream_tail` child owns primary-stream dependency
  request lifetimes, finite observation inventory and publication isolation,
  separately from writer reservations and API-origin selector proofs.
  The registry publishes admission closure to standalone supervision, including
  closure while a live dependency prevents case publication. Supervision stops
  Source before draining those owned requests and their evidence.
  `recorder/api_origin_observation` owns online origin,
  selector and captured-identity matching without changing dependency ownership.
  `policy/async_api` owns ordered Source request/response scenarios and
  terminal-resource syntax, including legacy single-scenario input.
  `recorder/async_api/selection` owns first-matching scenario selection and
  independent early signals; `recorder/async_api` matches complete observed
  SQL, Redis operations or successful HTTP exchanges;
  its `recorded` adapter reads immutable semantic JSONL through the same
  completion and occurrence checks. `redis/key_slots` owns physical key
  positions shared by recording completion and replay identity translation.
  `recorder/connect_failure` records actual failed upstream connects and the
  explicit client reset delivered by Recorder. `replay/connect_failure` owns
  finite case/endpoint matching and faithful timed transport delivery; neither
  owner treats protocol parsing or capture corruption as a dependency failure.
  `replay/network_access` loads the finalized network contract and owns strict
  endpoint admission and DNS-only availability; `replay/dns` retains DNS wire
  parsing and response delivery without inventing reachable DNS-only endpoints.
  `active_case/async_api` retains early completion signals, the common request
  deadline and normal Source-stop/drain behavior. Asynchronous completion keeps
  ordinary dependency ownership and never authorizes process-owned exclusions.
  Its exact cleanup inventory distinguishes post-Source-stop transport cleanup
  from complete business failures. `replay/lifecycle_cleanup` admits only those
  original references; protocol adapters retain captured prefixes and await
  actual Target termination after the controller's stop boundary. HTTP's
  `contracts/prefix` reuses global rendering without creating complete-response
  witnesses; `http/termination` owns flush confirmation and real transport ends.
  `recording_case` wires these case lifecycle operations into application state;
  its `interaction` child owns the lease/publication barrier. `record_service/proxy` owns
  external admission lease scheduling and transparent ingress transport; the
  gateway SDK owns atomic Redis reservation operations. `interaction/replay`
  drives only recorded inputs against fresh Target connections; response assertion
  compares independent output observations.
  `interaction/replay/socketio/transport` retains its reader through normal
  peer-close completion, so flushing a client close cannot release the Case
  while the peer is processing an earlier namespace disconnect. The scheduler
  bounds that close I/O and interrupts it on an actual dependency rejection;
  it does not wait for unused dependency inventory.
  Its `namespace` sibling retains each live namespace CONNECT barrier before
  sending new business events, including when recorded idle offsets are compressed.
  Only the actual Target CONNECT response releases that namespace's barrier;
  replies to actual Target server events and explicit transport cancellation
  remain available during admission.
  `gateway/http/interaction/websocket` applies the same transport-lifetime
  barrier while recording: Source resource calls begun during close remain
  inside the Case until actual Source peer termination. `interaction/finish`
  retains its existing cleanup deadline and marks unfinished cleanup incomplete.
  `gateway/http/interaction/websocket/closing` confirms application close for
  recognized Python ASGI peers through the live upgraded Engine.IO SID's native
  NOOP/disconnected status. After proving that exact SID live before forwarding
  CLOSE, it also accepts its native removal after Python Engine.IO's awaited
  disconnect handler. Initial unknown SIDs, mismatched SIDs, arbitrary HTTP 400
  responses and automatic WS close echoes cannot prove completion. Native
  statuses require complete JSON-string and SID matches.
  `closing/SourceClose` retains the early live-SID proof for Source-initiated
  closure. The transport flushes its native close echo before awaiting application
  disconnect and retains its Case lifetime throughout. Probe failure remains
  failure, and the existing finalizer owns cancellation and the cleanup budget.
  Transport failures remain visible to `finish` even when the primary close was already observed;
  Its `disconnect` child forwards a proven complete-boundary TCP FIN/RST as a
  typed terminal input and retains exact native application confirmation. Raw
  frame truncation retains failed evidence through the existing recovery path;
  no path synthesizes a client CLOSE input. Its `upstream` child retains Hyper
  preread bytes and the actual upgraded TCP control through HTTP/TLS adapters.
  `failure` classifies transport errors without formatting private
  frames or I/O context. `interaction/recovery` permits Source reuse only after
  this protocol proof, complete dependency/writer drain and failure publication;
  `active_case/recovery` owns the shared closed-attribution check. Protocol errors,
  unconfirmed teardown, lease loss and persistence failure still stop Source.
  WARN diagnostics expose only case identity, transport phase, close code,
  bounded error categories and typed confirmation outcomes, never private probe
  URLs, SIDs or body text.
  Replay control retains case identity and asynchronous dependency delivery
  ownership through the existing case-end lifecycle. Its `control/dependency_tail` child resolves finite immutable
  exchange references, adapts legacy API-origin observation metadata, and waits
  for real Target consumption within the absolute case budget. Protocol modules
  retain their own exchange identities and termination validation; native
  `finite_inventory` adapters expose delivery state without consuming exchanges.
  Kafka inventories retain each produce/delivery effect's semantic sequence in
  addition to its physical request sequence. Async metadata version 2 separates
  capture completeness from business completion; incomplete Source business
  observations remain diagnostic and cannot pass formal verification.
  HTTP's `tail` adapter identifies explicitly shared initialization without
  changing its physical Source identity. Tail drain permits only unstarted
  initialization to remain unused; the captured scenario's HTTP completion
  selectors and all started delivery/termination obligations stay required.
  `replay/startup` owns the first independently observed primary-input boundary.
  It freezes startup business debt and closes only unclaimed initialization slots
  with a typed admission state; it never consumes them or changes their owner.
  Protocol control and explicitly reusable snapshots remain separate facts,
  accepted resource I/O may finish, and Process inventory remains independent.
  An implicit low-level session with startup business inventory reports its phase
  as unverified until a real boundary is observed. Frozen Case views retain
  their complete mandatory inventory; process selectors cannot waive Case debt.
  Independent API aggregates omit startup inventories and do not make run-level
  startup debt a Case failure. The on-demand Source process evidence query retains
  the diagnostic entry point. Actual API response and dependency
  checks remain strict; the final batch receipt still requires startup closure.
  `replay/http/ingress` owns genuine parsed-header admission before request-body
  collection. A bounded metadata ledger freezes observation identity, observed
  Case and startup phase; a RAII atomic guard retains actual unfinished body I/O
  without claiming Source inventory. Native complete-body matching reuses that
  identity and hands off to response ownership under the Case-release lock.
  A static endpoint/method/path index permits a run-only guard only for a unique
  Process head without a competing Case or Startup head. All other admissions
  conservatively retain their observed Case. Header admission before the primary
  boundary permits only that real request to finish selecting Startup inventory;
  failed previews cannot discharge frozen startup debt. Cancellation and body
  errors release the guard and retain dirty facts. Cleanup observes guard release
  through notifications without introducing an attribution sleep.
  Its synchronous registry admits headers before they can await Replay state.
  The same small epoch lock fences the final empty-I/O observation and startup
  boundary, so mutex contention cannot move an already observed request into a
  later Case or erase its startup admission token. A proven Process head moves
  its guard by incrementing the run counter before releasing the Case counter.
  `replay/http/stream_delivery/full_delivery` retains ordinary response claims
  through the final body frame and the existing HTTP/TLS writer flush signal.
  Empty responses retain their header-flush obligation; dropped bodies and
  transports that close before flush fail the original claim. Protocol matching
  selects bytes without manufacturing delivery or committing time-copy facts.
  Explicit HTTP sharing retains its original Case owner and separate permission;
  membership in a shared request pool is not restart initialization ownership.
  `control/dependency_tail/progress` owns the Replay-only no-progress clock and
  bounded pending-reference observations. It excludes real resource I/O and
  unrelated process activity, and records only the stalling Case as incomplete.
  Its diagnostic leads with unconsumed recorded dependencies and Target-call
  guidance, retaining idle timing as the stop condition rather than attribution.
  `rewrite/evidence/execution` shares that distinction with issue summaries and
  evidence guidance while preserving actual Target-request rejection diagnoses.
  `control/server` owns bounded control connections; mutations stay serialized
  while read-only observations remain available during dependency waits.
  `control/case_execution` exposes actual dependency rejection separately from unused inventory;
  `e2e_run/request_feedback` interrupts one primary request across HTTP, streams and Motan.
  `e2e_run/case_sequence` owns chronological input admission on that same Target.
  `e2e_run/batch_evidence` binds final verification to one latest complete-round
  execution, its immutable Source manifest, whole input inventory, current owner
  snapshot and actual session receipt. It never joins focused method attempts.
  `e2e_run/workflow_evidence` independently authenticates one final session for
  every current workflow method and its complete Case inventory. Its validation
  child checks original response, dependency and Target-stop evidence without
  certifying startup or process consumption. `rewrite/dependency_review/workflow_verification`
  owns that scope's receipt, freshness and API obligations; WholeSource receipts
  and run-owned obligations retain their stricter, separate verification.
  Execution freezes a fresh Target/runtime-policy identity before startup and
  checks it again after execution; the cold evidence reader revalidates that
  identity, Source image revision and engine build before returning receipt refs.
  A failed primary or dirty dependency result belongs to its Case. Native
  rejection closes the affected dependency connection; the runner closes the
  primary transport and drains accepted I/O before admitting another input.
  The per-API failure counter, rather than a native-session failure, limits how
  many failed Cases execute. Unused Source inventory remains unused and dirty.
  `control/dependency_tail/metadata/interaction_inventory` derives finite waits
  from a clean original Socket.IO/WebSocket completion and its Case dependencies
  when explicit tail observations are absent. It streams original metadata,
  retains the Source elapsed-time budget and post-input idle allowance, and never
  supplies response frames to Target. A stalled native interaction records its
  no-progress failure and drains accepted I/O before the locked ownership
  release. Dirty evidence alone does not retain global Case ownership. An actual
  I/O cleanup failure retains ownership; recorded dependency errors remain
  ordinary replies.
  `metadata/references` owns the shared semantic exchange identities.
  Central observations with `semantic_required: false` do not create finite tail
  obligations. Redis protocol controls retain native Target session context,
  without creating business slots or ordinary-pool socket bindings; recorded
  session failures and actual stateful operations keep their native contracts.
  `dependency/execution` owns the protocol-independent rejection signal and typed error.
  `e2e_run/execution_failure` retains the incomplete execution cause and independent
  primary status observations for public diagnosis and evidence queries.
  `rewrite/evidence/witness` owns bounded, assignment-bound access to authenticated
  dependency witness values and recorded input header names. It reuses native
  carrier extraction without applying rules or changing match outcomes.
  Its MySQL selector reads one authenticated materialized SQL cell; the pure
  `replay/mysql/contracts/value_view` adapter reuses bounded native parameter
  decoding and physical field resolution. It does not pair statements or
  authorize formats, and preserves exact decimal text and native NULL/bytes.
  `rewrite/evidence/redis_argument` owns bounded native argument selection for
  unmatched independent Redis observations, bound to the current assignment,
  finalized session and exact request fingerprint without inventing a Source pair.
  Selected independent observation clocks stay authenticated and bounded with
  their IDs; they describe actual admission, not inferred business task origin.
  `rewrite/evidence/redis_stream_progress` projects bounded Case-local APPEND
  admission cursors and original Source fragments from retained audits. It owns
  omission reporting, exposes no payload and does not infer delivery, pair a
  rejected request or change protocol matching.
  `control/case_cleanup` owns failure-phase deadlines and the shared actual-I/O
  barrier. Its final empty-I/O observation stays locked through Case ownership
  release, preventing a new delivery from entering between the check and release.
  Its `pending` child assembles bounded timeout evidence from protocol-owned
  delivery references and observation claims while holding that same lock.
  A failed primary status ends normal async business waiting while
  retaining unused/dirty evidence; protocol owners expose delivery state, and
  runner response assertions retain the primary failure independently of cleanup.
  Normal interaction closure keeps Source and Target running;
  process shutdown remains with the ordinary recording and run supervisors.
  `e2e_run/evidence/interaction` owns on-demand authenticated SSE response
  diagnostics, with bounded payload previews and raw JSON differences. It does
  not persist plaintext, apply value rules or change assertion outcomes.

- `policy/global_json` owns the carrier-independent `json.fields` format map,
  deterministic Source-only format selection and compiled content identity.
  `policy/mysql_global` owns physical scalar table/column format selectors.
  `value_contract/global` composes these logical formats with strict remainder
  comparison and derives delivery copies; it does not select APIs or resources.
  MySQL `contracts/automatic` infers native temporal types from immutable wire
  metadata and projects SQL/result value positions. Protocol adapters retain
  framing, pairing, transactions and finite consumption. Identity correspondence
  is internal, case-local and keyed by complete typed values, independently of
  authored paths and format lists.
  Global JWT formats verify signatures and claims using immutable key snapshots
  loaded before comparison, then stage complete-token correspondence.
  `request_rules/derived` and
  `replay/policy/request_contract/derived_inputs` independently reconstruct actual
  native input re-signing at its precise send clock using frozen startup keys.
  Private `replay/control/derived_input` admission anchors complete delivered
  token values before HTTP exposure. The global comparator retains pairing and
  staged identity decisions; protocol adapters retain wire delivery.
- `policy/schema` and `policy/declarations` own the strict `traffic-policy/v3`
  authored document. `policy/global_json` owns the single global field-format
  map and its immutable Source-driven format selection; `policy/mysql_global`
  owns physical scalar-column patterns; `policy/redis_global` owns scalar-key patterns.
  `value_contract/redis_scalar` preserves Source scalar wire encoding and shares
  the global comparator without a second time/identity kernel. `policy/authoring` resolves endpoint aliases,
  plan-local proof inheritance and compact runtime contracts. Its Redis authoring
  namespace groups stateful effects under `redis.rules`; its `redis_keys` child
  lowers key-local append, read, expiry and sharing permissions into that same
  native runtime list and reverses only exact generated forms when rendering.
  No second rule evaluator or fingerprint is introduced. Resource field graphs, per-API value declarations and
  field-reference expansion are retired.
  `policy/proof` owns shared proof byte limits and bounded Source references;
  authoring resolves plan-local inheritance and common document revision context.
  `rewrite/unified_rule/source_proof` freezes Source explanations outside the
  published runtime policy, checks their snapshot hash and associates each
  explanation with the declared runtime permission before application.
  `policy/compiler` owns typed capability validation, field ownership and
  semantic effect fingerprints, prepared endpoint indices, table matchers and codec
  plans; these modules neither read evidence nor change runtime state.
  `value_contract/hypothesis` owns bounded pure hypotheses over typed values;
  JSON, physical SQL values and Redis arguments/key components reuse that kernel.
  `request_contract/mysql_hypothesis` owns immutable Source SQL projection caching;
  `redis_hypothesis` owns native key/value slot extraction and strict remainder.
  Native HTTP/MySQL/Redis matchers retain protocol eligibility and Source
  selection. Shared native indexes, candidate selection and finite admission
  own their common ordering, uniqueness and claim mechanisms.
  `request_contract/hypotheses` retains every attempted rule independently of
  selection; staged identity decisions commit only after native admission.
  `policy_evidence/hypotheses` owns the authenticated append journal, bounded
  group commits and durable acknowledgement before delivery. One checkpoint per
  genuine Target retains its encrypted key envelope and protected payload locators;
  journal acknowledgement follows payload and directory synchronization, without
  copying the payload or complete observation graph per candidate. Its publication
  child verifies and copies only the acknowledged prefix. Rejected and selected
  hypotheses remain available on every terminal outcome; used unproven rules
  keep formal verification dirty. Stream delivery owns its explicit fast versus
  recorded schedule, separately from immutable timing evidence.
  `policy/condition` owns Source self/sibling predicate validation, selection,
  Target discriminator equality and conservative disjointness shared by value
  fields and native Redis identity captures. `value_contract/time` owns exact timestamp arithmetic and trusted-clock
  relations. Its `calendar` child preserves civil-day distances using independent
  local request dates and an explicit fixed offset; it never treats a date as a
  midnight instant or rewrites counters. `value_contract/json` composes field contracts with strict remainder
  comparison and bounded whole-element multiset pairing; `value_contract/delivery`
  writes only explicitly authorized timestamps in derived copies. These pure
  owners never claim protocol exchanges or mutate recorded evidence.
  `value_contract/global` adapts the one global field plan to decoded JSON or
  known PB logical values, chooses numeric epoch units from independent Source
  clocks, and keeps unknown encodings or ambiguous numeric units exact.
  Protocol carriers own extraction, same-position pairing and actual delivery.
  `value_contract/time_copies/delivered` projects delivered Case-local typed
  timestamp fingerprints and paired delivery clocks into primary SSE checks
  and later MySQL global JSON requests. The MySQL copy adapter checks both
  deliveries precede the independent SQL request; physical-column contracts
  retain their own position-bound provenance.
  `replay/http/contracts/time_copies` stages HTTP JSON/SSE time provenance and
  publishes it only on successful delivery; MySQL/Redis reuse their read hooks.
  The private response control snapshot carries no payloads. The SSE adapter
  checks delivery-before-frame causality against the independent stream starts;
  it cannot choose an arbitrary dependency clock or borrow a future frame's
  elapsed timestamp budget.
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
  `policy_evidence/source` owns authenticated original-record references and
  delegates envelope reconstruction to native adapters. Its `storage` sibling
  owns bounded traffic chunks, sealed segments and portable segment copying.
  Its `payload` sibling stores UTF-8/Base64 bytes and configured HTTP header
  fragments, retaining byte-exact reconstruction and historical encrypted readers.
  `policy_evidence/authentication` owns the separate HMAC binding for plaintext
  request candidates, reusing the encryption owner's managed engine key resolution.
  `request_headers/evidence` selects original HTTP header byte ranges from a
  project header policy; business bodies and response headers are not selected.
  Version-3 coverage groups authenticate the exact visited candidate membership;
  the borrowed witness index selects original identities before proof expansion.
  `policy_evidence/catalog` publishes the sealed directory separately from the
  version-4 manifest and verifies its authenticated reference before expansion.
  `policy_evidence/limits` keeps whole-session observation, candidate membership
  and private directory capacity aligned across capture and publication.
  `replay/assertion/native/header_jwt` owns unique header carrier selection;
  `assertion/jwt/url` owns strict URL remainder and signed nonce echoes. Body and
  header adapters reuse the same private key snapshots and JWT verifier. Header
  ownership never implies a JSON body codec or a response-status exemption.

- `mysql/sql/field_bindings` owns conservative physical database/table/column
  resolution from real statement syntax and its bounded, literal-free analysis
  cache. Protocol request/response adapters map those origins to live values,
  reuse per-statement analysis and preserve strict unselected SQL and finite
  consumption. The cache never stores live values, clocks or matching decisions.
  MySQL recording preserves wire schema and original column origins; response
  fallback uses direct projections only when old metadata is sufficient.
- `rewrite/unified_rule/declarations` owns additive authored-graph merges and
  proof-preserving amendments; discovery supplies bounded physical-field
  suggestions without inferring codecs, table families or Source intent.

- `replay/report/sql_summary` owns bounded original SQL excerpts for diagnostics,
  including outer SELECT bodies when long projections hide the predicates.
  It uses the MySQL lexer, retains explicit truncation and never grants SQL
  matching or ownership permission. MySQL evidence retains complete result-row
  counts independently of lazy result payload storage.
- `replay/report/global_evidence` owns durable, source-bound shared Global report
  inventories and lazy detail projection. Its artifact child owns atomic private
  storage and portable publication; protocol children supply immutable report rows
  and sparse visibility changes using their existing consumption semantics.
  Protocol-specific visibility semantics belong to the regular inventory identity:
  new MySQL projections carry their report revision, while omitted revisions
  preserve historical report keys and unrelated protocol caches.
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
- `value_codec` prepares immutable typed codec plans and bounded schema reuse;
  its Scalar/JSON/Protobuf providers statically dispatch decoding, comparison
  views and authorized encoding. Decoded documents retain original bytes and
  native Protobuf presence/unknown fields independently of logical JSON views.
  `value_contract/encoded/prepared` caches only bounded immutable overlapping
  schema plans, never live clocks, Target values or comparison decisions;
  decoded Source values may be shared within a comparison. The pure value kernel
  still evaluates every applicable permission and supplied clock independently.
  `replay/policy/request_contract/mysql_selection` owns immutable SQL selector
  preparation and bounded raw-token reuse; bound parameters and live applicability
  never belong in that cache. Ordinary value selectors and native SQL effects use
  the same `sql_template/table` admission and physical-table binding. Value and
  mixed field ownership checks retain the complete declared table range.
  `replay/mysql/contracts/preflight_identity` owns derived SQL witness copies for
  composed request identity/value planning. Global MySQL scalar declarations and
  global JSON formats share the case identity store for result delivery; no
  separate identity read-back renderer, SELECT template or response-field claim
  is authored. Protocol response delivery retains its immutable Source copy and
  finite consumption. `dynamic_values/audit` restores only accepted
  Case-local binding fingerprints with native capture/reference guards and Source
  causality. Immutable later captures establish whether a statement references a
  binding; only captures completed before that request may restore it. Unrelated
  statements borrow no identity permission. Runtime SQL normalization remains in `dynamic_values/mysql`.
  Unified preflight retains original evidence and requires genuine Replay for
  these stateful relationships. Pure SQL value comparison retains the remainder.
  SQL value discovery reuses the statement-relatedness check before projecting
  a Target slot; an unrelated search edge retains Source-only guidance instead
  of aborting discovery or creating an independent Target validation.
  `mysql/sql/lexical_cache` shares only bounded immutable lexer output, including
  invalid-input results. `replay/mysql/candidates` indexes immutable Case/resource
  scopes and compatible command families in original inventory order; live
  availability, rule decisions, projection precedence and consumption remain in
  the MySQL matcher.

- `config/api_trigger` owns API-origin process-rule schema, SQL identity slots and bounded key-template
  validation; `api_trigger` owns immutable origin evidence and disposable index
  persistence. Its `same_resource` child owns report-only read eligibility for
  requests referencing an origin identity, separate from live ordering and
  transaction proof. Its `plan` child owns the shared stale-safe policy transaction;
  `mysql_plan` adapts bounded SELECT/UPDATE selectors. `mysql_transaction` owns
  complete wire-sequence provenance; its `tail` child attributes only a direct
  successful UPDATE-to-COMMIT handoff when the prefix is missing. `redis_script` owns adjacent script-probe
  association. Optional MySQL record locations and SQL prefilter facts belong to `dependency_index/mysql`
  and are retained during Recorder summary traversal. `dependency_index/mysql_transactions`
  owns rule-independent, Source-bound intervals across Global and Case records.
  `api_trigger/cache` owns versioned policy ownership and portable prewarm import;
  Global evidence has no fabricated primary request. MySQL literal
  INSERT parsing belongs to `mysql/sql/insert`. Source selector kernels support
  independent attribution proof; they never change a Replay report or consumption.
  Current-format sessions freeze ownership in `replay/attribution`; legacy API-origin
  discovery and transaction promotion cannot override central scope membership.
  `replay/mysql/transaction_scope` retains physical Target connection and transaction
  boundaries without moving later Case requests into another owner's inventory.

- `mysql/savepoint` owns bounded savepoint command parsing and Source name
  lifetimes. `replay/mysql/savepoints` owns connection-local Source/Target name
  bindings, with side-effect-free candidate previews and post-delivery commits.
  `transaction_equivalence/source` retains complete Source interval proof;
  `transaction_equivalence` retains the outer transaction delivery witness and
  its `member_comparison` child captures bounded Source-reference order evidence
  at an actual failed Target end, including the first difference beyond a
  truncated prefix. It neither changes matching nor reconstructs historical
  Target order from an unordered consumption set. The transaction owner
  includes savepoint controls in its required interval. Neither name aliasing nor
  inner rollback/release supplies an outer commit or consumes another socket's
  control. `transaction_ownership` reuses the Source name lifetime proof for
  Global-started intervals and versions its disposable proof cache separately.

- `mysql/isolation` owns closed isolation-setting/probe syntax without expanding
  the generic session-setup whitelist. `replay/mysql/isolation/source` proves
  original baseline probes and complete override/transaction/restoration scopes
  during preparation. Its parent binds NEXT settings to actual Target sockets,
  observes successful deliveries through the existing transaction owner and
  grants only proven Source restoration omission. Its Source proof classifies
  complete read-only scopes; its live owner requires every original read and a
  successful real Target end before allowing an already optional read-only
  Source end to differ between COMMIT and ROLLBACK. Candidate fencing stays in
  the MySQL matcher; values, business transaction parity, wire completion and
  original consumption retain their existing owners.

- `engine_binary` resolves companion executables and Linux reexec paths for a
  replaced running engine. Replay, coordinator workers and local interception
  share that resolver; process lifecycle remains with each caller.

- `replay/redis/append` owns explicitly authorized Case-local APPEND byte
  reservations, derived lengths, delivery completion and fingerprint-only range
  audits. Its `trace` child validates complete immutable Source byte order,
  resets and observation fences; `source` reuses that preparation for native
  rule preflight. A preexisting prefix needs only a Source-derived length base;
  its contents and creator remain outside this Case's increment proof.
  Ordinary Redis adapters retain all non-APPEND matching and
  finite consumption. Partial byte delivery is separate from active transport.
  Stream key selection reuses the request-contract owner's projection of
  already accepted complete identities; stream bytes remain with the APPEND owner.
  `redis/observations/absence` proves absent-state read lifetimes between owned
  deletion boundaries and concurrent accesses that preserve that proven state,
  retaining per-connection order and initial-reset causal fences. The existing observation runtime owns bounded repeats,
  delivery and audit. Native policy compilation and normal plan/apply retain
  permission ownership. `redis/read_commutation` owns explicit finite nil-observation ordering
  permission; its `source` child rejects mutations and validates absent-key
  participation in causally later multi-key cleanup before installing any
  permission. Cleanup itself retains ordinary finite command ownership.
  `redis/key_access` supplies conservative
  key-access exclusion to both Source proofs, and `redis/native_source` loads
  their complete scoped Source inventories. `redis/case_scope` identifies other
  ordinary Case records consistently for preparation and later inventory
  additions: they cannot establish or invalidate this Case's proof. Global,
  snapshot and explicitly shared ownership retain their separate boundary.
  `redis/connection_scope` partitions ordinary stateful lanes by Case, while
  Global and explicit session setup retain connection-wide constraints.
  Native command matching and
  delivery retain connection eligibility, claims and finite consumption.
  `redis/observations` owns explicit SET/DEL state observations and positive TTL
  refresh equivalence. Its `source` child validates complete, isolated key
  lifetimes before installing observation permissions; an initial successful
  EXPIRE may establish existing-key context without a Case-local creator.
  Request contracts retain write-to-read identity rendering. Preparation and
  observation slots exclude other ordinary Cases' reads and writes; mutations
  inside this Case and Global/shared inventory retain their ownership fences.
  Mutation matching, APPEND bytes and transport completion remain with their
  existing owners.
  `redis/observations/closed_expiry` proves unchanged scalar lifetimes whose
  matched TTL-bearing SET makes refreshes redundant until a successful finite
  deletion. It owns monotonic lifetime bounds, delivery-complete coverage and
  explicit closure audits; it grants no content or lifecycle mutation omission.
  Its `refresh` child admits extra exact-TTL refreshes from that same proven
  closed scalar lifetime when Source had none, using the delivered Target SET
  key and retaining a dirty Case until finite deletion and delivery settle.
  `redis/activity` owns independently declared JSON metadata refresh lifetimes.
  Its `source` child proves complete isolated read/SET histories and TTL bounds;
  `value` reuses global timestamp formats and the shared time kernel while
  retaining exact unselected fields. `runtime` renders current Target state and
  `lifecycle` retains finite creation/deletion, actual delivery and bounded audits.
  It does not grant APPEND or content/list consumption permission.

- `recording_api/methods` owns the optional per-route method metadata codec and
  lookup. Recorder run finalization projects its existing observed API set into
  the recording manifest once; coordinator execution summaries only read it.

- `verification_progress/logical_run` merges actual recording coverage and strictly
  newer focused attempts. Partial prepared inventories retain unfinished coverage.
  One attempt cannot be rewritten into a later passing contribution.

- `rewrite/engine_retry` owns per-method retry eligibility and durable consumption
  after an engine Git revision change, including an inventory-only final-route
  fallback that treats Complete/RevalidationPending/Skipped siblings as
  nonblocking without changing their verification status.
  A confirmed current ready/integrated delivery retains its integration and
  verification path ahead of this optional retry; retry eligibility and durable
  reservation cannot hide that delivery when a sibling becomes skipped.
  A known changed engine can also refresh an interrupted partial run whose
  older issue still names a response mismatch; completed failures and unrelated
  worker slices retain their existing admissions.
  `rewrite/replay_admission` combines exact
  method permits without releasing unaccepted route siblings; `rule_replay` owns
  rule-application requests. `rewrite/verification` owns reservation, Replay and
  result-transition cleanup. E2E state/result publication preserves the actual
  executor revision; `build_info` exposes its build-time constant without status I/O.

- `rewrite/repository_analysis` owns incremental Source-backed module grouping,
  batch/version validation and workflow snapshots; its `catalog` child owns the
  ignored project catalog and atomic publication. Route identity and pattern
  recognition remain with their existing recording/case-pattern owners.
  `rewrite/implementer` owns fixed slot identity, stable round-robin group
  assignment, queued API leases and explicit runtime feedback. Its `delivery`
  child freezes accepted commits/reports separately from reusable checkouts;
  review and integration retain their existing receipt/admission owners.
  `rewrite/group_replay` owns frozen group membership, exact method admissions,
  partial round summaries and continuation after comparison failures.
  `rewrite/verification` executes each route and publishes its transitions;
  `rewrite/next` continues an unfinished group through the normal native gates.
  Group analysis never queries runtime task activity or performs Replay.

- `rewrite/rule_plans` owns global pending-plan admission and busy Apply reports;
  its `events` child owns independent atomic plan publication and merging into
  coordinator snapshots. Validation stays with `rewrite/unified_rule`; policy
  application keeps its existing coordinator transaction. Replay reservation
  shares only the short publication lock, never a plan's expensive preflight.
  `e2e_run/evidence_admission` permits completed focused evidence for unrelated
  APIs while preserving active route/session isolation. See
  [concurrent rule planning](concurrent-rule-planning.md).

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
  `e2e_run/case_selection` validates selected/skipped input partitions.
  `e2e_run/batch_evidence` validates one current full session against the sealed
  manifest, engine, Target execution identity and frozen attribution. It never
  stitches focused snapshots or treats attribution receipts as actual delivery.
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
  its `scoped_read` child concatenates only selected physical records, validates
  the selected digest and retains original line numbers. Prefetch budgets use
  selected bytes, never the size of a shared central ledger. `RecordReader` and
  protected `SourceRecord` witnesses freeze the physical file and view stamp at
  preparation; per-record reads cannot reopen a whole scope after cache eviction.
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
  `recorder/redis/rpc` retains RPC attribution across connections without
  extending a completed PUBLISH's in-flight lifetime. A callback reacquires
  its original Case only while admission remains open; later callbacks retain
  exact publisher references in Global evidence. `recorder/redis/events`
  projects connection/exchange records. `replay/redis/pubsub` owns finite push
  evidence, subscription routing and delivery; its `adapter` child owns
  Socket.IO Redis-adapter identity correlation. Its `echo` child associates exact
  finite Source PUBLISH payloads with recorded self-echo notifications and delivers
  admitted Target payloads to confirmed subscribers without subscription-age delays.
  Notification pages retain payload digests; `echo` prepares sparse lookups for
  loaded adapter publishers before Replay readiness and shares them across Cases.
  Command delivery only reads prepared lookups; inventory construction stays
  outside Target connection handling. The `native_clock` child projects original
  external ordinary adapter slots onto unique passive native request windows;
  its `source` child reads original input namespaces and lifecycle/time metadata,
  using the production authenticated request reader for protected INPUT,
  `preparation` checks the complete run including unselected windows, and
  `driver` requires actual namespace admission and the current request epoch.
  Namespace-only notification metadata fences obsolete subscription-age timers
  without exposing payloads or changing ordinary non-native notifications.
  Ambiguous clocks/windows and unproven dynamic socket exclusions remain unused.
  The `delivery` child retains Case/epoch ownership through queued TCP writes
  and reports abandoned or failed Case inputs through the shared I/O barrier.
  The `subscription_evidence` child
  resolves exact recording-level anchors and canonical single-use aliases.
  The adapter retains subscription anchors required by linked RPC callbacks;
  command matching applies their preference within the existing ownership scope
  without bypassing source-lane order, session eligibility or connection claims.
  Payload semantics remain with
  the application. Source acquisition and Replay do not consume HTTP oracles.
  The RPC adapter supplies protocol-identity comparison copies to request policy;
  it still owns callback bindings and commits them only on request admission.
  `value_contract/url_query` owns bounded unique query selection, UTC date-segment
  validation and strict URL remainders; `request_contract/url` resolves selected
  values, timestamp references, request clocks and random shapes. Neither owns lanes,
  subscriptions, signatures or recorded callback results.
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
  evidence/plan/apply/fresh-Replay transaction. Its `read_back` child owns
  explicit same-key Redis write-to-read scalar bindings and derived delivery
  witnesses. Its `state` child keeps bounded Case-local observations with
  immutable Source causality; its `wire` child owns bounded RESP copies and
  selected JSON scalar decoding. It does not simulate Redis or change Target
  cache behavior. Redis adapters retain matching, delivery and consumption.
  Replay control supplies an
  independent inbound request anchor; protocol arguments cannot choose it.
  Its `script` child validates explicit Lua digests and bounded KEYS/ARGV
  envelopes without evaluating Lua. Redis compares dynamic-identity copies
  before disjoint request-time contracts; overlapping field ownership is rejected.
  Its `time` child adapts request-specific source format and calendar constraints
  to `value_contract/time`. Explicit clock groups retain a strict shared default;
  request sequence state carries group observations across commands.
  `redis/matching/request` composes global JSON identity and time decisions
  and commits them only after all request checks pass. HTTP JSON comparison uses the common
  global value kernel with dependency-local clocks; protected request witnesses
  retain independently observed Target bytes before candidate normalization.
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
  `evidence_admission` distinguishes an unfinished foreign execution from a
  malformed complete execution; resource preflight freezes the former's state
  while retaining complete Source proof and a fresh-Replay obligation.
  `e2e_run/replay_publication` stages the original Replay report and dependency
  sidecar into that same snapshot and retargets aggregate report references.
  `replay/report/aggregate/runner` validates runner-selected report locations,
  session identity and complete shared-session coverage while preserving the
  public recording report discovery boundary. `e2e_run/final_evidence` selects
  the prepared recording witnesses for every case in that session before
  deriving method evidence. Original reports, Case outcomes and errors remain
  immutable. `rewrite/dependency_review` owns independently proved attribution,
  conditional API receipts and explicit owner verification debt. Its `analysis`
  child selects concrete ownerless/disputed Source work and gates formal Replay
  until supported owner rules resolve it. Known-owned batch changes need no
  analyst; `investigations/resolution` publishes the existing API implementer's
  current-attempt diagnosis of its owned missing traffic.
  `dependency_review/source/lookup` streams sealed scope locators and reads only
  the requested Source identity's authenticated central rows. Its `scope` child
  verifies locator hashes and recording boundaries while retaining only matching
  UUID locations. Incomplete locator partitions retain the full metadata fallback.
  Lookup shares physical-effect folding with the full Source proof loader;
  diagnostic lookup never certifies attribution.
  `e2e_run/diagnostic_report` resolves published reports by exact session, either
  an archived actual batch or the current finalized focused API attempt. It
  retains Source, attempt, inventory and publication guards; malformed archives
  never fall back to another report. `dependency_review/target_query` owns
  bounded authenticated independent Target request reads from those reports,
  without granting ownership, matching or formal rule proof.
  `replay/attribution/views` publishes physical scope membership from frozen
  ownership decisions. Unchanged scopes retain their immutable original paths
  and native index caches; moved members rebuild both affected scopes without
  changing original capture bytes or the attribution snapshot identity.
  `decisions` stores immutable, shared proof templates with complete finite UUID
  membership and ordered history; `decisions/serde` reads legacy occurrence
  maps/arrays and publishes compact groups. Status validates proof groups without
  expanding per-occurrence DTOs; the Replay overlay owns that explicit projection.
  `case_defaults` restores ordinary Case admission for historical unowned
  notification inputs from authenticated capture clocks and observed Case identity.
  It preserves process-selector priority and original bytes, independently of
  authored proofs and consumption. Analysis, context and frozen Replay scope use
  this same default; current proofs can explicitly supersede it.
  `rewrite/unified_rule/attribution` admits Source-only ownership/lifecycle plans
  before Replay, without inventing a Target attempt. Its execution identity and
  preflight stay distinct from actual API and batch witnesses; value/sharing
  permissions retain their execution evidence requirements. `rewrite/fingerprint`
  separates executed behavior identity from pure classification changes.
  `rewrite/plan_recovery` retires a pending rule with unavailable Replay evidence
  and requests fresh verification while returning its selector and source proof.
- `replay/assertion/time` adapts response time configuration and diagnostics to
  the shared `value_contract/time` formats, fixed windows and precision rules.
  `policy/http_global` owns the one global HTTP header format map;
  `value_contract/http_headers` adapts case-insensitive names and ordered
  occurrences into the shared scalar kernel. Request matching stages its
  identity proposals with body/native proposals before one commit.
  `replay/http/request_headers` retains general audit evidence, protected-value
  handling and unselected-header modes. Its time-reference child resolves
  independent request starts; its fingerprint child identifies immutable inputs.
  Ordinary SDK headers retain strict presence and value comparison. Global
  header formats validate values without granting header omission permissions.
  The unified rule transaction owns global header authoring and complete Source
  coverage; protocol adapters retain framing, signature and finite behavior.
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
  retaining HTTP rules; `coordination` owns optional Redis discovery/leases and
  best-effort address refresh independently of Source and request supervision;
  `api_policy` loads and validates the gateway's startup JSON using SDK route
  validation, separately from Recorder capture configuration. `coordination`
  publishes that policy (defaulting to all paths) and resets counts once after readiness and
  before opening admission; address heartbeats never repeat these writes.
  `proxy` owns direct or reservation-aware request forwarding and completion;
  `source` owns fixed-identity process startup, trust, isolation and cleanup.
  Its `shutdown` child owns the standalone normal-stop 60-second case wait and
  pre-termination diagnostics, separately from failure-driven Source isolation.
  `active_case/shutdown` closes fresh admission without cancelling admitted
  activity, freezes the running-Case association at the first shutdown boundary,
  and installs timeout failures before publication commits. Recorder ledger
  persistence projects associated post-Case requests into the separate sealed
  shutdown scope; unassociated shutdown requests retain attribution analysis;
  `active_case/publication` owns the shared primary case commit barrier.
  `recorder/shutdown` persists run-level shutdown decisions and retains the
  failure cause for unfinished staging cases; ordinary finalization owns moves.
  Global admission closure wakes supervision even before case publication;
  confirmed Source exit permits engine-owned connection cleanup before the
  remaining evidence is drained. HTTP timeout recovery keeps request ownership
  through its bounded recovery period and supervised Source shutdown.
  Reservation and address lease primitives stay in the gateway SDK; startup
  policy publication uses Redis SET/DEL through the existing client.
  CLI bootstrap initializes encryption
  before starting Tokio threads. There is one public Source recording command.
  Its `kubernetes` child owns recording-startup Service discovery, ready barriers
  and supervised port-forward shutdown. `discovery` interprets bounded Service
  metadata; `process` owns scoped kubectl process groups and bounded pipe reads.
  `diagnostics` reduces forwarding stderr to bounded static categories and emits
  process-exit context without retaining credential-bearing child output.
  `supervision` publishes one child's readiness and propagates every unexpected
  exit without restarting the forward. Healthy upstreams remain available for
  the existing normal case drain before Source and the forwards stop.
  `config/upstream_routes` owns only the strict route/cluster configuration.
  `recording_upstream` owns immutable recording-only dial bindings and selects
  the dedicated HTTP client for declared routes. `http/client` owns connection
  pooling: forwarded HTTP retains active responses but never reuses an idle
  socket, while ordinary HTTP keeps its existing pool. DNS and native gateways
  preserve original host/port identity and protocol capture. Replay does not
  load tunnel bindings or start kubectl.
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
  Its `diagnosis` child retains bounded error kinds and request-relative clocks
  across raw transport and HTTP IO, without retaining error text or payloads.
  TLS adapters observe raw socket failures before TLS can translate them; only
  HTTP-level flush certifies response-prefix delivery. `active_case/stream_tail`
  proves closed attribution, quiet business IO and drained writers for local
  failure release. `gateway/http/interaction/recovery` admits only diagnosed
  HTTP capture failures after a clean primary close; publication retains final
  lease-loss ordering, and the supervisor retains all global stop decisions.
  Recorder invalidations carry a conservative typed recovery intent separately
  from explanatory JSON; diagnostic presentation never authorizes continuation.
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
- `replay/redis/snapshot_seed` owns marked Global seed admission against current
  process-owned request selectors, including historical revision-bound names.
  `snapshot_overlay` reuses that name compatibility with complete immutable
  coverage and response-consistency validation; recorded provenance is unchanged.
- `replay/redis/matching` owns command selection and source-lane order
  diagnostics. `replay/redis/connection_scope` distinguishes ordinary pool
  reuse (including server-side script execution and cache operations) from
  recorded stateful lanes and owns their exclusive target connection
  claims; runtime Redis I/O and session setup remain in `replay/redis/mod.rs`.
  `replay/redis/cross_case` owns finite sharing of source-proven Redis reads
  across cases in one completed recording; policy feedback owns promotion of
  the corresponding time-shift rule.
  `replay/redis/request_identity` owns the native request fingerprint shared by
  Replay admission and authenticated unmatched-request diagnostics.
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
- `e2e_run/source_response` resolves the immutable primary-response artifact
  and exposes only its recorded elapsed time for the HTTP execution budget.
  The driver adds its ordinary execution allowance to that duration; response
  status, headers and body remain with assertions and never become Target inputs.
- `e2e_run/case_selection` owns repair-attempt case selection, workflow and
  immutable API-inventory boundaries, and historical passed-case skips. It reads
  the opt-in local regression setting, preserves failed and unexecuted inputs,
  and always selects every case for final revalidation. Protocol loading and
  target cache behavior remain with their existing owners. Published reports
  contain only actual session membership; Source rule validation retains the
  complete canonical API scope, including skipped cases.
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
  `scheduling.rs` owns first-attempt priority at group boundaries, gated API
  revalidation selection and resumable system-repair blocking. Action selection,
  worker scheduling and coordination counts share its first-attempt eligibility;
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
  Its status summary reuses the caller's loaded workflow snapshot; standalone
  operation inspection loads its own snapshot only when no caller supplied one.
  Operations bind their selected recording; validated batch replacement retires
  finished older operations while retaining current failures and running ownership.
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
  on both load and save. Its `decision_history` child owns explicit, idle-only
  history compaction from raw state, original-byte backups, and on-demand archive
  verification; maintenance never adopts recording policy or folds pending events.
  `dependency_review/decisions/history` owns ordered audit references and legacy
  inline decoding. Its `archive` child durably publishes immutable history bodies
  before state references, independently of recordings and workflow replacement.
  References retain proof-template digests and counts so status validates metadata
  without loading historical UUIDs. Newly recorded origins bind workflow, recording
  and inventory; legacy origins remain unknown. Active `decisions` still own exact
  finite membership and acceptance identity. These modules never manufacture task-runtime
  handles or manage worktrees. `model.rs` owns the remaining persisted state and
  public action contract and reexports the worker contract for compatibility.
  `store/replacement` owns purpose-entry archival and rollback of obsolete
  snapshots. It reads only their version and workflow identity, preserves their
  original bytes and never loads old assignments or receipts into a new workflow.
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
  workers. Recognizing static routes or repeating existing patterns advances the
  catalog while preserving capture policy bytes, identities and proofs.
  `work_scope.rs` owns the API worker scope identity.
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
  Its optional stream timing mode and interval cap flow through `e2e_run/config`
  and `e2e_run/runtime` into Replay lifecycle state. Protocol delivery owns gap
  compression; configuration resolution does not rewrite recorded evidence.
  `rewrite/fingerprint` binds the mode and effective fast cap to execution
  identity, and `e2e_run/case_selection` keeps passed-case history within that timing.
  `e2e_run/execute/timing_guard` checks resolved and selected timing before
  freezing execution identity and launching Replay after asynchronous preparation.
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
- Within `rewrite`, `quality.rs` owns final source/isolation policy and the
  final agent-owned quality-check attestation. Ordinary delivery captures exact
  identity without scanning source or executing repository commands. Clippy and
  other lint run only in the consolidated final assignment. The final receipt
  binds the configured tool, committed candidate, build inputs and workflow scope.
  Historical worker/integration quality receipts remain readable but cannot
  authorize final revalidation. `target_quality.rs` is a legacy admission boundary
  that never launches repository checks. `target_replay_isolation`, owned by
  `quality`, prevents production code from consuming private replay addresses,
  runtime state and recordings; it runs during final pre-revalidation review.
- `rewrite/source_diff.rs` owns the Git source-diff boundary shared by Replay
  isolation and source review, including committed/worktree/untracked files and
  rename handling. Its `layout` child maps a target project nested below the Git
  repository root onto the corresponding directory in worker and integration
  worktrees, validates managed-file access, and owns conversion between
  target-relative and Git tree paths. Source diff expands over the target plus
  configured same-repository managed directories and rejects tracked candidate
  changes outside that delivery scope.
  Its `cache` child reuses successful Git identity/history, diff and file-list
  reads and PR-base resolution only within a status/inventory query, keyed by
  directory and exact arguments. Other Git commands, including output-file
  writes, invalidate those reads; later queries inspect Git again.
  `rewrite/review` owns final source review, spawn evidence, receipt admission
  and quality rework routing. Its `delivery` child captures exact worker and
  published integration identities without source scans or repository commands.
  Ordinary review check is a successful no-op for code quality; dispatch,
  committed-code and publication checks remain delivery responsibilities. Its `scan`
  child owns Rust syntax findings and complete-file line limits.
  Its spawn scan recognizes compiler-enforced file/item test configuration and
  Tokio test functions; extracted test files declare their own inner cfg rather
  than relying on inferred filenames or an unproved cross-file caller graph.
  `evidence` validates AI-provided locations and lifecycle explanations without claiming
  call-graph proof. `candidate` owns cross-worktree candidate identity, frozen
  canonical check context, and publication receipt admission without check
  execution. `integrated` owns ordinary freshness, action projection and
  unchanged-purpose baseline admission. Its baseline comparison uses
  `fingerprint::matches_revision` to include tracked/untracked source and
  configuration changes while excluding traffic policy, private runtime and
  progress publication. Ordinary review fingerprints use the same policy
  exclusion; traffic verification fingerprints retain configured traffic policy.
  `review/pre_revalidation` owns the final state-machine gate, exact-candidate
  requirement projection, check reuse and admission, preserved system-repair slices, and the complete
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
- `config/document.rs` owns the Recorder authoring-to-runtime boundary shared by
  standalone, embedded and generated configuration. Its common serde path
  compiles business capture requirements before validation and omits derived
  defaults when serializing, while retaining explicit overrides.
  `config/capture.rs` owns independent ingress/dependency protocol requirements,
  their required transport facilities and conflicting-override diagnostics.
  It reuses protocol identities rather than defining another protocol enum.
  Requirements do not filter observed traffic or add Replay matching work.
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
  narrow MySQL ownership selectors. Its `bounds` child owns statement byte/token
  capability limits, shared by value policies, identity normalization and
  statement parsing; cache admission remains a separate responsibility. Its
  `projection` child resolves bounded single-table SELECT fields, aliases and row-selection clauses without owning
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
  correlated `EXISTS` branches, direct-table JOINs and derived COUNT wrappers,
  and supported `UNION ALL` read trees with joins,
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
  registration. Its cleanup classification remains independent of setup
  omission over the complete loaded connection span. Its
  `control` child validates plain BEGIN/end responses and confirmed empty ends;
  business reads and explicit BEGIN remain required dependencies. Its
  `autocommit` child checks setup omission over the loaded
  read-only span, including retained zero-effect COM_PING continuity witnesses.
  Case-local completed read spans may restart across consistent inactive
  boundaries; active-transaction gaps and Global post-read gaps remain strict.
  `replay/mysql/transaction_equivalence/source` separately proves complete
  ordinary implicit read/write transaction segments, their write counts and
  first-write-through-end windows, retaining unsafe-evidence reasons. Its sibling
  `source_evidence` stores immutable Global ordinary-read identity/status facts,
  without SQL/result bodies or consumption rights. It can bridge only a Case's
  pre-write active sequence gap in an established implicit span with complete,
  unique, continuous same-identity Global reads. Unknown/duplicate facts,
  unsupported effects, missing status and gaps after the first write remain
  strict. These facts neither change ownership nor supply Target delivery
  witnesses. The Source scanner may resume at a later
  independently known inactive start; earlier rejected spans remain diagnosed
  and connection-level incompleteness still prevents setup omission. Its
  `source/error_rollback` child retains a complete contiguous active prefix,
  native DML ERR without status flags, and immediate successful plain ROLLBACK
  as a strict segment. It requires known inactive Source boundaries and exact
  identity/sequence continuity, never fills gaps with Global reads or infers
  missing ERR flags. The existing explicit physical Target transaction witness
  must deliver every prefix member, the error and the real end in order; this
  proof grants neither autocommit equivalence nor end omission. Its parent
  owns connection-local Target BEGIN/end witnesses, ordered finite Source window
  correspondence and delivery-confirmed setup coverage. Multi-write windows
  include every read after the first write, through the actual matching end;
  preceding reads remain finite ordinary dependencies. A single write can supply
  an independent Target autocommit-1/no-active-transaction delivery witness for
  successful Source COMMIT omission. A complete segment containing exactly one
  ordinary UPDATE can also omit successful Source ROLLBACK when that UPDATE
  returned an error or succeeded with known zero affected rows. This bounded
  Source-result compatibility does not infer Source conditional branches or
  prove arbitrary trigger effects; zero-row UPDATEs still count as writes.
  Other business writes ending in Source ROLLBACK retain the same-socket
  first-write-through-ROLLBACK obligation, including trailing reads. Zero-write
  spans retain the existing read-only or confirmed inactive cleanup proof;
  failed controls and unknown boundaries never gain an exemption. A persistent
  Source SET is satisfied only after every affected loaded segment has its own
  successful witness.
  A Target socket's delivered member prefix selects its ordinary finite end
  candidate so concurrent transactions cannot steal identical COMMIT/ROLLBACKs.
  It shares the bounded SQL effect checks in `optional_session/read`, never
  rewrites recordings or grants matching permission from report hints.
  Reports distinguish transaction-covered setups from read-only omissions and
  expose the first-write-through-end semantic revision without relabeling older
  reports. Global projection caches bind that revision independently of Source
  proof facts; Source-only prewarming cannot provide a Target witness.
  `rewrite/evidence/mysql_diagnosis` projects targeted Source/Target transaction
  guidance without asserting ownership or a capability gap from unused counts.
  `replay/mysql/cleanup_selection` owns immutable scope/end/predecessor indexes
  and gives a required transaction end precedence over identical optional cleanup
  only after its immediately preceding recorded exchange has been consumed.
  Availability and consumption remain live checks; end selection does not rebuild
  a consumed-record inventory for every request. Recorder's MySQL semantic
  tracker owns before-command status continuity and final resultset status
  capture. Neither infers transaction
  boundaries from HTTP responses or ORM names.
  `config/process_owned_dependencies/mysql.rs` owns MySQL rule validation and
  matching, while `config/background_mysql_feedback.rs` owns immutable-evidence
  planning and atomic configuration application.
  `config/process_owned_dependencies/redis` validates finite Redis task selectors,
  including exact-key process writes without snapshot permission. Its `pubsub`
  sibling validates exact received-notification scope and original subscription
  confirmations; it never matches outgoing commands or infers external producers.
  Recorder classification, Source-only rule preflight and independent attribution
  reuse that scope. Protocol delivery retains its original finite-consumption
  and subscription guards.

- `rewrite/dependency_rule/planner.rs` owns protocol selector conversion and
  construction of engine evidence plans; its parent owns coordinator rule
  lifecycle and state transitions. `config/process_owned_dependencies/mysql/evidence.rs`
  owns correlation of bounded MySQL report summaries with complete immutable
  exchanges, shared by planning and `replay/report/background_overlay/mysql.rs`.
  That Replay adapter owns reversible MySQL report reclassification only; its
  parent reads immutable case dependencies once for all protocol projections.
  `config/mysql_tables.rs` owns physical table selector
  validation, matching, and intersection independently of SQL template expansion.
- `replay/redis/pubsub/echo/window` proves disjoint finite Source publication
  intervals for repeated identical adapter broadcasts. Echo preparation caches
  these intervals before Target admission; protocol matching and actual delivery
  retain finite ownership. `dependency_index/global` and the Pub/Sub inventory
  keep notification clocks in metadata, independently of private payload bytes.

- `rewrite/unified_rule/manifest/eligibility` permits a finalized partial attempt
  to revoke existing bounded key-local Redis read-back permissions or revise
  formats on existing JSON identity fields. Identity revisions preserve the
  exact field set, kind and literal prefixes; every other compiled owner and
  signature remains identical. Other additions and modifications retain the
  complete-attempt requirement. Full Source freezing, independent Target
  preflight, policy CAS and fresh genuine Replay remain with the normal planner.

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
  `mysql/sql/table_template` owns only bounded token expansion and constraint
  solving for physical table markers and explicit derived projection aliases.
  Replay value selectors and process-owned selectors share it while retaining
  their own SQL admission, table ranges and lifecycle responsibilities.
  `rewrite/rule/generated_values` freezes the engine's file witnesses across
  coordinator plan/apply commands. `e2e_run` supplies the active-attempt guard
  independently of report availability; `rewrite/plan_recovery` retires legacy
  or stale file/signature proofs and requests fresh Replay.
  Native temporal metadata and explicit `mysql.tables` field formats share
  `contracts/automatic` result delivery. Inferred native times rebase only fresh
  Source values; explicitly declared formats preserve the request-relative
  offset of historical or future times without per-SELECT response rules.

- `request_rules` owns explicit inbound-request transformation policy and the
  per-send runtime. Its `jwt` child owns compact HMAC JWT verification,
  Bearer-header or named-query selection, and relative NumericDate translation;
  `socketio_connect` selects exact namespace/auth JSON fields in original
  interaction inputs. It reuses that JWT verifier and send clock, and leaves
  unselected namespace/business frames opaque. Native policy projection and
  named API signature declarations retain the same field ownership.
  `signed_timestamp` consumes typed `input_signed_timestamp` effects, verifies
  bounded sorted-field MD5 signatures and rebases JSON string timestamps using
  only the immutable request clock and startup secret. The Source-validation
  adapter freezes the same private key witnesses before unified rule apply.
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
  Its `render` child replaces derived scalar tokens in the original JSON byte
  carrier, preserving member order and all unchanged lexical data. Shared JSON
  codecs and MySQL JSON-cell delivery reuse it; policy authorization remains
  with their existing logical contract owners.
  Original semantic record readers may supply their envelope budget explicitly;
  ordinary value decoding uses the shared 64 MiB bound. `dependency/http_limits` owns
  the 64 MiB raw-body and derived HTTP witness/record byte budgets, shared by
  recording defaults, Replay, Source proof and dependency diagnostics.
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
  `replay/http/diagnosis` owns read-only published HTTP request queries and
  protocol envelope projection; its `observations` child selects authenticated
  identities before expanding one requested pair. `rewrite/evidence/http_requests`
  binds query cursors to the API issue and published report and returns commands.
  `value_contract/json/diagnosis` owns bounded original-value difference display;
  rule-aware residuals come from the existing runtime value-contract comparator.
  `policy_evidence` retains authenticated independent Target reads, including
  orphan requests, without turning candidate associations into successful matches.
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

- `replay/http/unordered` retains bounded order-difference diagnostics over
  immutable Source and independent Target request evidence. Collection semantics
  come from global `json.fields` and the shared whole-element comparator. This
  diagnostic adapter never authorizes matching, shares exchanges or changes
  finite consumption.

- `replay/redis/value` owns conservative JSON equality for complete string-write
  arguments and bounded collection-order diagnostics. Its selector types describe
  observations only; they do not define policy or an alternative matcher. Global
  `json.fields` and the shared content kernel own value permissions. Unknown
  payloads remain exact bytes. Redis matching retains keys, lanes and finite
  consumption; native usage accounting covers its remaining stateful effects.
- `replay/json_order` owns shared dependency JSON object identity and explicit
  array normalization; HTTP identity and Redis values consume it.
  `replay/recording_evidence` owns standard-run evidence file boundaries shared
  by protocol-specific visitors. `replay/assertion/protobuf/wire` owns bounded
  binary decoding; its `unordered_evidence` sibling exposes typed order witnesses
  without authorizing a schema or a rule.

- `replay/redis/shared_read` owns key/hash selection for finite shared reads.
  It does not interpret response values. Global JSON delivery and the physical
  write/read provenance store own temporal copies; there is no separate Redis
  JSON timestamp renderer or authored lock behavior.
  `replay/redis/key_selector` owns physical key/hash selectors and
  `replay/redis/json` owns bounded duplicate-rejecting JSON decoding.

- `policy/redis_global` owns physical scalar key patterns. The shared identity
  store and `request_contract/redis_fields/keys` relate complete values across
  SET payloads, protocol key slots and opaque script ARGV. Lua interpretation,
  TTL changes and extra command counts receive no permission from a value format.
  `redis_fields/time_writes` publishes temporal write provenance after successful
  wire delivery; JSON reads reuse those values only at the same physical origin
  with independent Source and Target ordering evidence.
  `request_contract/unified_response/contextual` reconciles complete global JSON
  delivery with native read-back values while retaining the native stored bytes;
  `redis_fields/response` owns bulk boundaries and exact surrounding RESP bytes.

- `e2e_run/execution_failure` owns bounded per-Case rejection summaries and pages;
  `rewrite/evidence/execution` binds their continuation commands to the same API,
  issue, immutable inventory and attempt. Omitted overview rows cannot establish
  absence of a failure or borrow another Case's rejection.

- `replay/assertion/interaction/socketio` adapts each Socket.IO business argument
  to the existing global JSON kernel at its own root. It keeps packet metadata,
  event names, argument order and binary attachment declarations strict. Source
  preflight, independent Target proof and final assertions share this adapter.
  `e2e_run/evidence/interaction/socketio` projects authenticated argument values
  for on-demand diagnosis within the existing private interaction evidence
  bounds; persisted reports retain no decrypted message bodies.

- Redis PUBLISH payloads use the common global JSON policy and internal
  correspondence store. Unknown binary payloads retain exact byte comparison.
  Redis matching owns channel, lane ordering, request framing and finite
  consumption; JSON format declarations do not grant resource exemptions.

- `replay/command_matching` separates lane-order admission from final response
  consumption. Case-scoped Redis claims satisfy request order while Responding,
  so pooled sockets cannot race successful delivery bookkeeping. Unclaimed,
  failed and client-termination exchanges remain blockers; final success and
  policy usage are still committed only after delivery. Other protocols keep
  their existing consumption-based admission.
  `replay/redis/admission` owns bounded waits for initial expiry-refresh
  predecessors and earlier activity GETs that have been claimed but have not
  finished delivery. `redis/activity/read_barrier` owns the same-lifetime,
  rule-bound activity predecessor check; admission preserves the original SET
  observation and excludes later reads.
  `observations/refresh_barrier` identifies this narrow fence; observation
  selection retains its completed-delivery requirement. Admission releases the
  replay mutex while waiting, preserves the original Target observation and
  event index, and rechecks the case and strict selection after delivery.

- `rewrite/unified_rule/preflight/global_values/redis/script_times` composes
  existing native script ARGV time contracts with global JSON preflight, while
  the parent keeps script/key/envelope and unselected argument checks. It does
  not execute Lua or grant new native permissions.

- `replay/policy/request_contract/global_value` adapts global JSON comparison
  and typed identity delivery to protocol callers. Its `identity` child creates
  isolated, bounded delivery views containing the selected request's staged
  identity proposals. Response echoes resolve those proposals before publication;
  a failed complete candidate leaves the shared case map untouched. HTTP matching
  commits the joint header, body, query and delivery decision. The protocol owner
  retains strict remainder comparison, independent witnesses and finite delivery.
  Explicit native JWT transformations continue to resolve signing inputs through
  `signing_keys`; global JWT formats verify signatures and claims against
  independently frozen keys before publishing complete-token identities.


## Unified policy responsibilities

- `policy/authoring/api` owns API codec/envelope/header bindings and shared DOCX
  field declarations; signature positions delegate to the signature owner.
  `policy/authoring/http` owns compact request path-identity declarations
  and the separate `http.response_rewrite` acquisition list. Both lower to existing native owners, preserve Source proofs
  and fold only lossless canonical forms. Ordered capture precedence remains
  independent of generated IDs and rendering groups.
  `policy/authoring/recording` owns case path selection and its original Source
  revision/capture identity; the document renderer writes this section last.
- `policy/global_json/template` validates global string layouts and typed slot
  formats. `value_contract/global_protocol/template` owns Source-only layout
  selection, exact literals, token validation and staged complete identities.
  Delivery adapters reconstruct only those selected slots. API encryption
  bindings retain private key snapshots and IV relationships; decoded plaintext
  without legacy overrides reuses the global JSON comparator.
- `replay/http/multipart` owns bounded protocol equivalence for complete Source
  form-data. Matching, final header audits and protected witness verification
  share its parser; it does not change recorded bytes, other headers, finite
  consumption or cross-case sharing fingerprints.

- `policy/signatures` owns named algorithm/key declarations and the private
  immutable key registry. Pure compilation validates references without startup
  I/O; Replay and plan initialization resolve the existing managed key snapshots
  once. `policy/authoring/signatures` lowers API token locations to the existing
  JWT/MD5 owners and renders only lossless generated shapes. Global JWT leaves
  reuse authenticated parsing and NumericDate comparison in `request_rules/jwt`,
  then compare claims through the shared JSON policy and publish complete token
  and claim identity proposals atomically. Global formats allow historical
  tokens; explicitly generated native responses retain their issuance checks.

- `policy/{schema,native,native_compile,strict_map,capability}` owns closed typed
  contracts, Source scope and pure validation. Unknown combinations reject before
  replay; adapter admission and runtime construction share typed projections.
  `native_compile/ownership/read_commutation` composes finite nil GET ordering
  with existing read-back owners whose wire transformation preserves nil;
  Source absence validation and all other response ownership remain separate.
- `policy/authoring` owns document revision context, rule-local proof inheritance,
  named contract abbreviations and readable YAML rendering. Its closed traversal
  expands only typed contract locations, preserving business literals. Optional
  Source explanations belong to plan IR; rendering removes those schema-owned
  records and verifies semantic fingerprints after a parse round trip.
- `value_contract/{json,encoded,time,generated,delivery,identities}` owns pure values, whole
  element pairing, microsecond relationships, conditional fields and staged
  nonces/templates. Keys are borrowed immutable inputs; bytes and plaintext do
  not enter errors or reports.
  `policy/time_scope` validates explicit shared, array-element and identity-bound
  clock scopes. `value_contract/json/clock_scope` resolves immutable array
  coordinates or identity fingerprints; the existing comparison owner retains
  relation budgets and cross-message validation.
  `value_contract/identities` owns bounded case/domain renaming proposals,
  equality and injectivity, and historical input anchors. The request-contract
  identity adapter commits accepted proposals and translates only declared
  physical leaves. MySQL result and Redis RESP owners retain wire framing and
  publish complete delivery batches before bytes become visible. The private
  `replay/control/identity` bridge joins runner-owned response constraints to
  dependency state before case cleanup; generated tokens never enter reports.
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
  `manifest/eligibility` owns narrow finalized-partial format changes: Redis
  scalar identities and existing JSON identity representations retain every
  other compiled permission and pass the same complete preflight and stale
  checks. Eligibility never certifies an incomplete Replay.
  Its `change` child admits explicit replacement sets, preserving unselected
  rules and API ownership. Replacements reuse complete preflight, whole-policy
  compare-and-swap, durable publication intent and recovery; they are not an
  alternate policy writer or a persisted policy format.
  Its `proposal` child merges new rules, additive identity references/read-back
  declarations and independently proven one-way finite raw identity read-back
  upgrades to state observations. Existing scope, contracts and prior proofs
  remain immutable. Preflight and publication retain all ordinary stale checks
  and fresh-Replay obligations for that extension.
  `manifest/primary` freezes each selected Case's original primary-response oracle
  and published assertion/Target artifacts, including inline binary bodies, even
  for dependency-only rules. It freezes managed decryption keys and supplies
  authenticated private request/response views only in memory. Primary payload
  adapters distinguish ordinary bodies from interaction observations; native
  response effects retain explicit body/header ownership. Preflight and Replay
  keep interaction body contracts inactive without weakening message assertions
  or dropping header date/JWT validation.
  `replay/assertion/interaction/contracts` owns the explicit SSE envelope/data
  adapter shared by Source/Target preflight and Replay; `value_contract/json/identity`
  owns pure payload identity comparisons, while the case store retains accepted
  relationships across physical observations. Policy SSE slots retain separate
  event/body field ownership. `unified_rule/discovery/primary` owns authenticated
  primary-response observations, scheduled before dependencies for response issues
  within the shared discovery budget. Its `page` sibling owns bounded scan and
  summary positions; `evidence/unified_discovery` binds continuation commands
  and evidence identities to the active issue. Its `interaction` sibling supplies bounded
  private SSE slot/time drafts and explicit authoring guidance without inferring
  identity authority. Public result observations retain private-field
  unavailability for virtual SSE pointers.
  `discovery/values` derives wildcard fields only from actual decoded arrays and
  combines bounded candidate bindings without inferring generation authority
  from field names, numeric object keys or observed physical shards.
  `evidence/rule_guidance/stateful_dependencies` projects supported mechanisms
  from bounded dependency operations and Source binding metadata. It supplies
  proof requirements and ordinary plan commands without granting permission or
  changing matching, ownership or consumption.
  `preflight/{api,dependency,session,source}` delegates primary response, native
  envelope, stateful Source trace and whole-recording proof to their existing
  owners. `preflight/response` records available primary responses with different
  statuses as unvalidated Target witnesses, keeping rule publication separate
  from Replay status acceptance without weakening artifact integrity or Source
  validation. `preflight/resource` enumerates complete recording scope for API-free
  resource rules and freezes relevant API memberships and foreign execution
  identities, including missing Target evidence. `preflight/payload` validates
  each execution with its own protected Target witnesses and clocks. Primary
  response assertions retain their prepared API scope. Discovery and proposal
  preparation omit API selectors for new resource rules while preserving legacy
  explicitly scoped relationships. Native bindings remain case-local.
  Coordinator admission preserves write intents and fresh real verification
  obligations across crashes. Bounded hints never substitute for full coverage.
  MySQL's `contracts` adapter filters structurally unrelated request candidates
  before scalar contract comparison. Preflight counts only validated pairs;
  an unpaired Source exchange retains its fresh-Replay obligation.
  `preflight/candidate_pairs` correlates each protected MySQL or Redis Target
  request observation over the complete selected Source scope, rejecting related
  Targets without a valid pair while retaining failed search edges as evidence.
  It does not claim Replay consumption or relax native ordering; accepted plans
  retain genuine Replay obligations.
- Historical feedback DTOs may remain as domain data or journal recovery inputs.
  Their old authoring entrypoints reject and production loaders accept only
  `traffic-policy/v3`. Test-only explicit fixture migration is not a reader
  fallback and cannot produce project proof.
