# Development Guide

Use this file for local commands, runtime behavior, recording, replay, and
testing details. Keep `AGENTS.md` as the short navigation map.

Author resource and API output fields once with the current
[resource-owned field contracts](resource-field-contracts.md). Contextual clock
relationships and stateful protocol effects retain explicit rules.

API-triggered asynchronous process traffic uses [API-origin rules](api-triggered-process-traffic.md),
including request-body conditions, recorded identity capture and old-recording reclassification.

MySQL replay driver compatibility and process-owned read rules are documented in
[mysql-replay.md](mysql-replay.md).

Redis Pub/Sub notifications and correlated RPC callbacks are documented in
[redis-pubsub.md](redis-pubsub.md).

Finite process-owned Redis GETs and initialization snapshots have separate
consumption contracts; see [process-owned Redis](process-owned-redis.md).

Cross-case HTTP initialization dependencies use explicit Replay scope rules; see
[HTTP cross-case replay](http-cross-case-replay.md) for discovery, plan/apply,
strict matching and fresh verification.
Source-proven arrays in outbound JSON requests use [HTTP unordered rules](http-unordered-rules.md).
SDK request headers retain ordinary strict presence and value comparison. Global HTTP formats validate generated values without allowing missing headers.
Failed outbound requests expose [HTTP request body evidence](http-request-evidence.md),
including exact protected body pages, raw differences and recorded rule results.
Rule planning reuses [recording indexes and sealed Source content identities](rule-evidence-index.md)
while retaining complete active-API coverage and fresh plan/apply checks.
Replay [candidate and witness storage](replay-candidate-performance.md) reuses
immutable Source references and preserves complete visited-candidate coverage.
Coordinators can [plan against unrelated completed APIs during Replay](concurrent-rule-planning.md),
then explicitly apply reviewed plans at the next idle boundary.

Redis JSON/Protobuf values and source-proven collection ordering use
[Redis value rules](redis-value-rules.md), with the same discovery and plan/apply lifecycle.
[Redis APPEND streams](redis-append-stream.md) support Source-proven changes to
batch boundaries under explicit API/resource/key scope, retaining read fences.
Source-proven expiry drift in Redis JSON read responses uses explicit
[Redis time-shift rules](redis-time-shift-rules.md), discovered through worker
source diagnosis without heuristic hints.

Source-proven Redis ownership tokens use [Redis scalar formats](redis-scalar-formats.md),
with bounded token-only witnesses, explicit endpoint/key scope and fresh Replay.

Source-generated identities shared across decoded SQL, JSON and Redis keys use
[case-local dynamic values](dynamic-value-rules.md). Generated filename dates
use [response header date rules](response-header-date-rules.md); both use
evidence-backed plan/apply and fresh verification with existing recordings.
[Dependency request rules](dependency-request-rules.md) cover integer JSON-RPC
IDs, signed Redis JSON writes, correlated write times and multipart boundaries.
[Generated HTTP request body fields](http-request-body-fields.md) validate bounded
random identifiers and signed JWTs against independent dependency request clocks.
[Shared HTTP stream/input timing](http-stream-input-timing.md) preserves client-close
ordering while accelerating dependency streams.
[Rewrite evidence](rewrite-evidence.md) describes the lightweight implementer
overview, conditional strategies and authenticated on-demand dependency metadata.
[SSE response diagnostics](interaction-diagnostics.md) expose authenticated
per-frame response values through bounded, read-only evidence queries.
[JWT response rules](jwt-response-rules.md) validate signatures, stable claims
and request-relative validity for freshly issued HTTP JSON tokens, including
URL query tokens, typed base64url nonces, RS256 public-key verification from
recorded MySQL results, and linked integer/RFC3339 expiry and TTL fields.
[JSON response time rules](response-time-rules.md) validate source-proven expiry
and scheduled-time offsets through explicit `preserve_relative` timestamps.

[Content formats and carrier bindings](content-policy-layout.md) describes global
string templates, HTTP acquisition/path declarations, shared DOCX fields, API
encryption/header positions and default multipart comparison.

## Rust Tooling

[Protocol and execution contracts](protocol-rule-execution-design.md) describe
shared request admission, codecs, native constraints and prepared rule/index
requirements. [Per-Case performance](replay-protocol-performance.md) records the
fixed-revision comparison and reproducible synthetic HTTP-to-Redis/MySQL benchmark.

[Rule candidate pre-matching](replay-pre-matching.md) collects supported value
differences without certifying them; managed streaming Replay can also skip
recorded idle gaps while preserving framing and termination.

Use the standard Cargo workflow:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
plugins/ai-software-engineering/skills/backend-rewrite/scripts/check-code-organization
cargo build --bins
```

The repository includes `.cargo/config.toml` for the configured crates.io
mirror. Do not replace that registry configuration unless explicitly asked.
The build produces sibling `traffic-e2e`, `backend-rewrite`, and
`backend-rewrite-admin` executables. Keep them together in installed packages
because detached coordinator actions delegate engine work to `traffic-e2e`.
After an engine build changes, the coordinator permits one fresh Replay per API
method for a runtime failure or a dependency-only failure with complete Replay
and all responses passed. Historical attempts without an engine identity also
receive one refresh within those categories. A route with a failed Replay on a
known older engine also receives one refresh regardless of Replay failure kind
when every other route is Complete, RevalidationPending or Skipped. Route
methods share this inventory condition but retain independent durable permits;
quality review failures are not Replay failures. RevalidationPending routes
still require their ordinary verification and do not become completed through
this eligibility check. The permit is persisted before execution and survives
restarts; failure retains the issue and cannot retry again on the same build.
A coordinator-confirmed, reviewed `rework_required` retains its pending resume
before an optional engine-change retry, including the unconfirmed new dispatch
generation. It does not consume the retry permit or waive fresh acceptance.
A current confirmed `running` or `queued` implementation keeps its dispatch
ahead of this optional refresh. An expired activity observation requests a fresh
runtime query rather than dropping the dispatch or starting Replay. A confirmed
`handoff_ready` or `integrated` delivery keeps its ordinary integration/verification
path ahead of the optional refresh. Skipping another
route cannot turn the accepted delivery into an ineligible historical scope;
no engine retry permit is consumed for it. Stale dispatch/recording observations
do not acquire that priority, and skipped/completed scopes remain excluded.
A changed process-owned policy first reclassifies the finalized report. If only
dependencies remain dirty, successful apply also requests one real Replay for
the affected route methods; unchanged reapplication does not renew it. Recomputing
an old failed report preserves an unused Replay request. Other
rule-application Replay requests remain independent. No worker claim
that target code is correct is needed to refresh stale engine evidence; source
review, target quality, worker activity and traffic leases still apply.

On Linux, a running `traffic-e2e` reexecs through `/proc/<pid>/exe`, retaining its
running inode and engine revision even when its installed executable is replaced.
Companion resolution also recognizes a replaced `backend-rewrite` executable.
Container bind mounts continue to use installed filesystem paths rather than
process-specific reexec handles.
An interrupted focused attempt that failed before Replay readiness has no
session to reclassify. Status retains its failure state without requesting
session reclassification; actual evidence revision still requires session identity.

The runner persists a primary response status mismatch (for example Source 200
and Target 500), or an unavailable response, before notifying Replay with
`case_failed`. This ends the normal asynchronous business wait. Unstarted Source
calls remain unused/dirty; error cleanup can contain any actual dependency or no
dependency. `replay/control/case_cleanup` owns the monotonic failure cleanup
budget and shared actual-I/O barrier, including Kafka and failed connections.
Only real delivery or termination must drain before releasing Case ownership.
An actual-I/O cleanup timeout includes a bounded `pending` snapshot taken under
the ownership lock: protocol counts, retained Source exchange references and
Redis observation claims. It contains no SQL, Redis keys, headers or payloads.
Use this timeout-time evidence to identify the blocker; a later interrupted
snapshot is captured after Target shutdown and can already show that I/O ended.
The recorded Target-stop receipt remains mandatory where Source requires it.
Body-only differences with the same primary status retain normal async waits.
A finished failed Case can continue to the next input and publish a complete,
dirty Replay; primary status mismatches take diagnosis priority over derivative
body fields. Nothing in this path marks the response or unused dependencies as
passed, and rule planning retains its complete-evidence checks.

Execution failure overviews contain at most eight Cases and expose explicit
total, returned and omitted counts. Follow `execution_failures_query` and each
`pagination.next_page` for remaining Cases from the same issue attempt. Missing
rows in the overview do not prove a Case had no rejected dependency.

Terminal E2E `diagnosis.replay_finalized` reports session publication separately
from selected-case coverage. A failure-limited attempt can finalize normally
while its Replay gate remains incomplete. Such an attempt retains its observed
dependency or response cause; incomplete coverage alone does not prove that
Replay failed to finalize. Older results without this field keep conservative
lifecycle attribution.

Socket.IO interactions apply global `json.fields` at each event/ACK business
argument root, just as other logical JSON carriers do. Protocol kind, namespace,
normalized server event ACK identity, event name, argument order/count and binary
attachment declarations remain exact. Known business packets do not fall back
to opaque byte comparison; control packets retain their transport contracts.
Fast replay aligns plain Socket.IO ACKs by namespace and original client event
ID. ACKs can cross same-namespace text events when the request was already
pending and the recorded input has no conflicting completion or transport
boundary. Business events are compared in their original relative order.
When a Source heartbeat timeout qualifies for fast replay, the engine enters
the terminal heartbeat phase after dispatching the recorded inputs. It defers
each Engine.IO Pong until a later business frame arrives within the Target's
advertised timeout. For a proven passive Pub/Sub prefix, recent delivery to
the real subscription also keeps the connection open while earlier native
slots are still draining. If there is no later frame, Target closes the actual
connection and runs its own disconnect handler. Case ownership remains active
while disconnect traffic is observed. Earlier assertion and dependency
differences remain in the report.

If actual execution cleanup fails after Replay readiness, the runner stops Target and asks
Replay to publish an interrupted diagnostic snapshot before stopping its process.
`replay/control/interruption` seals captured payload observations and writes the
report plus dependency index; `e2e_run/interrupted_evidence` builds runner-owned
aggregate and executed-case assertion projections. Active ownership, in-flight
exchanges and pending cases remain visible; `finalized` and aggregate `complete`
remain false. These artifacts support dirty-cluster, HTTP request, response and
rule-candidate diagnosis, but cannot anchor rule planning or count as passing
verification. Missing or failed snapshots remain explicit errors. Response and
dependency issues also expose bounded target runtime logs for attribution.

`traffic-e2e record` is built normally and supports optional Redis coordination.
See [standalone recording](recording.md) for its container contract, direct
standby, generated run IDs and handoff to rewrite.

All binaries report the package version, build revision, and exact pinned
target-runtime image from `--version`. Git checkouts derive the revision
automatically and append `-dirty` for uncommitted content. Builds without Git
metadata should set `TRAFFIC_E2E_BUILD_REVISION` to a 1-64 character release
revision containing only ASCII letters, digits, `.`, `_`, `+`, or `-`.
The build script resolves the invoking checkout from Cargo's runtime
`CARGO_MANIFEST_DIR`, so reusing a build-script executable across worktrees does
not retain another checkout's revision or Git watch paths.

## Coordinator decision history

Coordinator state retains current workflow data, active ownership decisions and
small ordered references to immutable historical decisions. Normal state saves
publish new audit bodies under `.traffic-e2e/local/runtime/rewrite/decision-history/`
before atomically replacing `state.json`. `status` and `inventory` read reference
metadata without opening these bodies. Active ownership and verification
receipts keep their existing semantics and exact occurrence membership.

Existing inline history remains readable. After detached operations and traffic
have finished, explicitly migrate it without advancing the workflow:

```bash
backend-rewrite-admin --target-root /absolute/target history compact
backend-rewrite-admin --target-root /absolute/target history verify
```

Compaction takes coordinator, feedback and rule-plan locks, preserves workflow
identity/revision and pending feedback, and keeps an original-byte backup under
`rewrite/history/`. Retrying reuses identical archive bodies; publication failure
leaves the previous state intact. A later ordinary state save also extracts inline
history. Read-only queries never migrate it themselves.

Verification explicitly reads the referenced bodies and checks content hashes,
counts, proof metadata and archival workflow bindings. Missing or changed history
is an audit error, never an empty history. Repeated occurrences, reference order
and prior proof revisions survive migration. New decisions record their original
workflow/recording/inventory; legacy origins remain unknown. Purpose replacement
may inherit old references, which retain their own archival workflow identity.
Archives and state backups must remain available independently of deleted
recordings and old Replay output; this change does not garbage-collect them.

## Shared Container Images

### Engine binary image

`docker/engine/Dockerfile` packages the prebuilt Linux/amd64 `traffic-e2e`,
`backend-rewrite`, and `backend-rewrite-admin` executables together under
`/usr/local/bin/`. Build and publish from a clean engine checkout:

```bash
./scripts/build-engine.sh --publish
```

The script builds all three release binaries once, verifies their revision,
stages only those executables, builds the image and pushes it to
`registry.api.demo.test/weibo_rd_if/traffic-e2e-engine:<version>`.
The image version is recorded in `docker/engine/VERSION`, starting at `0.0.1`;
increment the patch version for each new release. Git revision remains in the
binary version output and OCI image labels. Local dirty builds use a `-dev`
suffix; publication requires committed changes.
Use `--skip-build` to package matching binaries already built for the current
revision, or `--tag <image>` to choose another image reference. No project
configuration, credentials or recordings enter the engine image.

Project recording images use `FROM <engine-image>@sha256:<digest> AS engine`
and `COPY --from=engine /usr/local/bin/traffic-e2e /usr/local/bin/traffic-e2e`.
Their normal Source image supplies application code and system libraries;
recording image builds do not need an engine checkout, Cargo or SSH access.
Projects using Kubernetes dependencies copy kubectl from its independent
[distribution image](#kubectl-distribution-image), not from the engine stage.

### kubectl distribution image

Package a verified static Linux/amd64 kubectl independently of the engine:

```bash
./scripts/build-kubectl.sh --kubectl /data0/icy/bin/kubectl --publish
```

Without `--publish`, this only builds and checks the local image. The default tag
is `registry.api.demo.test/weibo_rd_if/kubectl:<client-version>` without the leading
`v`. `--tag IMAGE` overrides it. The script validates the executable format and
client platform, stages only the binary, records its version and SHA256 labels,
and checks it in a network-disabled container. Publication refuses an existing
tag and inspects the pushed manifest. Docker, `file`, `sha256sum` and Python 3 are
required; neither the binary nor cluster credentials are committed.

The published `kubectl:1.24.4` manifest is
`sha256:253a3a69fd34454f6ddf584a1339d7a748c8268a038afe2c5d83836d6c6ec0af`.
Its binary SHA256 is
`7a5bd1dc2ef61468e2a01bd66cc6590e472cab984229c88d5f67c375b9f13ccc`.
The scratch image contains only `/usr/local/bin/kubectl`; project recording
images copy it from a separate build stage as shown in
[`docker/record/Dockerfile.example`](../docker/record/Dockerfile.example).
The engine and Recorder runtime remain independent of this tool image.

Configure [Kubernetes upstream routes](kubernetes-recording.md) to discover
Service ports and supervise forwards before Source starts. Projects choose
controller-private runtime mounts or explicitly package a portable kubeconfig
in their dedicated recording image through a private build context. A packaged
kubeconfig retains its credentials in image layers; rebuilding is required to
rotate them. Keep these files outside Git and restrict their image path to root
with a `0700` parent directory and a `0600` file. The shared engine and kubectl
distribution images contain no kubeconfig.

### Runtime images

The repository owns Dockerfiles for project-independent recording and target
runtime images:

```text
docker/network-anchor/Dockerfile
docker/network-probe/Dockerfile
docker/recorder-runtime/Dockerfile
docker/builder/Dockerfile
docker/target-runtime/Dockerfile
```

Published Linux/amd64 references:

```text
registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62
registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107
registry.api.demo.test/weibo_rd_if/rust-builder:1.98.1@sha256:99fe1fa7319ef65993c61ca9aa9f3e58a10573a2701a19109adabca46007a670
registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-runtime:0.0.2@sha256:d322b050229334c2fec00cdce366a066697a7bafaf9b6842d77793eb1e4f10d2
```

Build the inert Linux/amd64 network-namespace anchor without network access:

```bash
docker buildx build \
  --platform linux/amd64 \
  --network none \
  --load \
  --file docker/network-anchor/Dockerfile \
  --tag registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1 \
  docker/network-anchor
```

Build the Linux/amd64 Recorder runtime through the host network. When the host
requires a proxy, pass only the standard proxy build arguments that are already
present in the environment; do not declare them in the Dockerfile or persist
them as image environment variables:

```bash
docker buildx build \
  --platform linux/amd64 \
  --network host \
  --build-arg HTTP_PROXY \
  --build-arg HTTPS_PROXY \
  --build-arg ALL_PROXY \
  --build-arg NO_PROXY \
  --load \
  --file docker/recorder-runtime/Dockerfile \
  --tag registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev \
  docker/recorder-runtime
```

The `-dev` runtime intentionally contains no `traffic-e2e` binary. Mount the
exact installed Linux/amd64 binary read-only at
`/usr/local/bin/traffic-e2e`. Publish only versioned tags, verify the pushed
manifest digest, and pin consumers to `tag@sha256`.

Recorder remains root inside this runtime for managed DNS and interception.
When its recording output is a host bind mount, the host wrapper must pass
`traffic-e2e internal recorder-run --artifact-owner "$(id -u):$(id -g)"` so finalization
assigns only the exact run tree back to the invoking host user.

Build the fixed Linux/amd64 network probe through the host network:

```bash
docker buildx build \
  --platform linux/amd64 \
  --network host \
  --build-arg HTTP_PROXY \
  --build-arg HTTPS_PROXY \
  --build-arg ALL_PROXY \
  --build-arg NO_PROXY \
  --load \
  --file docker/network-probe/Dockerfile \
  --tag registry.api.demo.test/weibo_rd_if/traffic-e2e-network-probe:0.0.1 \
  docker/network-probe
```

Runtime consumers pin the published manifest as
`traffic-e2e-network-probe:0.0.1@sha256:6804ffe944eb4709c4f8387e984dfcf524be14241c571756a6b6b85a8cb13f8e`.
The probe contains only curl and the public CA bundle, defaults to `998:998`,
and is used when the recording source image has no runnable Java environment
and for every Replay network preflight. It must not contain Java, Recorder,
Replay, Docker, or networking capabilities.

Build the Linux/amd64 Rust builder through the host network. The explicit
platform is required because its legacy upstream image omits architecture
metadata; the published builder itself must inspect as `linux/amd64`:

```bash
docker buildx build \
  --platform linux/amd64 \
  --network host \
  --build-arg HTTP_PROXY \
  --build-arg HTTPS_PROXY \
  --build-arg ALL_PROXY \
  --build-arg NO_PROXY \
  --load \
  --file docker/builder/Dockerfile \
  --tag registry.api.demo.test/weibo_rd_if/rust-builder:1.98.1 \
  .
```

The builder source pins that upstream by digest. Proxies are one-time build
inputs only; do not persist them in the image or expose them to target builds.
The builder intentionally leaves `CARGO_BUILD_TARGET` unset. Its Rust toolchain
uses the native `x86_64-unknown-linux-gnu` host target and therefore preserves
Cargo's standard `target/release` artifact layout. A project that explicitly
cross-compiles owns its target selection and artifact path.

Build the Linux/amd64 target runtime through the host network:

```bash
docker buildx build \
  --platform linux/amd64 \
  --network host \
  --build-arg HTTP_PROXY \
  --build-arg HTTPS_PROXY \
  --build-arg ALL_PROXY \
  --build-arg NO_PROXY \
  --load \
  --file docker/target-runtime/Dockerfile \
  --tag registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-runtime:0.0.2 \
  docker/target-runtime
```

The target runtime contains common dynamically linked Rust prerequisites and
the normal public CA bundle, creates `trp-record` as UID/GID `998:998`, and
defaults to that identity. It reserves `/app` and `/traffic-e2e/trust`; target
images add only their release binary and explicit
foreground entrypoint. The runtime clears the Debian base command so Docker
does not append `bash` to that entrypoint. Publish only versioned tags, verify
the pushed manifest digest, and pin target Dockerfiles to `tag@sha256`.

## CLI Boundaries

Ordinary implementer delivery and integration do not require source review.
Implementers own Source-correct logic, build/debug as needed, run focused tests
for changed modules, format when needed and return committed delivery identities.
They do not execute Clippy or other lint tools. Those tools belong to later
consolidated quality work.

Pooled `implementer handoff --deliveries FILE` accepts entries
`{api, dispatch_id, lease_generation, handoff_id, delivery_commit}`. The engine
validates the registered worktree, committed target/managed code, exact dispatch
and commit ancestry, then freezes a private identity receipt and durable Git ref.
No source scan, line limit, spawn evidence or repository command runs at handoff.
Legacy dedicated worker handoff uses `worker report --activity handoff_ready
--handoff-id ID --delivery-commit COMMIT`. Existing review receipts remain
readable for outstanding deliveries.

Integration only merges the assigned accepted commits and resolves actual
conflicts. It does not review code. A conflict-free merge executes no cargo
build/test/fmt/clippy, lint or review check. If conflict resolution changes code,
run tests for the affected modules and format only when needed; Clippy and other
lint remain prohibited. No full build/test cycle is required for integration.
The integrator returns the exact candidate commit and original handoff mapping.
The coordinator publishes that commit and acknowledges each ready handoff with
`worker report --activity integrated --handoff-id ID --delivery-commit COMMIT`.
The returned command accepts `BACKEND_REWRITE_DELIVERY_COMMIT`. Admission checks
identity and exact committed publication without source or repository checks.
`inventory` exposes frozen `delivery_commit` and `worker_worktree`; do not consume
a reused implementer checkout's current HEAD. A batch can share one published
candidate while retaining each handoff's separate identity. Already integrated
handoffs stay integrated, including after interrupted reporting.

`review check` outside `--pre-revalidation` returns `passed`, explains that no
check is needed, and captures only identity. It performs no source scans or
repository checks. Neither implementer nor ordinary integrator needs to invoke
it. Missing/stale ordinary review receipts do not block focused Replay. Worker
evidence exposes `context.delivery.assignment` and optional `required_repairs`,
without a review check command.

When the target is nested in a Git repository, keep `--target-root` at that
project. Worktree paths may identify the outer Git worktree or project directory.
`delivery.managed_paths` adds disjoint same-repository siblings; their paths are
reported relative to target, such as `../backend-rs/src/lib.rs`. Changes outside
this managed scope are rejected during identity admission.

Only `pre_revalidation_review_required` requests consolidated review. A separate
final-review assignment executes the configured `delivery.quality_check` and
required project tests on the final committed candidate, then reports success:

```bash
backend-rewrite --target-root /absolute/canonical review check \
  --pre-revalidation --quality-check TOOL --worktree /absolute/integration
```

This stage scans the whole PR, enforces changed production Rust files <=1000
complete physical lines, validates startup ownership for added Tokio spawns,
and checks Source/Replay isolation and source-sensitive domains. Read the
[Source review contract](../plugins/ai-software-engineering/skills/backend-rewrite/references/source-review-rules.md)
for syntax scope, test-only exclusions and exact evidence. The engine never
executes fmt, tests, Clippy or another repository command; the final assignee
owns tool execution. The configured quality tool defaults to `cargo-clippy`.

If final review splits or otherwise changes code, commit corrections and refresh
affected checks. Publish the exact passing final candidate and invoke
`review accept --report ...` to admit it for a complete final revalidation.
Ordinary identity receipts and earlier API successes cannot prove this changed
candidate. Final proof binds code, build inputs, policy, inventory and recording;
relevant changes require fresh proof, while progress-only publication may reuse
an already admitted matching receipt. A request to stop at ordinary API
`completed` leaves this stage pending. `review rework` can route final findings
to their responsible implementer; their repair and ordinary integration still
submit committed identities without a review-check cycle.

Use `traffic-e2e config ... init` for one-time target configuration and
`traffic-e2e prepare|run-api|run|status|recover|abort` for the standard
workflow. Use `traffic-e2e config recorder|replay plan|apply` for
evidence-driven managed rule changes. Use `traffic-e2e diagnose ...` only for
recorder development or focused low-level diagnosis. Managed record, replay,
target isolation, and host interception are implemented in the `traffic-e2e`
binary.
Repository scripts are development checks or explicit host trust-store tools
only.

Use the `backend-rewrite` binary and its `next`, `status`, `inventory`,
`evidence`, `rule`, `route`, `repair`,
`config`, and `recover` commands for AI-facing migration orchestration.
`traffic-e2e` has no
`rewrite` subcommand; `backend-rewrite` invokes the shared crate directly and
delegates only engine-owned detached work to its sibling executable.

When explicitly selecting a dynamic API before its first standard recording,
`next --source-route` requires the complete source route, including every router
mount prefix. For example, `GET /api/attachments/task/*/all` requires
`/api/attachments/task/{task_id}/all`, not the local decorator path
`/task/{task_id}/all`. APIs installed from a completed recording already have a
confirmed `case_path_pattern`; when no more specific source-route binding exists,
the coordinator uses that pattern as the route specification instead of stopping
Replay for duplicate route confirmation. If an older engine saved an invalid
route, repeat `next --api '/api/attachments/task/*/all' --source-route
'/api/attachments/task/{task_id}/all'` with the corrected full route. Correction
is allowed only while the API is pending, with no group or verification history;
valid bindings remain fixed. Existing recording and workflow progress are retained.

Confirmed dynamic source routes persist independently of recording batches and
take precedence over the recorded-pattern fallback.
Ordinary re-recording and recorder-contract refreshes reuse a valid binding for
the exact API method/pattern, including APIs absent from an intermediate batch.
Verification results still reset for the new recording. Existing workflow states
retain their valid routes when their inventory is rebuilt; routes already lost
by older resets fall back to their confirmed recorded patterns. New uncovered
paths are handled by case-pattern identification before inventory installation;
only an explicitly selected dynamic API without recorded pattern coverage needs
source-route confirmation. An explicit `source_baseline_changed` external recording requirement
discards retained source routes while recorded patterns remain usable. Restarting
the coordinator session does not clear bindings.

## Running Locally

Recording defaults to `redact_headers: []` so authentication and session headers
remain available for Replay. Redaction irreversibly replaces values with
`<redacted>` and can break authenticated requests. Existing projects with an
explicit list must set `recorder.recording.redact_headers: []` themselves;
previously redacted recordings require new capture to recover those values.
Unencrypted headers are stored as plaintext in the sensitive recording artifacts.
Newly initialized projects and the example configurations also default to
`encrypt_request_headers: [authorization]`, with or without Breeze. Existing
projects can enable the same request-header encryption. The low-level
`RecordingConfig::default()` and configurations omitting both lists preserve
headers without encryption; low-level callers must explicitly configure
`encrypt_request_headers` and provide the encryption key when needed:

```yaml
recorder:
  recording:
    encrypt_request_headers: [authorization]
```

JWT expiration between recording and Replay can be handled by an explicit
`traffic-policy/v3` `input_jwt` rule. See [JWT request rules](jwt-request-rules.md)
for the coordinator evidence, plan/apply, target key sources, and replay-only
revalidation flow. No new standard recording is required for this rule.

Header-name matching is case-insensitive, so this protects `Authorization` as
well. Managed preflight, recording, and Replay create and reuse one
project key at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`. The ignored
directory is mode `0700` and the strict Base64-encoded 32-byte key is mode
`0600`. An explicitly supplied `TRAFFIC_E2E_ENCRYPTION_KEY_B64` is imported
only when the managed key is absent; a later mismatch is rejected.

The configured request header value is written only as versioned ciphertext in
`request.json`, dependency captures and stored HTTP request witnesses. Socket.IO
WebSocket upgrade headers use the same configured list. All other traffic data,
including interaction messages, request bodies, query strings and response
headers, is stored without additional encryption. Binary values retain explicit
Base64 encoding. Historical encrypted interactions and witnesses remain readable;
existing recordings are never rewritten. Witness checksums, session signatures
and encrypted signing-key envelopes retain their integrity role.
Request encryption takes precedence over any explicitly configured
redaction; response headers follow `redact_headers`. Missing,
invalid, or wrong managed key material blocks Replay. The system passes the key
only to Recorder processes; it is never injected into source,
target, Breeze, commands, or policy.

Run the service with:

```bash
cargo run -- diagnose recorder --config config/project.example.yaml
```

Start the standalone Source/Recorder service inside the Source environment:

```bash
traffic-e2e record --config /etc/traffic-e2e/project.yaml \
  --source-workdir /app --data-root /data/traffic-e2e \
  -- ./source --port 8080
```

There is no required project configuration or rewrite state. Without coordination,
record waits for direct HTTP requests. Add `--coordination redis`, a reachable
`--advertise-url` and `TRAFFIC_E2E_RECORDING_REDIS_URL` for gateway discovery and
reservation validation. Configured include/exclude rules remain effective;
default include scope allows all methods and paths. API selection belongs to ingress.

Each process creates one run. Stop normally to publish its final manifest. Place
completed runs and authorized private key access in the target's conventional
local layout; backend-rewrite consumes them directly and never executes capture.
See [recording.md](recording.md) for the complete deployment and storage contract.

The managed runtime publishes Recorder lifecycle state on a Unix socket and
waits through its internal process contract:

```bash
traffic-e2e internal recorder-run \
  --config config/project.example.yaml \
  --control-socket /run/traffic-e2e/recording.sock

traffic-e2e recording wait-listeners \
  --control-socket /run/traffic-e2e/recording.sock
# Start the source application after this succeeds.
traffic-e2e recording wait-ready \
  --control-socket /run/traffic-e2e/recording.sock
```

Run the wait commands from another process that can access the socket, such as
`docker exec` in the Recorder container. `wait-listeners` succeeds after
Recorder initialization and every enabled listener bind, so automation can
then prepare CA trust and start the source. `wait-ready` additionally requires
the configured HTTP gateway source readiness probe and the post-ready quiet
window. Every matching configured background Redis request slides the quiet
deadline by 15 seconds, bounded by 180 seconds from source readiness. Neither
command parses recorder configuration or probes listener ports.
`--timeout-seconds` defaults to `300`.

The internal Recorder process enables local DNS capture and fake-IP TCP/UDP
redirect by default inside its managed container. For focused low-level
development without those rules:

```bash
traffic-e2e diagnose recorder --config config/project.example.yaml
```

Managed recording uses `recorder.dns_mock.upstream_dns` from project YAML for
fake-DNS forwarding. Local interception redirects every port-53 query emitted
by a container process running as UID `998`; it has no destination DNS bypass.
Recorder itself runs as root, so its upstream queries are outside the fixed
owner scope.

DNS interception places fixed-UID queries and mock-listener replies in reserved
IPv4 conntrack zone `4053`, before connection tracking runs. Other processes,
including Recorder's real upstream queries, retain their ordinary zone. This
prevents a reused UDP source port from inheriting another UID's earlier NAT
decision and bypassing capture. Both installation and removal delete only the
reserved zone's entries, using native netlink requests with each entry's full
original tuple and ID. They never flush the namespace's connection table and
do not require the `conntrack` executable. Interception requires a concrete
IPv4 DNS listener address, such as `127.0.0.153`; `0.0.0.0` is rejected because
wildcard UDP replies can use a source IP incompatible with reverse NAT.
Kernel and iptables conntrack-zone support is required;
installation failures roll back instead of continuing without isolation.

The opt-in [DNS conntrack regression](../tests/manual/dns_conntrack/README.md)
exercises the actual interception commands in a disposable network namespace,
including source-port reuse, reply translation, listener changes and cleanup.

The local interception path limits DNS and fake-IP interception to numeric UID
`998`. Run the containerized source service as `998:998` so bootstrap and case
dependencies are not polluted by unrelated processes. Host account resolution
does not affect this contract. The owner scope cannot be overridden by CLI
options, environment variables, or recorder configuration.

Gateway recording is intentionally conservative. Until the configured ready
probe succeeds, matching traffic uses the configured fallback strategy and no
case is created. After ready, only one matched case can be active across the
HTTP and Motan gateways in the process; overlapping matching requests also use
fallback so dependencies are not shared across cases.

A matched request first reserves the single case slot without accepting
dependencies. Recorder reads the complete inbound request and persists
`admission.json` before activating dependency ownership and forwarding the
request to the source. Cancellation before activation releases the reservation
without creating a case or attributing process-level traffic to it.

The default `http_gateway.fallback_mode = "upstream"` forwards those requests
to `fallback_upstream`. For a fallback that always returns the same payload,
use an in-process fixed response instead of running another service:

```toml
[http_gateway]
fallback_mode = "fixed_response"

[http_gateway.fixed_response]
status = 200
content_type = "application/json"
headers = { x-recorder-fallback = "fixed" }
body = '{"code":"xxx","msg":"xxx"}'
```

`status` is required and must be a final HTTP status. Configure `201` only
when the response semantically represents resource creation. Fixed fallback
requests are not forwarded, do not create cases, and are not recorded as
business exchanges. Framing and hop-by-hop headers such as `content-length`,
`transfer-encoding`, and `connection` are managed by the gateway and cannot be
configured in `headers`.

Motan primary-case recording uses a separate gateway with the same single
active-case and dependency-drain lifecycle:

```bash
backend-rewrite config protocol enable motan \
  --gateway-port 18081
```

This typed update is for an already initialized repository. It changes only
the recorder file referenced by the project: `motan_gateway.listen` is set from
`--gateway-port`, while the existing `motan_gateway.matched_upstream` remains
the sole native Motan service endpoint. Configure that recorder endpoint before
enabling the gateway when the default is not correct. The gateway port must remain distinct from the native service port.
Repeating the same command returns `status: unchanged`; changing the gateway
port updates only owned keys and preserves the native endpoint, Motan rules,
and recorder comments. Its result uses `validation_status: not_run`:
configuration alone does not claim that real Motan traffic has been validated.
Set `motan_gateway.enabled = false` to keep HTTP-only recording temporarily.

```toml
[motan_gateway]
enabled = true
listen = "0.0.0.0:18081"
matched_upstream = "127.0.0.1:8002"
max_cases_per_api = 100
rules = []
```

An empty `rules` array accepts every identified non-heartbeat Motan API. To
restrict recording, replace `rules = []` with one or more rule tables:

```toml
[[motan_gateway.rules]]
name = "record-alchemy"
apis = ["com.weibo.abtest.traffic.rpc.AlchemyRpcService#getConfig(java.lang.String)"]
```

`apis` uses the same canonical identity emitted by `motan-replay`. Add
`groups = ["abtest"]` only when the same API must be distinguished by Motan
service group.

Run `motan-replay --input-raw :8080 --output-rpc <recorder-ip>:18081` in the
host or network namespace that can observe the source Motan traffic. During a
local preflight `<recorder-ip>` is `127.0.0.1`; when capture runs remotely, use
the address of the host running preflight. The preflight prompt returns this
command instead of fabricating RPC argument values.
The gateway decodes Motan1 and Motan2 through the Breeze Motan Git dependency
pinned to `v0.0.3`. A matched request is forwarded to `matched_upstream`, and
its raw protocol request and response are published as one primary case.
Heartbeats, unmatched calls, overlapping calls while another case is active,
and calls after the per-API limit receive a protocol-valid empty success
response without reaching the source. Motan2 one-way calls do not receive a
response, as required by the protocol.

Every published HTTP or Motan primary case contains a protocol-neutral
`case.json` with `version`, `kind`, `api_key`, `display_name`, and an explicit
`source_binding`. The orchestration workflow uses the common identity; only
the source and driver adapters branch by protocol. Both kinds share a recording
run directory and `dependencies.jsonl`. Motan API directories include a stable
identity hash so long Java signatures remain filesystem-safe.

The HTTP gateway also limits successfully published cases per resolved case
pattern within one recorder run. The default is
`http_gateway.per_api_case_limits.default = 100`. Static paths are counted
independently by exact URI path; a URI matched by `case_path_patterns` is
counted under that configured pattern. Pattern-specific limits use exact keys:

```toml
[http_gateway.per_api_case_limits]
default = 100

[http_gateway.per_api_case_limits.overrides]
"/api/resource/token" = 25
"/api/namespaces/**" = 50
```

Dynamic override keys must already exist in the global HTTP
`case_path_patterns`. Once the published count reaches the effective limit,
later matching requests use the configured fallback strategy without creating
a case. Failed cases do not consume the limit, and restarting Recorder starts
a new run with fresh counts.

HTTP responses forward incrementally, and case-owned dependency collection and
publication continue independently after response completion. Primary HTTP
streams use [case-owned dependency observation](recording-stream-dependency-tail.md)
after normal EOF or client cancellation. Matching API-origin
rules enable [selected dependency observation](recording-api-origin-tail.md),
with a sliding idle interval and an absolute request deadline. Other finite requests
continue accepting new case dependencies for the fixed
`recording.case_dependency_post_response_window_ms` interval. This captures
synchronous server-side after-hooks that start dependencies only after writing
the response; set it to `0` when the target completes all relevant work before
the response. When the interval ends, Recorder closes dependency admission so
continuous case-external traffic cannot extend the case, then waits only for
already accepted in-flight dependencies to complete. In-flight MySQL queries
retain their original case ownership through the semantic exchange. If those
dependencies do not complete within
`recording.case_dependency_drain_timeout_ms` after admission closes, Recorder
fails the case instead of publishing incomplete dependency evidence. Matching
requests continue to use the fallback upstream while the previous case drains.

If a matched HTTP gateway request reaches `http_gateway.request_timeout_ms`
while waiting for response headers, its client receives HTTP 504 and the case
enters timeout recovery. If headers have already been forwarded, response-body
timeout terminates the downstream body while retaining its original status.
Recorder retains the
upstream HTTP operation and the active-case slot, then shuts down the dependency
connections open at that moment. This covers MySQL (including TLS), Redis,
Memcached, Kafka, Motan, HTTP/HTTPS proxy connections and raw TCP forwarding.
Primary HTTP requests, listeners, readiness and control connections are excluded.
Each case triggers only one reset; later reconnects remain attached to that case
and are not affected by a delayed second reset.

Query-level process-owned rules cannot prove exclusive ownership of shared pool
connections. These connections are therefore included in recovery, with protocol
counts, shutdown errors and `unproven_connection_scope` recorded in the failed
case's `timeout-recovery.json`. Their normal process-owned event attribution is
preserved. Recorder waits for the retained Source HTTP response to finish, then
for in-flight dependencies and an uninterrupted quiet interval of
`recording.case_dependency_post_response_window_ms`, bounded by
`recording.case_dependency_drain_timeout_ms`. Only then can a new case be admitted.
The timed-out case remains failed; late dependencies never make it replayable.

If Source never completes, the active slot stays occupied until recording
shutdown. If its HTTP transport fails, recovery is cancelled/panics, or dependency
drain exceeds its deadline, new case admission stops for the run because Source
completion/isolation cannot be established. Old recordings remain immutable;
fixing timeout isolation requires recording new evidence.

Standalone `traffic-e2e record` handles normal SIGTERM/SIGINT by closing fresh
case admission and withdrawing discovery, then retaining Source and existing
sessions for at most 60 seconds. This wait includes dependency tails and case
publication; existing stream limits still run and an isolation failure stops
Source promptly. An incomplete uncommitted case receives
`shutdown_case_drain_timeout`, while its earlier independent failure is retained.
`recording-shutdown.json` records the decision before Source termination. Process
termination and evidence cleanup retain separate budgets. See
[normal recording shutdown](recording.md).

On low-level Recorder shutdown, case matching enters a quiescing phase before run
finalization. New matching requests use the fallback upstream while the current
case is allowed to finish for up to
`recording.shutdown_case_drain_timeout_ms`. If the timeout expires, the
remaining staging case is retained under `failed/` with
`recording_incomplete_at_shutdown`.

`recording.max_body_bytes` is the system-wide body limit. It bounds recorded wire bodies and dependency captures, and
managed replay target responses.
`recording.max_decoded_body_bytes` may independently allow a larger decoded
HTTP case body, such as compressed JSON; when omitted it inherits
`max_body_bytes`. Content decoding reads at most the decoded limit plus one
byte, so highly compressed input cannot cause unbounded decompression. Both
effective defaults are 64 MiB.

### Rewriting HTTP Responses

HTTP response rewriting is an opt-in recording feature for responses that
publish a later connection target. The `pluto-eci-kubeconfig` built-in plugin
rewrites the Kubernetes API server in Pluto ECI's
`user_config` JSON response from an IPv4 address to a synthetic `.test` domain.
The `vintage-naming` plugin rewrites legacy Motan node addresses published by
Vintage naming responses. The `vintage-cache-config` plugin rewrites cache
node addresses published inside Vintage `/1/config/service` responses.

HTTP URL acquisition is a `capture_http_response` native effect in the unified
policy named by `project.policy`:

```yaml
format: traffic-policy/v3
rules:
  - id: sandbox-url
    match: {}
    effect:
      kind: capture_http_response
      authorities: [cs.wegent.intra.demo.test]
      methods: [GET]
      path: {kind: pattern, value: '/executor-manager/sandboxes/*'}
      status_codes: [200]
      content_types: [application/json]
      contract:
        kind: urls
        pointers:
          - contract: /base_url
            proof: {source: 'src/client:sandbox', fact: 'The client follows this URL.'}
    proof: {source: 'src/client:sandbox', fact: 'Source returns a dynamic sandbox endpoint.'}
```

Every pointer has an explicit Source fact. Built-in plugins use the same effect
with their typed plugin contract. Rules load once at recording startup; changes
require a fresh recording to obtain the downstream exchanges. See
[unified rules](unified-rule-contracts.md).

The typed `path` selector matches the request path excluding its query.
Whole-segment `*` matches exactly one nonempty level; terminal `**` matches one or more levels.
Thus `/sandboxes/*` matches `/sandboxes/123`, not `/sandboxes/123/files` or
`/sandboxes/`. The static recorder configuration retains exact `path` selectors
for legacy plugins. Pointers use JSON Pointer syntax (`~0` for `~`, `~1`
for `/`, numeric array indices); pointer wildcards are not supported.

By default generic rules apply to successful HTTP responses with JSON media
types (`application/json` or `+json`). Selected missing or null values are
skipped, and URL hostnames stay unchanged. IPv4 HTTP(S) URL hosts become stable
synthetic names such as `http-10-36-14-118-8080.trp.test`. The original scheme,
explicit port, credentials, path, query and fragment remain intact. Non-string,
invalid, unsupported IPv6, or ambiguous URL values fail the matched exchange.
The synthetic route forwards to the original IP and port and restores the
upstream HTTP authority; HTTPS retains strict upstream certificate validation.
The source client must trust the Recorder CA for intercepted HTTPS as usual.
The rewritten response and discovered routes are recorded together, and Replay
restores their reserved fake IPs before replaying subsequent HTTP(S) exchanges.

For Pluto ECI, that synthetic domain is registered in the recorder's fake-DNS
registry and routed to a local `kubectl proxy`, allowing the later HTTPS traffic
to pass through the TCP gateway and be recorded. The rewritten kubeconfig uses
HTTPS and replaces its cluster CA with the Recorder CA so client-go retains the
TLS credentials and trusts the Recorder-generated certificate for the
synthetic domain. The original kubeconfig, including its original CA and
Kubernetes server IP, is passed unchanged to the managed `kubectl proxy`.

The rewrite rule reads the request authority and full path from configuration.
Its `path` value includes the Pluto ECI cluster ID and is matched exactly, not
as a prefix. The plugin owns the fixed synthetic domain
`k8s-c142fe56e07d04a749c1630fb5f1b680b.pluto-eci.trp.test`. Configure the
`kubectl_binary` executable and an unused IPv4 loopback `proxy_listen` address.

Recorder manages the proxy lifecycle; do not start `kubectl proxy` separately.
When a response matches, Recorder writes its original kubeconfig to a unique
owner-only (`0600`) temporary file, starts `kubectl proxy`, waits for the
configured TCP address to accept connections, and only then registers the DNS
alias and returns the rewritten response. An unchanged kubeconfig reuses the
running process; changed credentials restart it. Recorder terminates the child
and removes its temporary file during replacement or shutdown. Kubeconfig
contents and paths are never logged or added as separate recording events.
The fake-IP gateway terminates the synthetic HTTPS connection and forwards the
decrypted request over plain HTTP to the managed proxy; the proxy independently
uses the original kubeconfig for HTTPS and client authentication to Kubernetes.

For Vintage, configure an exact `/naming/service` rule. By default it matches
every service and cluster; optional `services` and `clusters` filters can
intentionally limit interception to a known subset. The plugin handles
`lookup` and `lookupforupdate`, replacing every IPv4 `host` in every `nodes`
array with a stable fake IP while preserving the node port and all unknown
response fields. It deliberately leaves `getsign` unchanged, so recording does
not alter the SDK's local-cache or snapshot decisions. Empty filters match
every service or cluster.

Vintage v1 reports application failures, including a missing service, as HTTP
200 responses whose outer `code` is not `200`. These responses publish no
connection targets and pass through unchanged so the SDK retains its normal
fallback behavior. A successful outer response that is malformed or contains
an unsafe node address still fails the exchange instead of leaking an
unrecorded target.

Each discovered original IPv4 address receives one stable
`fake-node-<address>.trp.test` alias. The name deliberately identifies a
replay-only fake node without claiming that the node belongs to Vintage. The
rewritten HTTP exchange records the alias, original IP, fake IP, port, service,
and cluster. Replay reserves the
same fake IP before assigning any other target, so an SDK that caches the
recorded naming response still connects to the Motan replay endpoint. A fake-IP
collision or an address outside the configured replay CIDR fails replay
startup instead of silently routing to a different target.

For Vintage cache configuration, configure an exact `/1/config/service` rule.
The plugin handles `action=lookup` responses whose outer `body.nodes[].value`
fields contain YAML. Within each top-level cache resource, it rewrites every
`IPv4:port` scalar below `master`, `slave`, `master_l1`, and `slave_l1`,
including nested lists, while preserving all other YAML values. The response
rewrite only discovers and reserves addresses; normal Recorder protocol
detection classifies later Redis or Memcached traffic, and replay resolves an
address's protocol from the recorded dependency exchanges or, if necessary,
from the incoming connection.

Matched response bodies with `gzip`, `x-gzip`, or `deflate` content encoding
are decoded within `recording.max_decoded_body_bytes` before rewriting. The
rewritten response is returned with identity encoding and corrected entity
headers. Unsupported encodings or decoded bodies over the configured limit
fail the exchange rather than returning an unmodified address-bearing
response.

Enable the example `[http_response_rewrite]` configuration in
`config/project.example.yaml` and ensure the configured `kubectl_binary` is
installed. `traffic-e2e record` checks executables required by enabled rewrite
plugins immediately after loading the configuration, so a missing `kubectl`
is reported before Recorder changes local interception state. The rewrite
feature requires `dns_mock`, `tcp_gateway`, and
`tcp_gateway.record_http` to be enabled. The configured `proxy_listen` address
must not already be occupied.

The MITM CA certificate and private key configured under `[tls]` are a pair.
When both files are absent, `traffic-e2e record` reports that Recorder will
generate them automatically. If only one exists, startup stops with recovery
guidance instead of replacing the remaining file and silently changing the CA.

Rules are evaluated in configuration order. A matching legacy plugin retains
first-match behavior; when the first match is a generic pointer rule, matching
generic rules contribute their pointers to one rewrite. Parse or rewrite
failures fail the HTTP exchange and active case, so an original IP-bearing
response is never silently published. On
success, body-dependent headers such as `Content-Length`, `ETag`, and `Digest`
are normalized, and the rewritten response is what the recorder stores.

Plugins are compiled into the binary. They receive request/response metadata
and the complete decoded body, then return a rewritten body plus any synthetic
route and managed local-process requirement discovered from the response. The
Recorder core owns process and secret-file lifecycle. Adding another plugin
therefore requires a code change and rebuild; no dynamic `.so` loading is
involved.

For replay-mode development:

```bash
cargo install --path .
traffic-e2e --help
traffic-e2e diagnose --help
traffic-e2e replay path/to/case-dir
traffic-e2e replay --no-intercept path/to/case-dir
```

Target-specific dynamic UUID, timestamp, and signed-query matching belongs in
a source-controlled `.traffic-e2e/policy.yaml`, not product code or recorded fixture
overrides. Initialize it once and load it explicitly:

```bash
traffic-e2e config init --target-root ../target \
  --source-pod <pod> --namespace <namespace>
traffic-e2e replay --policy ../target/.traffic-e2e/policy.yaml path/to/case-dir
```

See [unified-rule-contracts.md](unified-rule-contracts.md) for the policy schemas,
assertion-only `expected-response.json` contract, dependency rule scoping,
runner-owned generated-scalar and unordered response fields, and dirty-evidence
behavior.

Process-owned asynchronous HTTP work uses
`process_dependencies.tasks.<actual-Source-task-name>.requests`, with explicit
HTTP host, method/path scope and independent Source proof. A task can group
requests across protocols. Finite initialization reads use `localcache.requests`. Unbounded unused-host
exemptions are retired. Finite sharing does not authorize unused work. Use the
same unified rule transaction described below; preserve target initialization,
refresh and readiness behavior when the dependency drives business state.

When a response-driving source hostname is absent from dependency evidence but
occurs in the configured Breeze snapshot, preview and enable its logical
resource instead of listing dynamic ports or backend domains:

```bash
traffic-e2e config recorder plan breeze-resource-capture \
  --target-root ../target \
  --resource usercounter \
  --source-revision <immutable-source-image-revision> \
  --evidence 'src/UserCounter.java:load uses usercounter'

traffic-e2e config recorder apply breeze-resource-capture \
  --target-root ../target \
  --resource usercounter \
  --source-revision <immutable-source-image-revision> \
  --evidence 'src/UserCounter.java:load uses usercounter'
```

The short resource name must resolve uniquely. The plan reports and persists
the exact descriptor identity, refuses IP-only resources because DNS bypass
does not include literal IPs, and identifies resources sharing captured
domains. Apply is add-only, atomic, and stale-safe. Start a new recording after
the change; existing artifacts remain unchanged.

For an active backend rewrite, the AI-facing coordinator accepts the
source-visible backend endpoint instead of a Breeze resource selector:

```bash
backend-rewrite --target-root ../target route \
  --cause missing-recorded-resource \
  --evidence-id <current-evidence-id> \
  --endpoint counter.example.com:9332 \
  --source-ref 'src/UserCounter.java:load reads the counter backend'

backend-rewrite --target-root ../target recorder-capture apply \
  <returned-plan-id>
```

The coordinator reverse-resolves a unique canonical resource from configured
snapshots, using a source-proven port to disambiguate a shared domain when
needed. It applies the capture rule immediately and parks only the affected API.
Other API work continues. Once no API remains runnable, all accumulated rules
require one full-scope externally produced standard batch; callers must not
produce a separate recording per rule.

Pass the recorder config for direct replay:

```bash
traffic-e2e replay \
  --policy ../target/.traffic-e2e/policy.yaml \
  --recorder-config ../target/.traffic-e2e/project.yaml \
  path/to/case-dir
```

Replay reads the global HTTP policy once at startup. A case-owned recorded HTTP exchange for
an allowed host that remains unconsumed is moved from
`unused_case_http_exchanges` to
`allowed_unused_case_http_exchanges`, which is retained as a non-blocking
diagnostic. A target request that is unmatched or unsupported remains dirty,
including requests sent to an allowed host. Restart replay after applying a
new host; running sessions do not hot-reload recorder configuration.

`traffic-e2e replay` also uses the fixed numeric UID `998` owner filter. Run the
containerized dependency-producing target process as `998:998`. Build steps,
replay itself, and replay-control commands remain under the developer account
or root; replay startup rejects UID `998` as its controller identity. If the
target cannot run as `998:998`, intercepted replay is blocked; do not widen the
owner scope to the login user or all local users.

For a prebuilt in-process E2E command, use `traffic-e2e target exec` rather than
granting the fixed user access to the workspace or build cache:

```bash
traffic-e2e target exec \
  --env-file .traffic-e2e/local/target-exec/.env \
  --copy-env APP_CONFIG=.traffic-e2e/local/target-exec/config/application.yaml \
  --copy-env REPLAY_CA=path/to/replay-ca.pem \
  --path-env CASE_DIR=path/to/readable/case-group \
  --write-dir logs \
  -- path/to/prebuilt-e2e --case-id <case-id>
```

The caller must have non-interactive sudo permission for staging ownership and
for applying the fixed numeric identity `998:998`; host account lookup is not
used. Copied inputs are read-only to the target; the temporary work tree is
writable and removed after execution.
Environment files use dotenv syntax. Later files override earlier files, and
same-named caller environment values or explicit `--env` assignments override
file values. Reserved identity, path, shell-hook, and replay-session variables
are rejected.
`--path-env` does not widen source permissions and fails when the fixed user
cannot already read the path. The
helper clears inherited proxy and shell-hook variables, verifies the effective
UID, and never accepts a user or UID option. Keep replay lifecycle commands
outside the target process.

`.traffic-e2e/local/startup/` is the managed, input-only snapshot for
source-proven target startup inputs. Its name or Git-ignore status does not
authorize generating content from a remote response, recording, log, debug
output, or diagnostic.

For a case collection, start one replay session and control active case
ownership through the CLI:

```bash
traffic-e2e replay path/to/recordings/<run-id>/apis/<api-directory>
traffic-e2e replay path/to/recordings/<run-id>
traffic-e2e replay --api 'GET /api/widgets/*' path/to/recordings/<run-id>
traffic-e2e replay --case-id <case-id> path/to/recordings/<run-id>
traffic-e2e diagnose replay-control wait-ready
traffic-e2e diagnose replay-control cases
traffic-e2e diagnose replay-control begin <case-id>
traffic-e2e diagnose replay-control end <case-id> --fail-on-dirty
traffic-e2e diagnose replay-control finalize --fail-on-dirty --fail-on-incomplete
```

`--api` resolves the complete immutable case set from recorded request methods
and paths. It is the managed focused-Replay selector and may cover more than one
recording member directory. `--case-id` remains available for explicit
low-level subsets and cannot be combined with `--api`.

Successful `finalize` writes a version-six report with its session id,
timestamps, exact selected case ids, and `finalized: true`, then stops replay.
The command returns success only after atomically publishing that exact report;
a report-write failure leaves the session open for retry. If finalization
fails, preserve the diagnostic report and use
`traffic-e2e diagnose replay-control stop` only for cleanup. Default replay
reports are retained under a unique
`.replay/sessions/<attempt>/replay-report.json` directory.
Replay keeps protocol evidence in memory and publishes `replay-report.json`
only during successful finalization. The diagnostic `report` control command
can build the current report on demand without publishing an intermediate
artifact. The session file is a small process-discovery document; detailed
case status remains available through the control socket. Version six keeps
exact success counters while retaining at most `success_detail_limit`
successful event details per category and executed case; unscoped startup
traffic has its own bounded scope. Successful details carry a zero-based
`target_event_index` within that case and category.
Redis reports with `redis.target_event_index_scope: case_request_admission`
instead allocate this index when a command enters replay matching, before
selection or response delivery. `matched`, `unmatched`, parsed `unsupported`
commands and request-associated delivery failures share that case-local index;
each case and the unscoped startup inventory starts at zero. Successful local
handshakes, unsolicited Pub/Sub pushes and unparsed bytes do not receive an
index. A failed recorded handshake does. Concurrent response completion and
the successful-detail cap never renumber requests. The bounded dependency
query preserves the failed request's index in its actual signature, while its
`target_matches` retain the same arrival indices and the existing truncation
indicator. Reports without this scope marker retain their historical success
completion indices; they cannot reconstruct failed-request arrival order and
require fresh Replay for this diagnostic.
Dirty event details remain complete, and unused MySQL entries reference bounded SQL
previews plus fingerprints instead of copying arbitrarily large SQL strings.
When a SELECT exceeds the 256-character prefix, `sql_summary.select_body` adds
an independently bounded 256-character excerpt beginning at its outer FROM.
Its own `truncated` flag covers the predicates, ordering, pagination and locks
in that excerpt. Quoted text, comments and nested SELECTs cannot select a false
outer FROM. Statements over 64 KiB, compound SELECTs and unsupported lexical
forms retain the original prefix/fingerprint without an inferred body.
Rejected Target queries derive the same summary from their original SQL before
the bounded dependency signature truncates its `sql` field. Both text and
prepared query rejections retain the outer clauses without exposing prepared
parameter values. Historical sidecars without the summary require fresh Replay;
the original clauses cannot be inferred from an already truncated prefix.
The bounded dependency query preserves this summary together with `index`,
`connection_id` and `query_sequence`, so an implementer can locate the original
semantic exchange when either excerpt is truncated. These are diagnostic views,
not matching evidence. `row_count` is present only for complete, untruncated,
well-formed result sets; zero is an observed empty result, while omission means
the exact count is unavailable. Lazy result storage retains the count without
loading or publishing result cells.
The report's `unrecorded_targets` field contains exact `host:port` targets to
which the target sent payload even though they were not accessed during
recording. DNS lookup and TCP connection establishment alone do not add an
event. Any reported payload attempt is dirty, is counted under aggregate
`network` events, and is clustered as `network/unrecorded_endpoint` in
dependency evidence.

Replay also samples the existing fixed-UID REJECT packet counters at each
controlled case `begin` and `end`. This requires no NFLOG or packet observer.
`egress_rejections` retains the sampled time window and packet delta; it has no
IP address, source classification, or per-event timestamp. Counts include
retries and background traffic from the same UID. Failed reads or changed/reset
rules yield `rejected_packets: null`, never a fabricated zero. `--no-intercept`
does not sample firewall counters. Standard recording does not install Replay's
REJECT policy, so successful direct-IP traffic during recording is not detected
by this diagnostic.

These counters do not affect dirty, response, or completion gates. Only when
responses differ or dependencies are dirty does `run-api` expose the auxiliary
`diagnosis.egress_rejections`; backend-rewrite exposes it through the issue
overview's `facts.issue.egress_rejections`. The `dirty_clusters` evidence response adds
the same bounded observations. Positive counts add a `rule_hints` entry with
`recorder-capture plan-http-response --help`; they do not by themselves produce
an applicable rule or establish causality.

After source investigation establishes a missing IP dependency, the coordinator
can run `route --cause unrecorded-ip --endpoint IP:PORT --case-id CASE
--ip-origin http-response --evidence-id CURRENT --source-ref SOURCE_PROOF`.
`unknown`, `static`, and `other` origins return the relevant investigation
requirements. The route is a preflight, with `accepted: false`, and leaves the
API out of system repair. Its `ip_capture` evidence matches reported endpoints
to exact recorded JSON responses and returns planner commands.
`recorder-capture plan-http-response` without `--pattern-checked` returns
`status: path_pattern_review_required`, the current path, and all existing
rules with the same authority, method and pointer. The engine does not
filter by path similarity or infer dynamic IDs. Review source path construction
even for the first rule; choose an exact path or wildcard pattern and check
whether existing paths should be consolidated. This response has no `plan_id`
or apply command, and generated commands do not prefill the confirmation flag.
Rerun with the selected `--path-pattern`, `--pattern-checked`, and a brief
`--source-evidence` note (or `BACKEND_REWRITE_SOURCE_EVIDENCE`). A short statement
such as `sandbox_id varies; use * and consume base_url` is enough;
no structured proof format is required.

The checked response has `status: planned` and the usual plan/apply fields.
The plan reuses an existing covering rule or consolidates fully covered managed
rules with identical selectors and response filters. Its diff and
`traffic_e2e_report.replaced_rules` identify every replaced rule. Uncovered
paths, other selectors and project-owned static rules are retained. Multiple path entries
share one domain group; consolidation uses selectors and full path coverage
instead of names. Policy changes after planning and
old HTTP plans lacking the review confirmation cannot be applied.
Inspect the plan and execute
its `next_command` apply; status reconstructs a pending apply. Apply persists
the capture rule and parks the API for consolidated fresh recording. A pending
capture plan or unresolved supported capture candidate blocks capability-gap
submission. If a rule is already configured, inspect whether fresh recording
loaded it and cite the remaining engine failure rather than repeatedly adding
rules. Historical recordings are never edited.

For a collection, multi-case selection, or multiple sessions, generate one
deterministic coverage and dependency summary from the recording source root.
Select the exact final case and session ids so older attempts cannot satisfy the
gate:

```bash
traffic-e2e diagnose replay-aggregate \
  --case-source recordings/<run-id> \
  --case-id <case-id> \
  --session-id <session-id> \
  --output aggregate-report.json \
  --fail-on-incomplete \
  --fail-on-dirty
```

Repeat `--case-id` and `--session-id` for an exact set. Without a case filter,
all published cases under the source are in scope. If retained attempts report
the same case and no exact session selection resolves them, aggregation fails
instead of guessing which run is final. The aggregate command does not parse
target-project test output or classify why an unreported case was skipped.

`traffic-e2e diagnose replay-control` directly uses the Rust-owned control
protocol and Unix socket client; no shell facade owns JSON or socket logic.

Before migrating a dynamic API from a collection, persist its exact immutable
case grouping outside the recording source:

```bash
traffic-e2e diagnose case-group ensure \
  --case-source /path/to/recordings/<run-id> \
  --case-dir /path/to/recordings/<run-id>/apis/<api-directory> \
  --method GET \
  --source-route '/api/users/:id' \
  --pattern '/api/users/*' \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --output ../target/.traffic-e2e/local/run-reports/<run-id>-case-groups.json \
  --recorder-config ../target/.traffic-e2e/project.yaml
```

For an exact static route, omit `--pattern` and `--recorder-config`.
The command validates every case in the current directory and returns
`already_canonical`. A dynamic first call returns `created`; a repeat from any
member directory returns `already_grouped`. Dynamic groups are manifest-backed
and do not create or move a group directory. The output path must remain outside
the canonical case source. Mixed directories, duplicate case ids, overlapping
groups, a changed source revision, or a changed case inventory fail the command.

Replay-time route discovery can produce safe `case_path_patterns` feedback for
a target repository. Apply focused, add-only feedback through the managed
configuration interface:

```bash
traffic-e2e config recorder apply case-path-patterns \
  --target-root ../target \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'
```

The command updates the global HTTP policy, sorts and deduplicates patterns,
validates the complete recorder config, and replaces the source traffic policy file
atomically. Every authority mode is add-only: a full case source or full replay
does not authorize deleting patterns that were not observed.

Delete only a specifically proven-invalid entry already inside the AI-managed
block. Name it explicitly, attach single-line source-route evidence, and include
`--allow-delete`:

```bash
traffic-e2e config recorder apply case-path-patterns \
  --target-root ../target \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/cases \
  --remove-incorrect-pattern '/api/incorrect/*' \
  --correction-evidence 'router.go@<revision>: route is static /api/incorrect' \
  --allow-delete
```

Omission from recordings, including an authoritative or full case source, is
never correction evidence. Every named pattern must appear in the internally
computed removal plan before deletion. The command always emits JSON and never
modifies recordings or existing case directories.

A focused action with no `--pattern` is valid and returns
`no_candidates: true` with no config diff.

Select Source recording traffic at ingress. `record` preserves configured
include/exclude rules. In Redis coordination mode, `--api-policy` publishes
gateway API selection and a shared per-API admission limit at startup; it does
not change Recorder capture rules. See [recording](recording.md).

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

## Migration E2E Runner

Use the rewrite coordinator as the normal AI-facing migration command. It
keeps engine-managed state under `.traffic-e2e/local/runtime/` and exposes one
active issue. Coordinator APIs are the primary interface:

```bash
backend-rewrite next
# After recording, select one canonical API route:
backend-rewrite next --api '/api/widgets/*' \
  --source-route '/api/widgets/:id'
backend-rewrite status
backend-rewrite status --api '/api/widgets/*'
backend-rewrite inventory
backend-rewrite evidence <query-id>
BACKEND_REWRITE_CASE_PATH_PATTERNS_JSON='["/api/tasks/*/tree"]' \
  backend-rewrite case-pattern apply <batch-id>
# Provide finalized external recordings in .traffic-e2e/local/artifacts/recordings/<run-id>/.
# Optionally select recording_run_id in .traffic-e2e/regression.yaml, then:
backend-rewrite next
backend-rewrite repair verify <repair-id>
BACKEND_REWRITE_SUBAGENT_HANDLE='<replacement-handle>' \
  backend-rewrite worker transfer --previous-agent-handle '<old-handle>' \
  --reason 'stored handle is unavailable after session replacement' \
  --approve-ownership-transfer
backend-rewrite verification request \
  --api '/api/widgets/*' \
  --reason 'shared response mapper changed'
```

Rewrite action schema v35 always returns `action.kind`, `action.summary`,
`action.details`, and `action.commands`. Variant facts exist only under
`details`; executable argv exist only under coordinator command roles such as
`execute`, `status`, `advance`, `recover`, `apply`, and `acceptance`.
Unscoped and scoped `status` and `next` expose scheduling state and short issue
summaries. They contain neither diagnostics nor an evidence command.

The coordinator dispatches the implementation-worker role, exact API scope, canonical target root, and absolute assigned worktree.
Workers fetch their own current context and evidence:

```bash
backend-rewrite --target-root /path/to/target evidence --api '/api/widgets/*'
```

Exactly one selector or opaque query ID is required. These read-only selectors
resolve the requested item without switching the active API or advancing state,
including parked APIs. Unknown items and items with no current issue fail
explicitly. Dispatch confirmation still gates evidence; workers wait for the
coordinator to confirm and retry the same query if they start too early.
Evidence schema v4 overviews include `context` with canonical target root,
workflow/recording identity, revision, and the worker's
binding/dispatch identity. `facts.issue` retains the complete bounded issue.
API overviews supply further exact commands in `queries`.
Workers retain the initial identity in their returned handoff along with
supporting proof, tests, commit/patch and necessary coordinator inputs. The
coordinator gets current acceptance commands from the engine; workers do not
need an action JSON or evidence command in their assignment.

Relevant API overviews include a `source_process_traffic` query for bounded
bootstrap, configured `process_owned`, and Redis snapshot triage. Existing
`evidence <query-id>` calls remain supported for overview/detail queries and
pagination. Query identities follow the owning item across concurrent scheduling
and reject replaced evidence. Current context metadata is excluded from evidence
hashing so unrelated workflow revisions do not invalidate diagnostic evidence.
The overview does not authorize rule planning; use the applicable planner
returned by a specific evidence query. A current overview supplied to `rule plan`
returns its exact supported detail-query command, without calling it stale or
requiring another Replay or dispatch. Use the detail response's evidence ID;
replaced issue evidence still rejects as stale.
Schema v24 added top-level `pending`, counting only coordinator actions executable
now. Inventory summaries rename their old `pending` count to `unverified`.
Persisted state uses version 2 with the dependency-review ledger, optional worker
observations and a worker-event revision cursor. Version 1 cannot resume under
the current engine; an explicitly authorized purpose confirmation can archive it
and start a fresh workflow. Update AI skills with the binary when adopting this schema.
Schema v25 keeps only workflow identity and revision in scheduling responses;
`inventory` retains the full workflow metadata. Global and scoped status share
the same global pending projection. System-repair actions identify their API:
unchanged repairs wait, while a changed acceptance revision schedules repair
verification before worker dispatch. Accepted replay repairs authorize the same
API's replay without requiring another worker handoff. `worker confirm` records
binding delivery only; explicit coordinator reports supply running/queued state.
The engine does not query an external AI runtime. Running/queued reports expire
60 minutes after the most recent explicit report; another running/queued report
resets that interval. Handoff-ready and integrated observations do not expire
while awaiting integration or verification. Missing or legacy unclassified
observations require a fresh report.
Coordinator sessions must actually invoke the task runtime's list/status tools
for all outstanding worker assignments on resume, before waiting on agents,
after every bounded wait, and on required status checks. Prefer a bulk listing
such as Claude Code's `ListAgents` (the tool corresponding to `/list-agents`),
then query omitted or unclassified tasks by their actual runtime IDs. Neither
engine inventory, a business task list, cached reports, nor absent stop events
establishes runtime activity. Retain the query call/result reference with the
assignments. The sixty-minute expiry does not waive these checks; the CLI cannot
independently verify that a coordinator invoked an external runtime tool.
Start and resume with `backend-rewrite status`; an initialized project without a
workflow returns an executable initialization action with `pending: 1`.
Status does not duplicate an `active_issue` or publish an unconditional
top-level `next`. Every returned command contains a canonical `cwd` plus exact
argv. The argv includes the canonical absolute `--target-root`, so executing a
read-only evidence command from an isolated worker worktree still addresses the
single coordinator state.

The binary writes one compact JSON object per command by default. Pass global
`--pretty` only for interactive human inspection. This keeps automation output
atomic and avoids reconstructing one response with `head` and `tail`.

Legacy per-API worker transfer is an exceptional compare-and-swap ownership
change for workflows without an implementer pool. New workflows use the fixed
slot protocol below. It is
valid for an unresolved `implementation_required` API
work item, including a parked item, and requires its
current `--previous-agent-handle`, a replacement `--agent-handle`, a bounded
reason, and either of two equal authorization bases: `user_approved` or
`runtime_api_confirmed_missing`. The replacement handle must not own another work
item in the workflow. A successful transfer preserves the worktree, records the
prior handle fingerprint and reason, changes the binding generation, and
issues a new dispatch, and atomically confirms the replacement. A handle that
no longer owns the work cannot replace its newer owner. Old delivery reports
retain the previous dispatch and cannot advance the replacement.

For `user_approved`, use `--approve-ownership-transfer`. An earlier explicit
user authorization covering this transfer remains valid. For
`runtime_api_confirmed_missing`, supply the actual queried API/tool or command
and its query time together; no evidence file or additional user approval is needed:

```bash
backend-rewrite worker transfer --previous-agent-handle OLD --agent-handle NEW \
  --reason 'runtime query confirmed the original worker no longer exists' \
  --runtime-query-command 'ListAgents' \
  --runtime-query-at '<actual query time in RFC 3339, including timezone>'
```

The coordinator must actually execute the runtime API/tool or supported command
before creating a replacement, with query coverage sufficient to establish that
the exact previous worker no longer exists and cannot be resumed. `ListAgents`,
its supported `/list-agents` entrypoint, and equivalent runtime status APIs are
examples, not an allowlist. Session restart, cached observations, incomplete
listings, failed queries and ended-but-resumable tasks are insufficient. Obtain
an exact per-task query when list scope cannot establish absence. Explicit user
cancellation still takes precedence.

The approval flag and runtime-query parameters are mutually exclusive. The query
command must be a nonempty single line of at most 4096 bytes; query time must be
RFC 3339 with a timezone (e.g. `2026-09-12T12:00:00+08:00`). Supplying them attests
that the query actually confirmed the previous worker missing. The engine checks
input completeness and time format, then stores `runtime_api_confirmed_missing`
and `query.api_or_command` / `query.queried_at` in the transfer record's
`authorization` field. It neither executes the recorded command nor independently
proves the query ran. Historical records lacking `authorization` deserialize as
`user_approved`, matching the requirement enforced when they were written.

`next` consumes one completed external standard batch from the conventional
recording directory. It retains that batch across Replay retries. Missing input
returns `input_required` with `recording_evidence_required`, the required
directory and bounded candidate/rejection diagnostics under
`action.details.recording_input_diagnosis`; there is no capture execution command.
A selected unfinished manifest returns `recording_in_progress` and a wait command.
External recording ownership remains outside rewrite, including on recovery.
For deterministic selection use local `recording_run_id`. Runs are never copied, split or merged
into fabricated capture batches. The coordinator derives its stable API inventory
from the adopted cases.
`next` and `status` expose only its
bounded summary (`total`, `completed`, `unverified`, `active`, `implementation_required`,
`system_repair_required`, `awaiting_recording_refresh`, `revalidation_pending`,
`current_index`, and `current_api`) so their size does not grow with API count.
Schema 34 counts HTTP routes rather than method contracts. `current_api` is the
path/pattern, and `current_index` addresses expanded route `items`; each item
retains its individual verification entries in `methods`. A route completes
only when every included method completes, and counts as skipped only when all
methods are skipped. Stored `.traffic-e2e/progress.yaml` remains method-keyed.
Normal coordinator commands and unscoped Replay advancement operate on routes;
HTTP method-qualified selectors are rejected.
Busy Replay summaries annotate each HTTP route with its method set from the
adopted recording, for example `building target for [GET, OPTIONS] /api/teams`.
This is the API's recorded method set, independent of which methods are being
reverified in this attempt. Historical recordings without method metadata show
the route alone; Replay and status do not backfill the recording.
The state-machine coordinator consumes the global action while top-level
`pending > 0`, executes the indicated command or runtime dispatch, and continues
from its response. When only asynchronous work remains, `pending=1` selects
`commands.wait` (`backend-rewrite wait --seconds 30`, with a 1–30 second bound).
Wait observes engine-state changes and returns `worker_events_required`: actually
invoke runtime list/status tools for all workers awaiting results, reconcile
their states and completion/failure/interruption events, report changes with
their original identities, then execute global status. Each wait requires a new
query pass even if no event arrived and stored activity has not expired. Queries
are collected together; existing per-worker report commands persist changes or
required refreshes. Unchanged running reports need not be refreshed every wait;
activity observations still expire at 60 minutes. `terminal_allowed` is the
separate successful completion gate.
A global `blocked` action has `pending=0` and stops this run after eligible
revalidation drains and remaining APIs require external system repair. Repair
APIs remain incomplete, with bindings/evidence
retained. Resume with global status after repair; the engine cannot wake a
stopped AI session. Other explicit failures retain their recovery/retry contracts.
The engine selects across the whole inventory, including parked implementation
issues. The coordinator does not scan `unverified` to choose work. `inventory`
expands the English `details.ready` and `details.waiting` breakdown and dedicated
worker bindings; ready counts sum to `pending`.

New workflows use a bounded, reusable implementer pool. Local
`.traffic-e2e/regression.yaml` accepts `max_implementers: 16` (default 16, positive
integer). The workflow freezes this value at creation; editing it affects the
next workflow, not active slot count or group mapping. `inventory.implementers`
exposes the effective limit, stable slots/handles, group mappings, queued tasks,
current API and counts. An API’s recorded methods remain one implementation unit.
Action schema 38 adds `repository_analysis_required` and
`implementer_dispatch_required`; `inventory` also exposes the adopted analysis,
active group round and last partial/completed group summary. Existing workflows
without a pool retain their original per-API binding protocol.

Names and paths are fixed by slot, without workflow prefixes or API slugs:

```text
<canonical-target-root>/.traffic-e2e/local/rewrite-worktrees/api-implementer-0
...
<canonical-target-root>/.traffic-e2e/local/rewrite-worktrees/api-implementer-15
<canonical-target-root>/.traffic-e2e/local/rewrite-worktrees/integrator
```

The returned implementation path is enforced. For targets nested in a larger Git
repository, it is the outer worktree root; the engine normalizes review/edit
scope to the corresponding target child and configured managed siblings. Reuse
worktrees and caches, preserving queued tasks and unhanded changes. Slots are
created lazily; an API does not allocate a new checkout. Historical worktree
migration is outside this protocol.

The coordinator creates an absent checkout with `git worktree add` at the exact
engine-returned root, based on the integrated target revision. Confirmation
rejects ordinary directories, symlinks and mismatched Git roots. The engine does
not create task-runtime sessions or fabricate their handles.

After static/dynamic route identification and inventory adoption, the engine
requires complete incremental repository analysis before any group Replay:

```bash
backend-rewrite repository-analysis context
backend-rewrite repository-analysis apply <batch-id> --file /absolute/analysis.json
```

`repository_analysis_required` returns the exact batch, selected/pending routes,
Source/workflow/recording identity and existing group catalog. A read-only
`repository-analyst` traces shared modules/state machines/write hotspots and
returns one complete incremental submission:

```json
{
  "schema_version": 1,
  "catalog_revision": "<exact returned catalog revision>",
  "groups": {
    "sessions": {
      "summary": "Session lifecycle",
      "source_refs": ["src/routes/sessions.py:create_session"],
      "shared_modules": ["auth/session"],
      "write_hotspots": ["src/session.rs"]
    }
  },
  "assignments": {"/api/sessions": "sessions"}
}
```

The assignments cover exactly pending canonical routes. Define only new groups;
joining an existing group references its ID without redefining it. Existing group
metadata and assignments are immutable through this incremental interface. The
engine checks batch/version/Source/recording identity and writes
`.traffic-e2e/local/repository-analysis/catalog.json`. This ignored project catalog
survives workflow changes; it is read through the context command, not edited by
agents. No ungrouped API starts Replay, and analysis does not overlap Replay.

Group count is unlimited. New group IDs are mapped in stable order round-robin
to the workflow’s slots; persisted mappings remain stable. Same-group APIs default
to the same implementer. A group beyond the slot count wraps around. The
coordinator may explicitly change future mapping:

```bash
backend-rewrite implementer reassign --group sessions --slot 3 --reason 'redistribute remaining work'
```

In-flight assignments retain their original slot and lease. There is no automatic
cost scoring or rebalancing. An implementer can queue work from several groups
but develops at most one API at a time. Unrelated groups can continue on their
slots while another group is waiting.

`implementer_dispatch_required` returns one same-group batch in `details`, with
slot/name/worktree/handle, group ID, batch dispatch ID, lease generation, and an
`apis` list containing each API’s own dispatch and lease. The coordinator
creates/resumes that slot’s actual runtime session and executes `commands.confirm`
after acceptance:

```text
backend-rewrite implementer confirm --slot <N> --group <group-id> --dispatch-id <batch-id> --agent-handle <actual-handle>
backend-rewrite implementer report --slot <N> --api '/route' --dispatch-id <api-dispatch-id> --lease-generation <generation> --agent-handle <actual-handle> --activity running
```

Confirmation is idempotent and records members queued; report real `running`,
`queued` or `idle` activity per original API lease. Pool observations cannot use
handle-only `worker report`: one handle can own several APIs. The engine rejects
stale dispatch/lease callbacks and simultaneous running APIs in one slot. Query
runtime handles in bulk, then reconcile their API tasks through returned reports.
The task runtime still controls accepted queuing and execution availability.

Resume retained handles first. When an actual runtime API query confirms that
the exact old handle is missing and cannot be resumed, create a replacement
session and recover the slot through:

```text
backend-rewrite implementer replace-runtime --slot <N> --previous-agent-handle <old> --agent-handle <new> --reason '<proven absence>' --runtime-query-command '<actual query>' --runtime-query-at '<actual RFC3339 timestamp with timezone>'
```

This preserves the fixed checkout, mapping and pending tasks while renewing
their dispatch/lease identities; old callbacks are rejected. Reload `inventory`
before resuming pending work. Accepted handoff history stays unchanged. Runtime
timeouts, incomplete listings, session restart or an ended resumable task do not
establish absence, and the replacement must never share the checkout with a
still-active original session.

Implementers own Source diagnosis, code and relevant local tests. Before delivery,
each API obtains its own current passing scoped review. A handoff may contain
one API, multiple APIs, or a completed subset spanning assigned groups:

```json
[
  {
    "api": "/api/sessions",
    "dispatch_id": "<original API dispatch>",
    "lease_generation": 1,
    "handoff_id": "<unique stable API delivery identity>",
    "review_report": "/absolute/original-review.json"
  }
]
```

```text
backend-rewrite implementer handoff --slot <N> --agent-handle <actual-handle> --deliveries /absolute/deliveries.json
```

`--deliveries` accepts the path to that JSON file, not an inline JSON array.

Validation admits every selected member before publishing updates. Accepted
commits and reports are frozen independently of the reusable checkout; those
API leases are released, and unlisted tasks remain assigned. Distinct API
handoffs need distinct IDs even if they share a commit. Handoff does not imply
whole-slot idle or API completion. Integrators consume the exported frozen commit
and report, never the implementer’s current HEAD after reuse.

API expert assistance uses existing worker confirmation, activity reports, and
integration admission. The coordinator supplies no extra timestamps or runtime
duration. Each binding retains `first_bound_at`, `last_integrated_at`, and
`last_integrated_commit`. Only a newly accepted API integration containing a
committed worker change and a nonempty published candidate updates the latter
two fields. Empty/unchanged handoffs, duplicate reports, unrelated integrations,
worker resumes, and ownership transfer do not reset them. Before the first code
integration, the timer starts at initial worker confirmation. Legacy bindings
without a timestamp initialize it on their next accepted confirmation or activity
report, without asking the coordinator to reconstruct history.

When only one unfinished API remains in the inventory, its implementer is
actually running, and more than two hours have passed since its last code
integration (or initial binding), the engine returns `expert_required`.
HTTP methods on the same route count as one API. Every other route must be
complete or skipped; unfinished APIs without worker bindings also block the
trigger. Queued and ended tasks do not count as running;
unknown, stale, or unconfirmed runtime status requires reconciliation first.
The count uses current API work scopes, including parked APIs, rather than all
historical bindings. It does not predict workers needed after future Replay.
The trigger has no attempt-count condition. `status`, `next`, and
bounded `wait` checks evaluate it, including during traffic operations; `wait`
still requires runtime-event reconciliation before the next status decision.

The coordinator must not initiate expert assistance based on elapsed time,
difficulty, or its own judgment. Only an engine-issued `expert_required` action
authorizes the assistance flow. Execute `commands.prepare` to reserve the
returned API. Preparation rechecks
eligibility under the worker feedback lock. The resulting `dispatch_required`
action asks for one read-only `api-expert`, with its API worktree and evidence
command in `details.apis`. An unconfirmed reservation returns `not_due` with no
dispatch command while another unfinished API exists. Already confirmed experts
retain their report-delivery and cleanup lifecycle. Recover an existing runtime
task for `expert_id` before submitting, then execute `commands.confirm_expert`
once the task is accepted, including queued work. Continue engine work while the
expert runs.

When the expert ends, forward its findings or unresolved/failure report to the
retained implementer and execute the API's
`inventory.experts[].apis[].commands.report_delivered`, supplying the expert
handle, stable report ID, and recipient handle. Only one expert may be active;
each API is covered once per workflow, across retries, revalidation, transfers,
and recording inventory changes. Expert reports remain advisory and never
satisfy implementation or verification gates. Experts never spawn other experts.

If the API passes before its expert report arrives, the engine returns
`expert_required` with `details.state=close_required`. The coordinator queries
the task, stops it if running or queued, confirms it has ended, then executes
`commands.close_expert`. An unsubmitted reservation closes without creating a
task; recover and confirm an already accepted task before closing it. The API
remains passed. `closed_at` records cleanup, releases the expert slot and retains
one-time coverage. Late report callbacks cannot reopen the API or the expert;
keep findings as reference. Final workflow delivery waits only for this cleanup
acknowledgement, not for the investigation to finish its analysis.

Reservation, confirmation, and delivery use the durable worker feedback
transaction so an in-flight verifier's older snapshot cannot overwrite them.
Repeated identical commands are idempotent; a second expert handle or conflicting
delivery is rejected. Expert confirmation persists its runtime handle and fingerprint; status and
inventory expose the known handle for task recovery and closure.

Legacy workflows without a pool retain per-API `worker confirm` and runtime
`worker report` behavior. New pooled runtime observations and handoffs use the
explicit `implementer` interfaces above. Integration and rework still use the
original handle, unique handoff ID and original matching review report through
`worker report`; these exact delivery identities disambiguate APIs sharing one
handle. Reports never substitute fresh review files for old callback identities.

`integration_required` delegates selected accepted handoffs to the retained
integrator, publishes its exact checked candidate, and reports each delivery
integrated with that candidate’s passing report. Source conflicts requiring API
behavior changes return to the implementer through `rework_required`. Integration
requires a free verification/publication resource.

Group Replay rounds freeze the recording, target fingerprint, route list and
exact per-method admissions. An initial round contains selected APIs pending
fresh verification in one group, including `api_pending` retries whose old
evidence became stale even when they retain earlier attempts. Acceptance contains
only reviewed/integrated or otherwise precisely
admitted API methods. A shared group never admits an unhanded API. Routes run
sequentially, preserving recorded methods, isolation and per-API evidence, and
results are saved as each route finishes. Ordinary failure continues to the
remaining routes; the group’s failed API batch is dispatched after the round
finishes. Infrastructure execution errors retain a partial summary and unfinished
membership for recovery without repeating completed routes. `inventory` exposes
active/last group rounds and the pool. Other groups’ ready implementation can
continue while traffic remains serialized. At each group boundary, dispatch its
failed APIs first, then prioritize APIs with no Replay attempts over integration,
acceptance Replay and pending refreshes with prior attempts. An active group
always drains before this selection. Ordinary integration and acceptance resume
when no eligible first attempt remains; rule, review and repair gates still apply.

Source quality rework preserves assigned findings in `context.review.rework`
alongside any behavioral issue. Repeated routing to the same owner and target
revision extends the current repair. Worker dispatch/status/integration remain
available; otherwise `wait_required` on `source_review_rework` waits for the
repair without repeatedly scheduling a failing review or traffic acceptance.

`worker_status_required` asks for a runtime observation, including for legacy
bindings and running/queued observations at least 60 minutes old. Historical
confirmation alone never proves liveness. Feedback uses a separate short,
durable transaction and is folded into state on load/save, so a long Replay
cannot prevent feedback or overwrite it when saving an older snapshot.

CLI `next` launches detached engine operations and returns
the current action immediately. Continue dispatching workers and reporting
handoffs while verification runs. `execution_failed` retains a bounded error
and exact `operation retry <operation-id>` command; resolve its cause before
retrying. A stopped executor requires recovery. Neither condition is completion.
For a `target_runtime` issue, changing the committed engine revision permits one
fresh coordinator Replay of the same API method and immutable recording without
a target-code handoff. Legacy failed attempts without an engine identity receive
one compatibility retry. Each attempt records the executing engine's Git revision,
embedded at build time; rebuilding the same commit or changing only target code
does not renew this permit. Status compares persisted strings without running Git
for engine identity, hashing executables, or scanning recording cases.
An older interrupted attempt can retain a response, dependency or replay issue.
With a known different engine revision, an incomplete replay that executed some
but fewer than all selected cases receives the same single-method retry permit.
The issue and parked workers are preserved; ordinary completed failures, unknown
engine identities for these retained issues, and quality work do not gain this
permit. A fresh attempt must still satisfy every response and dependency gate.
Next still requires current configuration and delivery identity and acquires the
ordinary traffic lease. It durably consumes each method's revision permit before
starting Replay, preserving the prior issue and attempt history. A running retry
does not dispatch its old issue again. Failure, process restart, and recovery never
refund the permit; a new result determines the next action. Other issue kinds and
unaccepted sibling methods retain their existing handoff and repair gates.
Worker and ordinary integration admit exact committed identities without source
or repository checks. Non-pre-revalidation review check succeeds without code
checks. The coordinator reports exact published delivery commits;
the legacy `target-quality run` entrypoint only validates an existing receipt.
One admitted integrated API handoff schedules that API's Replay. After ordinary
work drains, `pre_revalidation_review_required` blocks the final full sweep until
the integrator's quality-checked candidate is published and its final-stage receipt
is admitted. Final unified verification then handles shared changes.

Returned `next` commands omit `--api`; the engine retains its selected route
independently of command arguments. Explicit `next --api '/route'` selects the entry route; pooled execution still
finishes that frozen group round. Legacy workflows retain single-scope behavior. Schema 36
adds `advance_required.details.operation` (`replay` or `workflow`) and the
engine-selected `details.api` without asking the coordinator to select it.

After status returns
`advance_required`, the returned `next` validates the
adopted external run, prepares the current API, runs focused E2E, and returns
either one bounded implementation issue or the next validation action.

Regression settings are local to the target repository in
`.traffic-e2e/regression.yaml`. Initialization generates this file and adds it to `.gitignore` and `.dockerignore`.
It does not need a commit and is explicitly excluded from code and target
fingerprints, even if manually tracked. Existing projects without the file use
all recorded APIs.

```yaml
# Optional: directly reuse this completed standard recording.
# recording_run_id: "20260911093000"
# Fixed implementation slots captured when the next workflow starts.
max_implementers: 16
# Optional: continue passing Replay beyond a completed group when selected.
auto_next: false
# Skip previously passed cases during repair Replay; final revalidation stays full.
retry_failed_only: false
# Optional: cap successful stream input intervals; omitted preserves Source timing.
# replay_timing: fast
# Per-interval cap in fast mode, in milliseconds (0 removes artificial waits).
replay_interval_cap_ms: 5
# Omitted or empty only selects every API in the recorded inventory.
only:
  - "/api/users/*"
  - "/api/users"
skip:
  - "/api/users"
```

Set `retry_failed_only: true` to skip previously passed cases during repair Replay.
The caller continues using `next`; the engine selects APIs as usual and filters
their cases internally. The first attempt runs every case. Later attempts retain
failed, incomplete and unexecuted cases, including cases left by the per-API
failure limit, and accumulate passed-case skips within the same workflow and
unchanged Source/API inventory. Final revalidation and standalone `run`/`run-api`
always execute the full selected API inventory. Only the latest attempt is read:
if it ran two cases and one passed cleanly, the next repair selects only the
remaining case. Cases already omitted by that latest selection stay omitted.
Independently completed clean cases remain eligible even when later session
cleanup fails. A latest full result without selection metadata
can supply those outcomes when its complete Source/API inventory matches.
There is no scan, restoration or separate ledger for older attempts. Missing
latest evidence starts a full baseline. The setting defaults to false and can be changed
between attempts without changing target fingerprints.

Set `replay_timing: fast` to shorten artificial input waits for ordinary Case
Redis Pub/Sub messages and complete successful HTTP dependency streams. Each
recorded interval becomes `min(recorded interval, replay_interval_cap_ms)`;
the cap defaults to 5 ms and accepts 0. Pub/Sub includes subscription-to-first-push
and adjacent push intervals. HTTP includes request-to-headers, headers-to-first-chunk,
adjacent chunks and final-chunk-to-EOF. Compressed offsets accumulate those
individual gaps, preserving shorter gaps, payload order, framing and trailers.
Target processing and dependency calls initiated by Target retain their real
execution time. Process-owned Pub/Sub and abnormal or interrupted HTTP streams
retain their existing lifecycle timing.

The same fast setting and interval cap accelerate supported
[Socket.IO input gaps and completed quiet tails](interaction-recording.md#completion-profiles).
Managed fast replay caps each Case's execution and dependency wait at 120
seconds from Case activation. Cleanup retains its own budget after a failure.

`replay_timing: recorded` preserves Source stream timing; omitting it has the same
behavior. The low-level equivalents are
`traffic-e2e replay --stream-timing fast --stream-interval-cap-ms 5`.
These settings reuse existing recordings. Mode and active fast-mode cap are
bound to executed Replay identity, and changing either requires fresh passing
evidence and resets previously passed repair-case skips. They remain excluded
from target and code fingerprints.

Skipped passes are scheduling history, never fresh response or dependency
evidence. `diagnosis.case_selection` reports available, selected and skipped
counts; other attempt counts describe only selected cases.
Backend-rewrite overview and execution-failure queries expose the same diagnostic
as `case_selection`, including for an already finalized attempt. It describes
the runner's selection, separately from the low-level Replay report's `mode`.
Missing legacy selection metadata is reported as null, without inferring skips.
Existing explicit localcache and cross-case dependency rules still load from the
complete recording.
Logical progress keeps the recorded case totals and cannot mark a partially
selected API fully verified, even when that repair attempt passes.
Skipping requests can nevertheless change application-local cache warmup or other
state established by earlier requests. Use full Replay when cases depend on those
side effects; the engine does not infer or synthesize cache contents.

Set `auto_next: true` to let an unscoped `next` continue after fresh passing
Replay when the next globally scheduled action is also Replay. During an active
revalidation round, terminal failures also continue to its remaining members.
Each step saves its result and releases its workflow lock and Replay lease before
merging new feedback. A started round drains before worker dispatch, integration,
repair acceptance or a new round. Outside a round, first-pass discovery and ready
handoffs retain their existing priorities. Stale Replay, resource recovery,
review, rule/input handling, waiting and final publication retain their gates.
Changing `auto_next` to false stops continuation beyond the current group; a
started group round still drains. Legacy workflows stop after the current step.
The omitted field defaults to false; its value must be a boolean. Explicit API
or source-route inputs use single entry selection; pooled group rounds still
complete before returning to the coordinator. These local settings do not
invalidate evidence or require a commit.

While an operation runs, ordinary `status` returns `wait_required` unless a
higher-priority independently executable worker/expert action is ready. Both wait
and those independent actions expose `details.execution_mode` as `single` or
`auto_next`; auto-next summaries say `automatically advancing Replay`, and wait
summaries also include the current Replay phase and progress. The operation remains busy between APIs,
so another command cannot start a competing Replay or admit an integration.
Retries retain the mode and the last selected scope, rather than restarting the
first API in the chain. Legacy operation markers default to single execution.

When a route has several methods, selection prefers a pending first attempt or
a method with precise rule/system-repair Replay admission over an active sibling
still awaiting implementation acceptance. Scoped status and detached `next` use
the same selection. A rule for one method never admits an unaccepted sibling;
the route batch preserves that sibling's issue and worker binding.

`only` and `skip` can be combined: first select `only` (or all APIs when absent or empty),
then remove `skip`. HTTP selectors must be exact canonical routes from `inventory`,
without a method, and select all recorded methods on that route. Method-prefixed
HTTP selectors are rejected. Non-HTTP Motan selectors retain `MOTAN /...`.
The recorded path pattern's `*` is part of that inventory
identity, not a glob over other APIs. Unknown names, duplicate entries within a
list and unknown fields are errors. Omitting `only`, `only:`, `only: null` and
`only: []` all select every recorded API before applying `skip`. An empty `skip`
list excludes nothing. Removing the file restores all APIs.

Set `recording_run_id` to a 14-digit standard recording ID under
`.traffic-e2e/local/artifacts/recordings/`. The coordinator directly validates
and uses that recording as the regression baseline. It does not start a source
recording or use the historical requests to collect a replacement. Missing,
unfinished, failed, empty or unusable recordings block `status` / `next`; no
other recording is selected as a fallback. `only` / `skip` select APIs from this
recording's inventory.

Switching the ID resets current API verification and retains
historical artifacts and cumulative progress. Returning to an earlier ID starts
a separate progress epoch. The YAML edit still does not change code or target
fingerprints, but verification must run against the selected recording. Remove
or clear the field before requesting a fresh recording or completing a required
capture refresh. Omitting the field, `recording_run_id:`, `recording_run_id: null`
and `recording_run_id: ""` all preserve the current baseline and the existing
automatic recording workflow. Nonempty values must still be valid recording IDs.

On `pr_base`, `backend-rewrite status` always returns `purpose_required` before
old worker, expert, completion or verification actions. Scoped status, `next`
and `wait` preserve that boundary too. This does not depend on code changes,
session identity, previous approval or whether the old workflow finished.
The action contains two commands. Use the one matching the user's explicit
request; otherwise ask the user to choose. Before confirming, actually query the
coordinator's runtime for active child agents/sessions of the current session.
Exclude the coordinator itself, unrelated independent sessions, engine bindings
and historical sessions. The observed count must be zero; do not infer it from
being on `pr_base` or automatically stop active agents. Supply the result through
`BACKEND_REWRITE_SESSION_ACTIVE_AGENT_COUNT`,
`BACKEND_REWRITE_SESSION_QUERY_COMMAND` and `BACKEND_REWRITE_SESSION_QUERY_AT`
(required by the returned command), or the equivalent flags
`--active-agent-count`, `--runtime-query-command` and `--runtime-query-at`.
The query timestamp must be RFC 3339 with a timezone. No evidence file is needed.
The engine validates and records the coordinator's declaration; it cannot inspect
the coordinator runtime itself. With those query values supplied:

```bash
backend-rewrite purpose confirm --purpose replay --user-approved
backend-rewrite purpose confirm --purpose record --user-approved
```

`replay` reuses the selected completed recording. `record` requests new external
live traffic and continues to Replay after publication and normal case preparation.
The latter can initialize a workflow without prior recordings. It supersedes the
old local recording pin for this workflow; a later explicit pin change is still
honored. `only`/`skip` continue to apply.

The coordinator only confirms purpose. The engine generates a unique
`replay/yyyyMMdd-<seq>` or `record/yyyyMMdd-<seq>` branch, creates and switches to it,
using the machine-local date and one above the largest local/remote sequence for
that purpose and day (starting at 1). It returns `work_branch` and `next`. No
branch name is required. Confirmation consumes the entry permission by entering the work branch;
subsequent `status` / `next` calls continue there. Returning to `pr_base` always
requires a new confirmation, even with unchanged code and an unfinished workflow.

Existing worker bindings, failures, review receipts and expert assignments are
archived under ignored runtime history and replaced with a new workflow identity.
For obsolete version-one state, confirmation reads only its version and workflow
identity, archives the exact original bytes and initializes the current schema.
It does not load old assignments, receipts or recording references. Current-state
corruption and unknown future schemas still fail. Archive failure leaves the old
state untouched; failed branch creation restores it. Existing recordings must
independently satisfy the current recording format and are never converted by
this workflow reset.
The engine does not query, wait for or resume old workers. Old callbacks cannot
satisfy the new workflow; first Replay diagnoses current behavior without an old
implementation/review gate. Only fresh failures lead to new workers and expert
planning, with fresh integration timers. Each API can bind a new worker once
under this purpose authorization, when a fresh failure needs implementation.
This permission is independent per API and is consumed by its first binding.
Subsequent replacement requires explicit user authorization or an actual runtime
query confirming that worker is missing.

The committed `pr_base` revision captured by purpose confirmation is the trusted
review baseline. An unchanged baseline proceeds directly through recording/Replay
without an ordinary source-review receipt, including when an old or broken
`source-review.json` remains on disk. This Source-review exemption does not
replace the final pre-revalidation gate. Committing engine progress files or changing
only source traffic or verification policy does not create a source-review
obligation. Other committed, staged, working-tree or untracked source/configuration
changes require normal committed-delivery identity admission where applicable,
without a source review before focused verification. Final delivery still requires
the complete final review and subsequent full revalidation. Pending handoffs
retain their exact commit/dispatch contract; no exemption admits unpublished code.
Source review and engine-issued final pre-revalidation checks belong to the
delegated integrator, not the coordinator's startup path.

An actual active/stale engine operation must finish or recover before replacement;
this is the serialized traffic lease, not an old task-runtime liveness check.
Failure to create the work branch while still on base restores the previous state.
`status` remains read-only throughout. The legacy `regression begin` CLI is hidden;
coordinators should use the purpose command returned by `status`.

`status`, `inventory` and `next` use current selection/recording/auto-next
settings between traffic operations. `max_implementers` is the exception: the
active workflow keeps its captured effective limit until a new workflow starts. Excluded APIs are reported as `skipped`, do not dispatch workers or
block completion, and retain original progress/evidence for later re-inclusion.
A scoped `status --api` or `next --api` for an excluded API returns `complete`
with an explicit skipped explanation and false current-verification flags.
Global completion is restricted to the selected scope, with separate verified
and skipped counts; skips never become passing traffic observations.

Passing Replay completes the API. A repository or policy content change makes
prior E2E evidence stale and marks completed APIs `revalidation_pending`; it does
not immediately replay them. Automatic revalidation starts only when every
included method contract is complete, pending revalidation, or at a confirmed
system-repair gap. Skipped methods are excluded. Pending implementation,
unintegrated handoffs, integrated-but-unverified deliveries and recording-refresh
waiters must finish their existing acceptance/input flow first. Before starting
a full revalidation round, the engine requires current final pre-revalidation
proof. The same final gate applies before successful completion when the
inventory already has current passing evidence; an unchanged purpose baseline
is not an exemption. The engine returns `pre_revalidation_review_required` with
the exact check and admission commands when proof is missing or stale:

```bash
backend-rewrite --target-root /absolute/canonical review check \
  --pre-revalidation --quality-check cargo-clippy --worktree /absolute/integration
```

The retained integrator first executes the tool named by `details.quality_check`
across `details.quality_paths` on the final committed candidate. This requirement
is configured by `project.delivery.quality_check` (default `cargo-clippy`); for
Rust the agent runs `cargo clippy --workspace --all-targets -- -D warnings`.
Only after success does it execute the returned command with the required tool
identifier. The flag attests successful agent execution; the engine matches it
to canonical configuration, runs Source/isolation checks, and records a
version-bound final receipt. It does not execute repository quality commands or
independently certify the tool run. The integrator repairs routine findings,
commits the corrected candidate, and checks it before reporting success.
Changes requiring API behavior decisions return to the responsible implementer.
Only the coordinator publishes the exact passing candidate and calls `review
accept --report ...`; acceptance validates proof without repeating execution.

The final receipt binds candidate code, canonical inputs, check policy,
verification policy, inventory and immutable recording. It also hashes
`Cargo.toml`, `Cargo.lock`, `.cargo/config`, `.cargo/config.toml` and
`rust-toolchain`/`rust-toolchain.toml` in each managed project and its ancestors
through the repository root. Target/managed code and changed tracked Cargo or
toolchain inputs must be committed before final checking and admission;
progress, policy and private runtime retain their existing separate treatment.
Failing, stale or ordinary-integration reports cannot start the full sweep.

Relevant changes invalidate final proof. Retrying the same successful final
candidate reuses its cached report and restores its delivery report file if
needed, without executing the suite again. Progress-only publication and moving
between APIs in the unchanged round retain matching admitted proof. The durable
sweep binds the exact final report's SHA256 identity, so an interrupted
replacement admission cannot reuse another candidate's consumed membership.
Missing or stale proof is a normal state-machine action, not an API Replay failure.

Admitting a new final candidate schedules every included successful method for
another full sweep, even if its first-pass evidence was current. Confirmed
system gaps keep their repair identities and do not block other runnable APIs.
Starting revalidation persists the complete set of stale method contracts in
inventory order. Run every member once before returning to implementation or
repair acceptance. A terminal failure records its issue and consumes that round
membership, so failures on multiple APIs are collected in the same sweep.
Route batches include only their remaining methods, never completed siblings.
Between Replay steps, later fingerprint changes can mark successes stale again,
but cannot re-add them to the active round. Recovery and process restarts retain
its remaining membership. A fingerprint change during Replay still discards
that unaccepted result and requires a valid attempt before consuming membership.

After the sweep drains, repair and accept every failed API, or confirm its system
gap. Only then may another round start for evidence that is still stale. An API
accepted earlier in this repair phase is not replayed again while other repairs
remain outstanding. `verification request` reports selected stale APIs through
the same gate; it cannot promote them to ordinary pending work or bypass an
active round. No empty round is created: with current evidence for all included
APIs, normal completion/publication proceeds; if only confirmed gaps remain,
the existing global `blocked` stop preserves evidence and bindings for resume.
Gaps never count as passing traffic or allow successful terminal completion.
`terminal_allowed` still requires every included API's passing evidence at the
current target fingerprint plus the existing review and publication gates.
A commit preserving effective worktree content does not change the fingerprint.

After a finalized unscoped standard recording, the coordinator compares its
concrete APIs with a persistent historical API catalog canonicalized by current
`case_path_patterns`. Only new uncovered APIs produce one
`case_pattern_identification_required` batch. The coordinator delegates this
read-only static/dynamic source route analysis to `repository-analyst`, separately
from API implementation; the analyst has no implementation-worker binding or
worktree. Its fixed apply command receives
the complete JSON pattern list through
`BACKEND_REWRITE_CASE_PATH_PATTERNS_JSON`; `[]` confirms that every candidate is
static. This action has no source-revision or evidence input. Apply updates the
managed source traffic policy and the catalog, while existing recording files
remain immutable. The current recording inventory is then derived again under
the updated policy.

Recording and focused Replay share one serialized traffic-runtime
lease. Global status first returns any executable worker dispatch or feedback
action. When resources or running workers are the only remaining activity,
schema v30 returns `wait_required` with
the requested and blocking APIs, the live operation when available, a retry
delay, and the exact `commands.wait` argv. This lease serializes each traffic
operation, not a complete API lifecycle: while worker A implements, the
orchestrator may run Replay for API B and dispatch worker B. No worker may start
a traffic operation. If code changes during Replay, that result is discarded;
later code changes defer already-completed API evidence to the final epoch.

`status [--api]` is read-only and returns the selected work
item's `action` from the persisted workflow revision. Before execution starts
it reconstructs the same
run ID and argv; owner status for a live detached worker may return
`recording_in_progress`, and only a
finalized manifest returns `advance_required`. A running manifest without a live
owner returns `recovery_required`; `backend-rewrite recover` removes only that run's
managed resources and allocates a replacement run. A pending rule plan produces
`plan_apply_required` with only the stored plan ID. The persisted plan keeps
the evidence validation performed at plan time, so its own workflow revision
does not make apply stale. A corrected plan using the same evidence ID replaces
the pending preview before apply; recorder configuration is still changed only
by apply. Worker delivery and ordinary integration validate exact committed identities
without source review. Ordinary Replay does not require a source-review receipt.
Before the final full revalidation, `pre_revalidation_review_required` requests
the consolidated source, line-limit, spawn, isolation and configured quality
checks on the final candidate. Review corrections are committed before the full
revalidation of that version. The engine never executes repository quality tools.

A failed focused E2E attempt reuses the same finalized standard cases after the
target changes. Backend rewrite consumes external evidence and never starts
recording, allocates recording IDs, or manages recording containers. Place
completed Source recordings under `.traffic-e2e/local/artifacts/recordings/<run-id>/`
and optionally pin `recording_run_id` in the local regression configuration.
Without a pin, `next` selects one completed batch and retains its identity.
Fresh-capture requirements wait for a newer externally produced batch without
modifying old evidence.
Missing evidence returns `input_required` with no recording execution command.
See [standalone recording and handoff](recording.md).

After a focused attempt, `next` and `status` expose
`latest_focused_e2e.execution_mode` as either `fresh_standard_cases` or
`reused_standard_cases`. The same bounded object identifies the standard
recording run, exact case-source directory, case-inventory ID when available,
previous/current attempt numbers, and whether the latest attempt passed. It
describes the latest completed attempt, so a repeated `next` with no target
change returns the same evidence without claiming another replay occurred.

Workers fetch the overview through `backend-rewrite evidence --api`, bound to their canonical target root. Further gate and
aggregate facts use only the returned `backend-rewrite evidence <query-id>`
commands.
For a response issue, `facts.issue.response_diagnosis` in that overview
contains exact total/indexed/omitted difference counts plus at most 20 clusters
grouped by normalized Pointer pattern and difference kind. Each cluster reports
affected cases, total occurrences, and one exact representative. The first
entry in the overview's `queries` is `case_response_differences`; it returns at
most 20 ordered differences from that representative case with bounded expected/actual values.
If a selected case finishes without usable target response assertion evidence,
the diagnosis counts one `response_unavailable` difference at `$response`; the
evidence page reports the recorded response as present and the target response
as unavailable. When the HTTP driver can classify the observed transport
failure, both the representative and evidence page include an
`unavailable_reason`, such as `target_connection_closed`,
`target_connection_failed`, or `target_request_timed_out`.
The managed HTTP request deadline includes the recorded Source response's
`duration_ms` plus the ordinary 30-second execution allowance. A recorded
30.26-second RPC can therefore complete its preserved callback delay without
being cut off by a shorter fixed client deadline. Missing elapsed metadata
retains the allowance; malformed elapsed metadata fails explicitly. Only elapsed
time affects this budget; Source status, headers and body remain assertion data.
When more are available it returns the next opaque evidence command instead of
an open cursor. The `representatives` result includes the representative case
ID, its exact immutable standard `case_dir`, and a structured
response difference. A focused E2E difference contains expected and actual
observations. It does not duplicate the complete Replay response
or expose a Replay-local result directory. The AI may inspect all persisted
files under `.traffic-e2e/local/artifacts/`, starting with the representative case for
efficiency. Artifacts remain read-only, and coordinator results remain
authoritative for the active run and legal transitions.

For a response, Replay, or dependency issue, `dirty_clusters` reads a bounded
Replay dependency sidecar instead of the complete Replay report. The sidecar
contains only case-scoped unmatched, unsupported, unsafe, and unused-case
events, grouped by protocol and `host:port`, with bounded operation counts and
one exact representative `case_dir`. Each compact cluster has a stable
`cluster_id` and the correlated startup interaction count. Recording-global
source bootstrap and configured process-owned traffic are returned only by the
separate `source_process_traffic` query. They do not affect the case gate.
`unused_global` events and target activity outside an active case remain
aggregate diagnostics and do not make a case dirty.

When evidence identifies a protocol with supported rules, the report includes
`rule_hints`. Each entry contains an English applicability hint and an
exact read-only `help` command. This list is separate from
`applicable_rule_planners`, which contains planner entrypoints appropriate to
the current evidence state; neither list proves that a rule applies. For a
response body without a configured or protocol-defined codec, the planner
offers each syntactically valid protobuf, Hessian2, or DOCX codec candidate. Motan1
`value` responses are already defined as Hessian2 by the protocol, so their
unwrapped bodies use Hessian2 semantic equality for the verdict without a
codec rule. The observed body framing is reported separately as `envelope`,
and `body_diagnosis.used_for_verdict` says whether structured comparison
determined the verdict. Once one codec is configured, the response rule hint
instead directs the AI to the reported field/value differences and
unordered-path candidates. These candidates identify mechanically explainable
paths but do not prove that order is semantically irrelevant. Every selected
protobuf/Hessian2 path and every DOCX timestamp selector must include one-line
source evidence. Codec-only selection is evidence-light because it ignores only
DOCX/ZIP packaging metadata or changes decoding without relaxing body values.
Memcached dirty-cluster evidence returns the supported JSON/PB value slot and
its typed contracts. Use the same proposal entrypoint as other protocols:

```bash
backend-rewrite --target-root ../target rule plan --file /tmp/proposed-rules.yaml \
  --evidence <current-evidence-id>
```

The rule planner requires current dirty-cluster evidence and source proof for
each selected logical field. It owns the fixed five-second timestamp window;
the caller supplies neither an offset nor a tolerance.

Dependency evidence can be projected without parsing the JSONL directly:

```bash
backend-rewrite case dependencies <representative-case-dir>
```

The summary is grouped by stable target ID and includes an exact
`detail_command` for every target. Executing that command returns only the
selected target's bounded operation details and representative exchanges. MySQL
exchanges expose SQL up to 8192 bytes, typed parameters, database and username,
attribution, result status, row counts, column names, warnings, and the original
exchange locator. They omit result row payloads and report truncated previews
and omitted examples explicitly. The ordinary MySQL and Redis diagnostic flow
uses these returned commands; inspect the smallest original record only when
bounded output lacks a necessary fact. Redis
exchanges keep keys, arguments, and responses associated; response previews are
capped at 256 bytes and retain encoding, original length, and truncation
metadata. Complete small Redis scalar frames also expose a decoded
`response_value`. Keys are labeled only for understood command shapes. Memcached
representative keys and outcomes are returned together, but flags are
intentionally neither interpreted nor exposed. Dependency `representatives` and `dirty_clusters` evidence also
return the appropriate summary command so an AI does not need to reconstruct
argv or write an ad hoc artifact parser.

Use one `backend-rewrite rule plan --file RULES.yaml --evidence EVIDENCE_ID`
transaction for Source capture/classification, input adaptation, API response,
dependency request and dependency response effects. Query the returned bounded
rule discovery and capability evidence before authoring. `rule apply PLAN_ID`
uses the expanded reviewed rule and reports the remaining Replay or recording
obligations. See [unified rules](unified-rule-contracts.md).

Fast Replay does not currently reproduce process-local TTL expiry between
recorded requests. If compressed request intervals keep a target cache warm and
omit recorded dependency calls, retain the strict unused-dependency evidence and
report the engine capability gap. Replay does not wait the original recording
intervals, clear application caches, or relax dependency consumption to hide it.

Terminal runner snapshots retain `reports/replay-report.json` and its dependency
sidecar alongside assertions and aggregate reports. Each focused method snapshot
owns a complete copy, and aggregates refer to the published copy. Removing an
external `.replay` directory therefore does not invalidate newly published rule
evidence. A finalized attempt with a missing original report cannot be published.
Dependency failures remain shared across method snapshots. A dirty-cluster
representative can therefore belong to another method in the same session;
the query resolves its case directory within the same immutable recording,
preserving the session's dirty counts and gates. Unknown or duplicate recorded
case IDs remain errors.

Rule reclassification aggregates the retained runner report within its owning
snapshot, validates its session and recorded case identities, and keeps the
complete shared session when rebuilding one method's evidence. Unresolved
dependencies in a sibling method continue to fail the shared dependency gate.
Process-owned ownership changes rebuild every retained method projection of the
same session and attempt, preserving each method's response assertions. Other
sessions are left untouched. Publication retains a revision checkpoint until all
method snapshots, the run index, and progress agree; retrying does not count a
second Replay. If an older engine refreshed only one method, `status` requests
`next` with `reclassify_dependencies` before resuming a stale implementation issue.
Status itself does not rewrite evidence.

Each coordinator attempt records a separate Replay execution identity. Reusing
responses requires unchanged managed code, verification policy, startup snapshot,
and effective environment. Process-owned classification alone may change. When
execution inputs changed, or legacy state has no execution identity, reclassification
refreshes diagnosis but requests fresh Replay and preserves the old target fingerprint.
If `rule apply PLAN_ID` stops after writing the policy or report,
retry the same pending plan. Ownership planners recover original unused-case
witnesses from the engine's reversible reclassification markers in memory;
policy application and reclassification can then complete without duplicate
rules or lost exchanges. Native Global exchanges do not authorize a Case rule,
and unmatched, unsupported, unsafe, and header-mismatch checks still apply.

For a legacy pending rule whose Replay report or sidecar is already unavailable,
`next` returns `rule recover PLAN_ID`. This command retires only the matching plan,
returns its selector and source proof, and requests fresh Replay with the existing
recordings. It does not apply the stale plan or fabricate evidence. After Replay,
query current evidence and plan again. The retired `dependency-rule` commands do not accept new plans.
This recovery is for missing evidence; a partially applied ownership rule with
available evidence resumes through `rule apply`.

Use `backend-rewrite route` for a source-proven missing recorded resource,
Recorder/Replay capability gap, external-data blocker, or source change. For a
missing dependency, use `--cause missing-recorded-resource --endpoint
'hostname[:port]'`; the coordinator resolves the endpoint through configured
Breeze snapshots and returns a recorder-capture plan only when the unique
resource is currently bypassed. Query IDs and evidence IDs are bound to the
workflow revision and active issue, so stale evidence is rejected.

An accepted system/source repair route snapshots a coordinator-defined revision
and returns `repair verify <repair-id>`. The caller cannot provide an acceptance
command, and `next` cannot bypass the repair. Successful
verification decides whether to rerun the same cases or require fresh external
standard recording evidence. A successful `missing-recorded-resource` route instead
returns the existing recorder-capture apply command and never enters system
repair.

A fresh external recording requirement from repair verification also takes over
any pending capture refresh. The coordinator retains applied rules and the old
baseline reference until validation succeeds. It skips batches already present
when the requirement begins and waits for a newer completed batch; it does not
reserve a capture ID or execute recording. Publication and scope
checks still apply, and the recording must contain published cases. A new
recording does not have to cover every API from the old recording: its observed
APIs define this round's inventory. Historical recordings and the known API
catalog remain available. An absent API is outside this round and is not
counted as newly verified; old cases are not merged into the new recording.

If an administrator confirms that an issue was incorrectly routed as a
`source_change`, `recorder_capability_gap`, or `replay_capability_gap` system
repair, return that exact repair to target implementation explicitly:

```bash
backend-rewrite-admin --target-root ../target repair cancel <repair-id> \
  --reason 'the observed mismatch is target-owned' \
  --confirm-misroute
```

The command accepts only the current repair and one of the supported
source/capability route and issue combinations. It clears the accepted route,
restores the issue's target-code owner, and returns the coordinator-owned
advance command. It does not cancel external-data repairs, delete evidence, or
provide an ordinary AI workflow bypass.

Recordings grouped by an older coordinator may retain concrete route ownership
after the canonical API inventory adopts case path patterns. If Replay reports
that a case directory is already owned by a concrete group, rebuild only the
current workflow's exact recording run through the administrator interface:

```bash
backend-rewrite-admin --target-root <target> repair rebuild-case-groups \
  <recording-run-id> --confirm-rebuild
```

The command requires an idle coordinator and traffic runtime, verifies that the
run belongs to the current workflow, and rebuilds the complete derived index
from its canonical API inventory. Managed indexes store their case source and
member paths relative to the target root, so they remain valid when the complete
target directory is moved. When migrating a copied legacy absolute-path index,
the command also requires the original index and case source to remain readable,
verifies the run ID, source revision, and location-independent case inventory,
and migrates the E2E run index in the same operation. It preserves the recording
and keeps backups beside both replacements. If the replacement is incomplete or
invalid, the old case-group index is restored automatically. After a successful
repair, execute only the exact operation retry returned by `backend-rewrite
status`.

Initialize a rewrite target once, before its first coordinator session:

```bash
backend-rewrite --target-root ../target init \
  --source-pod <pod> --namespace <namespace> \
  [--pod-container <regular-container>] \
  [--kubeconfig /path/to/kubeconfig] \
  [--env-file /path/to/initial.env] \
  [--readiness-path /healthz] \
  [--http-backend-port 8080] \
  [--http-gateway-port 4080]
```

From the target root, `--target-root` is unnecessary. Defaults are backend HTTP
port `8080`, Recorder HTTP gateway port `4080`, readiness `/healthz` with fixed
success status `200`, and upstream DNS `10.10.10.11:53`. The backend port is
shared by the source and target processes and drives the generated Recorder
upstream, target readiness endpoint, and Replay
request destination. It must differ from the gateway listener port.
Initialization accepts a readiness path but no readiness status argument;
generated `project.yaml` retains the explicit `success_status: 200` contract.
The selected regular Pod container must be running and ready while init
captures its immutable image and effective runtime inputs. Later commands use
the ignored local source snapshot and do not require the Pod.

Alternatively, initialize from a local Docker container by name or ID:

```bash
backend-rewrite --target-root ../target init --source-container <container>
traffic-e2e config init --target-root ../target --source-container <container>
```

`--source-container` is mutually exclusive with the Pod provider and its
Kubernetes options. Running, exited, and created containers are supported;
initialization does not start, stop, or pause the input container. The Docker
provider captures `Config.Env`, security settings, and bind/volume contents,
and commits the writable layer plus the effective ENTRYPOINT, CMD, WORKDIR,
and image user into an immutable local image. The existing recording adapter
still runs as `998:998`. Configuration comes from Docker's container config,
not the environment of a process started by an entrypoint script. The source
image must be Linux/amd64; no registry digest is required.

The image is saved privately as `.traffic-e2e/local/source/image.tar` with a
SHA-256 checksum for recovery after local image cleanup. This archive can
contain application files and credentials and must remain ignored with the
rest of `.traffic-e2e/local/`. Later operations do not require the original
container or its mounts. Writable mount snapshots are copied into each managed
run and owned by `998:998`; the baseline is never mounted writable. tmpfs mounts
become empty runtime mounts. Virtual system paths, Docker network identity
files, and unsupported mount types are reported as ignored; overlapping
mounts and unsupported security options fail initialization. Engine-managed
networking and ports are not inherited from the input container.

Capturing a running container is an online filesystem snapshot, not a
transactionally consistent application checkpoint. Initialization rejects an
observed restart or configuration/state change during capture, but cannot
freeze concurrent application or external-volume writes. Use a stopped,
quiescent source when a consistent application checkpoint is required.

The command generates version-18 `.traffic-e2e/project.yaml`,
and one empty `.traffic-e2e/policy.yaml`, referenced by `project.policy`.
When the root `Cargo.toml`, `Cargo.lock`, and `src/main.rs` are all absent, it
also generates a runnable readiness-only Rust target using `http-server`
`v0.0.2` with its `macros` feature. `ReadinessApi` exports the configured GET
route through `#[api(auth = none)]` and `#[http_server::get(...)]`, returns
an empty `200` response, and starts with `Server::bind` / `serve_until` for
graceful shutdown. The generated route must be a literal path without captures,
query, fragment, whitespace, or a trailing slash (except `/`).
The bootstrap also includes a temporary `src/startup_probe.rs` initialization
module. Keep that module and its
`src/main.rs` call through initialization preflight, then delete the module,
declaration, and call when real target implementation begins. It generates
`.traffic-e2e/Dockerfile.target` only when absent and creates or safely extends the
root `.gitignore` and `.dockerignore` with canonical local-state, Rust build,
recording, data, credential, and environment-file exclusions; existing regular
target files are preserved.
`project.yaml` combines project settings with the static recorder settings;
`policy.yaml` holds all explicit rules and proofs. Project settings
have a single `policy` path plus source, target, replay, verification,
delivery, and state sections. `verification.max_failed_cases_per_api` defaults
to `10`; Replay stops admitting additional cases for an API once
that many cases have not passed. Remaining Replay cases stay unexecuted rather
than being reported as failed. A typical
target section is:

```yaml
target:
  dockerfile: .traffic-e2e/Dockerfile.target
  # Maximum time from target launch until every enabled endpoint is ready.
  startup_timeout_seconds: 180
  startup: {}
  # Optional application outputs written by the target at runtime.
  runtime_outputs:
    - id: application-logs
      container_path: /data1/weibo/logs
      mode: read_write
      retention: keep
```

The target itself is always managed. Add other code directories from the same
Git repository under delivery without moving the E2E configuration to the
repository root:

```yaml
delivery:
  pr_base: dev-migration
  quality_check: cargo-clippy
  managed_paths:
    - path: ../backend-rs
      build_context: sibling-backend
```

Paths are relative to the target, must use a normalized form with any `..`
components first, and cannot select the repository root, a nested Git
repository, or an overlapping directory. Omit `managed_paths` to retain the
single-target behavior of version-18 configuration.
The string form, such as `- ../docs`, adds review and delivery scope only. The
object form additionally exposes that exact directory to the target Docker
build under its explicit `build_context` name. The target remains the default
Docker context; consume an additional context explicitly in `Dockerfile.target`,
for example `COPY --from=sibling-backend src /build/backend-rs/src`. Context
names must be unique lowercase Docker identifiers of at most 64 ASCII
characters. The engine does not infer repository layout or copy an additional
context into an image automatically.

Target readiness path and status come from the project document's
`recorder.http_gateway.ready` section. Target startup readiness uses
`project.target.startup_timeout_seconds`, which defaults to 180 seconds when
omitted and accepts values through 1800 seconds. `project.replay.startup_timeout_seconds`
controls Replay service readiness (default 60), separately from dependency index
and case-loading timeouts. On a contended host, increase this existing readiness
budget before retrying a startup timeout. `project.replay.request_timeout_allowance_seconds`
adds 30 seconds by default to each HTTP case's recorded Source duration; it accepts
1 through 1800 seconds. Increase this bounded allowance for large downloads on
slower hosts. It changes the execution budget, not response or dependency assertions.
The target's native HTTP port is the port in
`recorder.http_gateway.matched_upstream`; Replay uses it on loopback.

`project.replay.case_no_progress_timeout_ms` defaults to `2000` and must be
positive. It bounds Replay-only idle waiting for unfinished dependency tails
after the recorded primary inputs have completed. Real resource delivery,
including an upstream SSE response, keeps its existing I/O budget.
Clean Socket.IO/WebSocket recordings without tail sidecars can retain their
finite Case Redis, MySQL, HTTP and connection-failure obligations from the
original semantic inventory. Wire close does not finish a sleeping disconnect
hook: the old Case remains active until its required calls really complete,
before the next input is admitted. A delayed online-state read therefore receives
its own recorded response, including a successor's socket identity; Replay does
not invent a missing delete or serve a previous Case's inventory to a new Case.
The absolute budget includes recorded Source elapsed time plus the normal
execution allowance and is anchored once at admission. Existing optional-session,
shared-initialization and proven process permissions retain their meanings.
Explicit tail observations take precedence. Unclean or unsupported legacy
footprints keep the existing transport/started-I/O cleanup path; no partial
inventory is claimed and the ordinary verification gates still apply. No
recording files are rewritten to create this wait.

For this native interaction inventory, the recorded duration after the final
client input supplements the configured idle timeout. This permits a real
disconnect grace interval that equals or exceeds the ordinary idle timeout;
the absolute admission deadline remains unchanged. The supplementary interval
uses only input offsets and elapsed time, never output frames, values, or a
later Case's timestamps. All-consumed inventories complete immediately.
Waiting evidence exposes `source_post_input_allowance_ms` and the effective
`no_progress_timeout_ms`. If this native interaction still stalls, its Case
remains active and the runner stops Target before admitting another input.
An actual Replay dependency rejection retains the same native Case, including
rejections after its finite inventory was consumed. The final ownership-release
lock repeats that check. A recorded dependency error delivered as contracted is
ordinary consumption and does not trigger this rejection fence.

Case dependency completions renew the idle clock. Unrelated process activity
does not. Recorded idle gaps do not impose a minimum wait. The direct Replay
CLI exposes the same setting as `--case-no-progress-timeout-ms`.

Finite async references retain MySQL's native setup/cleanup and complete
transaction-equivalence proofs. A proven unstarted session-control omission
does not remain in the pending tail inventory, and remains separately reported
as an omission rather than fabricated consumption. Missing business reads,
locking transactions and unproved write/commit boundaries stay mandatory.
An optional command that Target has started must finish its actual delivery.
Complete ordinary row-lock SELECTs retain a strict real Target transaction.
Once that lock lifetime and every other Source transaction are covered, the
driver's default autocommit setting may use the same equivalence proof. Session
variables, named locks, output writes and unknown effects retain the original
setup requirement; an autocommit locking read cannot replace a real transaction.
The captured HTTP completion resource remains strict, including when another
HTTP read is allowed as shared initialization.

On expiry, only the current Case records `case_no_progress` and ends incomplete.
Its message leads with the number of recorded dependencies left unconsumed and
asks Target implementers to check the corresponding calls. The idle wait and
absence of in-flight dependency I/O are secondary stop details, rather than a
claim that a Target call was rejected or that the primary HTTP request timed out.
Other tail profiles retain their existing next-Case behavior. Native reports retain `case_execution_failures`,
matched/Target-unmatched/Source-unused evidence and bounded pending Source
references; runner execution-failure queries retain an independently observed
primary HTTP status. HTTP 200 does not certify async completion. `status` remains
readable while `end` waits and includes `session.waiting` (idle time, actual I/O,
and pending references). Rule reclassification cannot waive an execution failure.
This setting does not change Recorder/Source runtime timing or the separate
`dependency_loading.case_timeout_seconds` preparation budget.

`review check` owns the Source/Replay-isolation standard and never executes
repository quality commands. Outside pre-revalidation it returns success
without source scans and explains that no check is needed. Configure the final tool identifier
in `project.delivery.quality_check` (default `cargo-clippy`). At the existing
`pre_revalidation_review_required` stage, the integrator executes that tool on
the final committed target and managed projects. Only after success does it
report `--quality-check TOOL` through `review check --pre-revalidation`. The
engine matches the tool to canonical configuration and binds the agent's
attestation to the candidate and inputs; execution remains the agent's
responsibility. For `cargo-clippy`, use `cargo clippy --workspace --all-targets
-- -D warnings` in each applicable Rust project. Other language tools use their
project configuration. Formatting and unit tests follow repository instructions
and the changes being made. The existing publish, accept and full revalidation
sequence remains unchanged. Repository-specific requirements in `AGENTS.md` or
`CLAUDE.md` do not replace the engine Source/Replay-isolation standard.

Managed replay reads its target response limit from
`recorder.recording.max_body_bytes` in `project.yaml`.

Existing configuration is never overwritten. If any of the three required
configuration files exists, the whole initialization refuses without creating
another configuration file. Existing target source, Dockerfile, and unrelated
ignore-file rules are preserved. Normal
execution does not migrate or dual-read obsolete project schemas; migration
and repair require administrator-owned tooling outside `backend-rewrite`. Use
`backend-rewrite startup mount ensure <ABSOLUTE_PATH>` to add a path omitted
during initialization. When an administrator intentionally replaces or
refreshes captured content, recapture the exact declaration and then run
preflight:

```bash
backend-rewrite-admin --target-root <target> \
  startup recapture --confirm-replace
traffic-e2e diagnose preflight --target-root <target>
```

Recapture reads the initialization-owned local source snapshot; it does not
contact the original Pod. Preflight is read-only validation and does not repair
a stale snapshot. The initializer owns
the baseline `.gitignore` and `.dockerignore` generation described above; all
non-versioned runtime data lives below `.traffic-e2e/local/`. It creates an
empty mount snapshot under `.traffic-e2e/local/startup/` and a mode-0600
`.traffic-e2e/local/target.env`, importing the optional `--env-file` when
provided. Do not hand-write generated snapshot state.

After initialization, replace an upgraded source image and its effective
Kubernetes runtime inputs through the administrator API:

```bash
backend-rewrite-admin --target-root <target> source upgrade \
  --source-pod <ready-pod> --namespace <namespace> \
  [--pod-container <regular-container>] \
  [--kubeconfig /path/to/kubeconfig] [--context <context>] \
  --confirm-replace
```

This is not project initialization and never rewrites `project.yaml`,
the file named by `project.policy`, either Dockerfile, target
code, Git state, or `.traffic-e2e/local/target.env`. It captures the selected
Pod's new immutable image, effective environment, command and arguments,
security settings, and supported ConfigMap/Secret mounts into a validated
staging snapshot. The complete source snapshot content revision must differ
from the current baseline, so the same command also supports runtime-input-only
changes when the image ID is unchanged.
While holding the rewrite coordinator lock and requiring no live traffic
operation, it publishes the source snapshot, recaptures the exact existing
target startup declaration from that new source, and rolls the source snapshot
back if startup recapture fails. The next managed source run automatically
rebuilds an adaptor cached for another source image ID.

When the coordinator issued this change through a `source_change` system
repair, execute its exact `backend-rewrite repair verify <repair-id>` command
after the administrator upgrade. Verification detects the new source image
revision and requires fresh external standard recording evidence; the administrator
command does not bypass that coordinator transition. A runtime-input-only
upgrade does not change the image revision and therefore does not satisfy a
`source_change` repair. Runtime-input repairs use `external_data_blocker`
acceptance, which compares source runtime and startup snapshot revisions;
execute the acceptance command issued for that repair.

`backend-rewrite startup env` lists names, checks presence or exact equality,
ensures or removes a value, imports a dotenv file, and validates the canonical
file without returning stored values. `backend-rewrite startup mount` lists,
checks, or adds a missing source-compatible absolute path while preserving
existing captured content. Replacing or refreshing content remains
administrator-owned.

The initialized target repository contains `.traffic-e2e/Dockerfile.target`. It
is a BuildKit multi-stage build whose final image has a non-empty OCI entrypoint
and defaults to `USER 998:998`. Every target build requires a BuildKit SSH
mount. traffic-e2e manages its agent at
`.traffic-e2e/local/socks/ssh-agent.sock`, recreates a stale socket, loads the
calling account's default OpenSSH identities with `ssh-add`, and passes that
exact socket to `docker build --ssh`. The agent exposes signing only; keys
remain build-time inputs and are not copied into the image. Build output
continues to stream to the caller, while a bounded actionable tail is returned
through preflight and E2E API errors when Docker or Cargo fails. traffic-e2e
builds the image from the repository root, tags the cache as
`traffic-e2e/<project>-target:cache`, validates the resulting immutable image
ID, and runs that ID directly. A target start receives each declared startup
path at the same absolute path. A captured ConfigMap/Secret path preserves its
access; a path supplied by the immutable source image defaults to read-only.
Parent/child overlap is rejected. For example:

```text
.traffic-e2e/local/startup/mounts/data1/weibo/confs
  -> /data1/weibo/confs (source-compatible rw/ro)
.traffic-e2e/local/target.env
  -> target container environment (values are never returned by startup APIs)
```

Read-only startup inputs bind directly from the immutable snapshot. Writable
startup inputs are copied into a container/run-private directory before launch,
then mounted `rw`; the canonical snapshot is never exposed writable. Managed
source and target containers receive separate writable copies. Other
application Docker mounts are recreated as empty, destination-mirrored private
directories with their original `rw`/`ro` access. Docker-managed host files
(`/etc/hosts`, `/etc/hostname`, and `/etc/resolv.conf`) are not copied. Runtime mount
copies are removed after their owning container or managed run stops.

`target.runtime_outputs` is a separate output-only contract. Every configured
container path is mounted read-write from an engine-created, run-scoped host
directory below `.traffic-e2e/local/runtime-outputs/`. Diagnostic preflight mounts
the source role; Replay mounts the target role. Replay uses the
logical run and sequence in its host path, while managed recording uses the
recording run ID. The resolved paths and their roles are printed when a
container starts and returned by run/status or managed recording results.
`retention: keep` preserves them after container cleanup for host-side
analysis. Runtime output paths must not overlap each other, startup mounts,
or Replay-owned paths.

Runtime output contents do not update the startup snapshot and do not trigger
startup recapture. The host directory is below `.traffic-e2e/local/`, which the
required `.dockerignore` excludes from the target build context, so writes do
not invalidate target image build layers. Adding or changing the declaration
in `project.yaml` changes project configuration once, but subsequent log writes
remain runtime-only. Runtime outputs may contain sensitive application data;
they stay Git-ignored and are not consumed as Replay inputs or expected
responses. Remove retained run directories only under the exact
`.traffic-e2e/local/runtime-outputs/` root when they are no longer needed.

Every target start loads application-owned values captured in
`.traffic-e2e/local/source/`, followed by project-level
`.traffic-e2e/local/target.env` overrides. Initialization may seed the override
file from an optional dotenv file and does not inspect source code. The startup
env API can use `--from-source` without displaying a captured value. The engine
does not define a generic port variable or adapt framework-specific environment
names. The target contract contains no generic `TRAFFIC_E2E_CONFIG_DIR`,
`TRAFFIC_E2E_TARGET_PORT`, or `TRAFFIC_E2E_REPLAY_CA_CERT_PATH` variables.

During Replay traffic-e2e mounts the public Replay CA at
`/traffic-e2e/trust/replay-ca.pem`. If a target runtime needs an
application-owned environment variable for this fixed path, implementation
adds it to `target.env` through the startup API. Target TLS clients must add
that certificate to their normal trust store without reading Replay sessions
or private key material. The entrypoint must remain in the foreground and stop
cleanly on `SIGTERM`. Application logs belong in a configured writable runtime
output such as `/data1/weibo/logs`; stdout/stderr output is not required.
traffic-e2e owns network namespaces, readiness, signals, and cleanup.

Use the pinned shared Rust builder/runtime images and stable BuildKit cache
mount IDs described by the backend-rewrite initialization contract. A source
change reruns the relevant Cargo build layer, but cached registry, git, and
target artifacts prevent downloading the dependency graph again when the
builder identity and cache IDs are unchanged.

For diagnostic preflight, the runtime keeps a target-scoped
source-adaptor cache image. `.traffic-e2e/local/source/` is authoritative for
the immutable local image ID and captured Kubernetes runtime inputs; preflight does not contact the original Pod. The target repository
owns the reviewed `.traffic-e2e/Dockerfile.source` build contract. Adaptor
build binds the exact image ID through a deterministic temporary local alias
and labels the resulting adaptor with that ID. A missing adaptor or one labeled
for another source image or build-contract revision triggers a build/refresh.
The adaptor preserves the snapshotted source
command and arguments and does not send commands to port `880`. The manager forms a
non-recursive build context from regular files at the top of `.traffic-e2e`, so
`.traffic-e2e/local/` is never included.
The adaptor image's own `USER`, working directory, entrypoint, and command are
used at runtime; the manager does not regenerate a Dockerfile or infer launch
from `RUN_COMMAND`. Cleanup removes run-private containers but retains the
matching adaptor image. Standard recording uses
the separate project-owned `.traffic-e2e/Dockerfile.recording`; its caller owns builds and
container startup, and `traffic-e2e record` supervises Source/Recorder inside it.
Initialization and managed runtime do not provision a Breeze sidecar, inject
Mesh connection settings, or ship Java class patches. Existing projects must
remove the retired `project.breeze` setting and any obsolete patch-copy steps
from `Dockerfile.source`. Application-specific startup inputs use the normal
startup declarations; Breeze SDK use and Vintage response rewrite rules remain
independent of this startup contract.

Changes confined to the file named by `project.policy` (including case
pattern discovery) do not require code review
or invalidate an otherwise current accepted code review receipt. Both policies
remain part of the configuration commit gate and
traffic verification fingerprints; changed source, startup inputs and other
configuration still require the usual review. Candidate publication still
requires the exact reviewed commit.

Only final `review check --pre-revalidation` runs the built-in
target `replay-isolation` quality gate. It
examines only Rust lines added relative to `delivery.pr_base`, including
staged, unstaged, untracked, test, comment, and documentation lines. It does not
parse Rust syntax. New `.trp.test` occurrences are always rejected. New
case-insensitive `sample.test` or `demo.test` occurrences require an exact
`--hardcode-ai-verified TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN`
argument and a matching commit trailer
that identifies the source repository revision and source file line where the
same hardcode was verified. The target occurrence must already be committed at
that exact position. See the backend-rewrite workflow reference for the
canonical trailer format. Unchanged legacy occurrences are outside this
added-line gate.

The runner sends HTTP requests itself; the target image does not read cases or
write response reports. The configured port is shared by the image
environment, readiness, replay requests. Replay starts the target once for
the selected cases, intercepts dependency traffic by fixed UID, and prevents
uncontrolled external egress.

After initialization has generated the target template and the initialization
AI has reviewed and completed the generated `Dockerfile.source` scaffold,
run the authoritative preflight:

```bash
traffic-e2e diagnose preflight
```

It first validates the startup snapshot, then builds and statically inspects
the target image, starts the recording-environment preflight, and finally starts
a real Replay session with the fixed network probe image and the same target
image. The system automatically records exactly one `GET` for the configured
readiness path with its finalized source response; this validates standard
recording and is not a business sample. Recording also publishes exactly one
marked
`demo.test` Global dependency; Replay must consume it through fake DNS, reject
payload sent to unrecorded `example.com:443` with `unrecorded_targets`
evidence, and block direct external egress for UID `998`.
Source-local port `880` is not a preflight dependency and receives no managed
switch commands; the configured HTTP Gateway readiness contract remains
authoritative. The HTTPS probe runs before the one-case readiness request. The
Java probe command has a 10-second execution bound. Ordinary recording does not repeat this initialization gate, and Motan business traffic
is not requested or evaluated during initialization preflight.

Later, `traffic-e2e record` applies the Motan gateway failure check. Its result
reports `motan.status: verified` after at least one
published Motan case or `not_observed` when that recording still contains no
Motan request. Gateway errors and failed admitted cases make the recording
command fail instead of silently completing.

Full success returns overall `status: passed` with separate `target_image`,
`recording`, `replay_network`, and `target_runtime` results. Target identity,
startup environment, mount access, listener, readiness, clean `SIGTERM`
shutdown, and cleanup are validated after the target starts with dependencies
from the preflight recording; the successful checks are
written to `reports/target-runtime-checks.json`, while normal stop evidence
proves clean shutdown and cleanup. A failure prints bounded JSON
containing `status: failed`, the failing stage, and a reason, exits nonzero, and
does not advance rewrite state. Manual `docker build`/`docker run` output is
diagnostic only.

The lower-level commands in the remainder of this section are the traffic
engine interface used by the coordinator and by traffic-e2e maintainers. They
are not the normal rewrite-AI workflow.

Prepare each API after confirming whether its source URI is static or dynamic:

```bash
traffic-e2e prepare \
  --target-root ../target \
  --case-source recordings/<run> \
  --case-dir recordings/<run>/apis/<api-directory> \
  --method GET \
  --source-route '/api/widgets/:id' \
  --pattern '/api/widgets/*' \
  --source-revision <revision>
```

Use the returned group id for the focused migration loop:

```bash
traffic-e2e run-api \
  --target-root ../target \
  --case-source recordings/<run> \
  --api 'GET /api/widgets/*'
```

One attempt starts Replay once, starts the target once, executes every selected
case through the runner-owned HTTP driver, stops the target once, and finalizes
Replay. The terminal JSON reports independent `responses`, `replay`, and
`dependencies` gates plus a bounded `diagnosis` containing counts, clustered
Pointer/kind differences, and one representative expected/actual observation.
Value presence explicitly distinguishes JSON null, missing, unavailable, and
not-applicable evidence.

During an active attempt, the complete internal `state.yaml` is persisted only
at lifecycle checkpoints needed for recovery and once more for terminal
publication. Per-case status uses a small replace-only `progress.json` without
durability syncs, so status can report build, replay progress, and finalization
without repeatedly serializing the full case inventory. Recovery treats that
progress file as informational and never resumes partial case results.

Normal AI operation starts with the bounded terminal result. Representative
evidence links directly to an immutable recorded case for request, expected
response, and dependency inspection, and the AI may inspect any other artifact
as needed. Prefer coordinator APIs over inspecting
`.traffic-e2e/local/runtime/**`; the directory contains implementation-level
state whose layout is not a stable interface. Treat it as read-only and never
infer or mutate workflow state from file recency. Generated assertion details,
aggregate reports, `.active`, and `latest` are implementation surfaces rather
than ordinary migration evidence.

Run the current complete API group only until it passes, then stop. Focused
attempts replace the selected API's terminal contribution to the current
logical recording run. `.traffic-e2e/progress.yaml` is the single public
business ledger for standard live-traffic recording batches. Only copying one
new standard batch from live traffic increases run and case coverage. Replay and any retries only settle that standard batch's current
result; even one hundred verification attempts never add another run or case.

Progress is published in two steps. Recording completion immediately increases
`executed` coverage, exposes the latest batch with `passed: null`, and clears
the global streak plus only the per-API streaks covered by that batch. APIs not
present in the recording keep their streaks. A terminal result then updates
`passed` counts. Success reconnects the streak that existed before recording
only when the batch never failed; after any failed attempt, later success for
the same batch starts at one run and that batch's successful case count. A
retry never increases `executed`.

Focused dependency reclassification compares progress after applying the same
scope merge used by publication. A partial prepared inventory retains the
unfinished recording's other API observations; different case counts or results
still reject revision, and a complete inventory still requires matching scope.

Read-only coordinator status checks shared-session reclassification against the
published group membership rather than discovering recording cases. Methods and
action projections reuse one snapshot per query; the next query reloads changed
rules, sessions, and reports. Report checks deserialize only classification
metadata and skip unrelated JSON values. Actual evidence revision still loads
and validates the recording inventory and progress before writing anything.
Both paths validate a repair subset using the same prepared API fingerprint and
complete partition of selected and skipped passed cases. Missing, overlapping,
unknown or duplicate case identities remain invalid; final Replay cannot skip.
While case pattern identification waits, a pinned recording reuses the pending
batch's persisted API observations even before installing the API inventory.
Status still checks the completed recording manifest and current selectors;
pattern apply and initial adoption retain full case validation.
Legacy selectors resolved only by recorded `api_pattern` metadata fall back to
validated discovery when the current policy and observation snapshot cannot
establish membership.

The committed file contains only business aggregates and the latest batch
summary. Replay provenance, pending state, failure barriers,
idempotency keys, and ordered observations remain in the ignored
`.traffic-e2e/local/artifacts/progress/counted-runs.yaml` ledger. That local
ledger is runtime authority and can reconstruct a reset public snapshot.
The public API list excludes concrete paths already covered by a same-method
case pattern in the cumulative progress inventory. This applies to numeric,
UUID and named members alike; numbers alone never cause an API to be hidden.
`totals.apis.covered` counts the visible API entries. Historical per-member
observations remain in the local ledger and global run/case totals are retained;
member counters are not added to pattern counters because historical coverage
may overlap. Every publication, including reconstruction and epoch transitions,
uses the same projection, so old member entries cannot reappear after Replay.
Existing `replay-progress.yaml` coverage is migrated once and that file is
removed after `progress.yaml` is durably published.

```yaml
version: 3
updated_at: 2026-08-15T02:00:00Z
totals:
  runs: { executed: 45, passed: 11, success_streak: 1 }
  cases: { executed: 7916, passed: 7307, success_streak: 386 }
  apis: { covered: 3 }
latest_run: { passed: true, apis: 2, cases: 386 }
apis:
  GET /api-a:
    runs: { executed: 14, passed: 6, success_streak: 4 }
    cases: { executed: 422, passed: 414, success_streak: 20 }
```

When the rewrite coordinator accepts a newly finalized standard recording, it
starts a new verification progress epoch. The preceding public aggregate becomes
the new epoch's baseline, so cumulative totals, per-API totals, streaks, and the
latest run remain continuous. The preceding counted-run and observation ledgers
are retained under `.traffic-e2e/local/artifacts/progress/history/` for diagnosis
but are not loaded into the new epoch; only runs observed in the current epoch
participate in its idempotency checks. An epoch created by an older binary with
an empty baseline is rebuilt from this archive before its public snapshot is
published.

Intermediate attempts do not require Git commits for progress. After every API
is verified, the rewrite coordinator synchronizes the final public
`progress.yaml` snapshot and returns
`input_required/verification_progress_commit_required` until every dirty,
coordinator-managed delivery file is committed: the file named by `project.policy` and `progress.yaml`. The action lists only the dirty
paths. A reset at that gate is reconstructed from the local ledger and cannot
make terminal completion available.

After every published case is prepared exactly once and every focused group
passes, the grouped result is sufficient unless behavior-affecting code changed
after an earlier group pass. In that case, run the complete regression round:

```bash
traffic-e2e run \
  --target-root ../target \
  --case-source recordings/<run>
```

The full command uses the same single target lifetime for the complete round,
atomically publishes runner-owned evidence, and updates
`.traffic-e2e/progress.yaml`.

The current logical run passes only with complete response, Replay, and dependency gates.
Use `status`, `abort`, and `recover` for interrupted global rounds; never repair
runner state through filesystem edits.

When managing host interception directly, always pair `up` with `down`:

```bash
sudo traffic-e2e diagnose interception dns up
sudo traffic-e2e diagnose interception fake-ip up
sudo traffic-e2e diagnose interception fake-ip down
sudo traffic-e2e diagnose interception dns down
```

## Recording Files

Recording access can be limited with the recording configuration:

```toml
[recording]
access_policy = "block_known_writes"
```

`unrestricted` is the default and preserves normal forwarding. The
`block_known_writes` policy rejects requests classified as writes by the HTTP,
MySQL, Redis, Memcached, and Kafka adapters. Read, session-setup, unknown, raw
TCP, and UDP operations continue to be forwarded, so this compatibility policy
is not a strict security boundary. Rejections are written to `traffic.jsonl` as
payload-free `readonly_rejection` events. A rejection during an active HTTP
gateway case is also added to that case's `dependencies.jsonl` for diagnosis
and invalidates the whole case. The case is moved under `failed/` and is never
published as replay evidence. A rejection outside an active case remains a
run-level audit event and does not create dependency evidence.

`block_known_writes` can explicitly allow narrowly scoped MySQL writes:

```toml
[[recording.access_rules]]
name = "allow-request-log-insert"
effect = "allow"
protocol = "mysql"
operations = ["insert"]
routes = ["audit-db"]
databases = ["pluto"]
tables = ["request_log"]
```

`operations`, `databases`, and `tables` are required and non-empty. A rule must
also contain at least one exact `route` or business `target`; when both are
present, both must match. Supported operations are `insert`, `update`,
`delete`, `replace`, and `upsert`. A missing field, empty required list,
unsupported operation, incomplete SQL classification, multi-table write, or a
multi-statement query not wholly covered by one rule is rejected. Database and
table identifiers are matched exactly and case-sensitively. Mixing session
changes such as `USE` with an allowed write in one multi-statement query is
also rejected. Rules cover the SQL-visible target only; operators must account
for database triggers or other server-side side effects on an allowed table.

An allowed write is forwarded and recorded as a normal `mysql_exchange`, so it
can remain part of a valid case dependency contract. The rule match is also
audited in run-level `traffic.jsonl` as a payload-free `access_policy_allow`;
that audit event itself is not appended to `dependencies.jsonl`.

The automated gateway GET plus dependency GET/POST scenario lives in
`tests/readonly_case_integration.rs`. The local two-mock and optional
cross-machine manual procedure lives in `tests/manual/readonly/README.md`.

Generated runtime artifacts are ignored by git:

- `target/`
- `data/`
- `.traffic-e2e/local/`
- legacy `recordings/`
- `*.swp`

Do not commit generated CA files, traffic recordings, test captures, or local
swap files.

New recorder configurations use one artifact root for standard recording batches:

```text
<artifacts.root_dir>/
  recordings/<run-id>/
```

Each recorder process creates one run directory under
`<artifacts.root_dir>/recordings/` named `YYYYMMDDHHMMSS`. Valid case output is
published inside that run:

```text
<run-id>/traffic.jsonl
<run-id>/recording-run.json
<run-id>/recording-network.json
<run-id>/errors.jsonl
<run-id>/global-dependencies.jsonl
<run-id>/global-dependencies-summary.json
<run-id>/pre-readiness-traffic-summary.json
<run-id>/source-process-traffic-summary.json
<run-id>/global-dependencies-debug.jsonl
<run-id>/apis/<api-directory>/<case-id>/request.json
<run-id>/apis/<api-directory>/<case-id>/expected-response.json
<run-id>/apis/<api-directory>/<case-id>/dependencies.jsonl
<run-id>/apis/<api-directory>/<case-id>/dependencies-summary.json
<run-id>/apis/<api-directory>/<case-id>/dependencies-debug.jsonl
<run-id>/failed/<api-directory>/<case-id>/
```

Every newly published case contains `dependencies.jsonl` and
`dependencies-summary.json`, including cases with no semantic third-party
dependencies. For a zero-dependency case, `dependencies.jsonl` is empty and
the summary has `total_events: 0`. This distinguishes a confirmed empty
dependency contract from missing capture evidence.

Every finalized run also contains `recording-network.json`. It stores the
deduplicated DNS names queried by the source and the exact `host:port`
endpoints actually reached through the TCP or UDP gateway. Replay requires
this run-level manifest and does not derive a compatibility allowlist from
semantic dependency files. A recording without the manifest must be recorded
again. A queried domain with no accessed endpoint receives an empty DNS answer
during Replay: a DNS observation alone does not prove Source obtained a usable
address, and Replay must not invent a reachable address for DNS-only activity.
This retains the recorded absence of transport, without claiming the original
DNS response code. Domains with accessed endpoints keep fake-IP routing and
strict port checks; entirely new domains keep quarantine routing. During
Replay, an endpoint outside the manifest may resolve and accept a
TCP connection. If the target sends payload on that connection, Replay closes
it before protocol handling and reports `访问了录制时没有访问过的域名:port` in
the Replay report and bounded dependency evidence.

Failed cases are diagnostic artifacts, not replay fixtures. A case with a
truncated request or expected response body is kept under `<run-id>/failed`
with `recording-error.json` instead of being published. Successfully published
cases remain in their normal API directories when another case fails. A clean
shutdown reports `status: completed` and exits successfully even when
`failed_cases` is nonzero; consumers select only canonical published cases and
use `failed_cases` plus `errors` for diagnostics. `status: failed` and a
nonzero process exit are reserved for Recorder-level runtime or finalization
failure.

A complete zero-length response body is publishable even when its
`Content-Type` advertises JSON. Recorder preserves the empty body and replay
assertions compare it as exact bytes. Non-empty bodies advertised as JSON must
still contain valid JSON.

Use `dependencies.jsonl` for replay-oriented semantic data. Use
`dependencies-debug.jsonl` only for protocol-level debugging. UDP datagrams,
including push-metrics side effects, are recorded as semantic dependencies when
captured by the UDP gateway. Run-level
Global dependency files contain replay-oriented startup traffic plus explicit
process-owned-rule matches. Replay discovers them by walking upward from a case
directory and prefers Case before Global. Ordinary exchanges are consumed
once. Marked Redis process-owned snapshot seeds are reusable for identical
logical reads.
Automatically generated `dependency.process_dependencies.*` names depend on the
Source task and request selectors, independently of the Source revision. The
revision remains part of Source proof validation and policy fingerprints.
Historical names included the revision. Replay admits an older marked Redis
seed under a current generated process rule only when its port, command, key and
argument selectors still match. The original rule name remains recorded
provenance; it does not authorize reuse without a matching current policy.
Explicitly authored rule names retain exact-name matching. Snapshot overlays use
the same admission and retain their complete coverage and response-consistency
checks.
`pre-readiness-traffic-summary.json` is a bounded projection of only source
`bootstrap` data interactions grouped by `host:port`. It excludes connection
lifecycle events and known ping, heartbeat, and setup exchanges. The rewrite
coordinator exposes the projection through its opaque evidence-query API, so a
target AI does not need to read this file or the Global JSONL directly.
`source-process-traffic-summary.json` is an independently bounded writer-owned
projection exposed through the issue-scoped rewrite evidence API. It separates
all pre-readiness data interactions from configured process-owned-rule traffic and
retains protocol, `host:port`, operation, and count. Redis process-owned snapshot
facts include successful seeds, later recorder reuses, fill failures, and the
same counts per intercepted domain and port. Snapshot hits remain absent from
replay dependencies; the summary counts them before that persistence filter.
These observations are diagnostics for startup, refresh, and local-cache
hypotheses, not proof of business ownership or response causality.

Completed protocol events are moved by unique ownership into one asynchronous
JSONL writer. `recording.writer_queue_capacity` bounds this queue by event count
(default `65536`); it does not impose a byte budget. Producers never wait for
free queue capacity. A full or closed queue marks the recording as failed so
traffic forwarding is not delayed and an incomplete recording cannot be
published as successful. Case and run finalization send ordered flush commands
through the same writer, so queued dependency reservations remain in flight
until their records have been persisted.

Redis reads matched by a process-owned dependency rule use a bounded run-local
first-value snapshot. Recorder owns the internal retained-response capacity;
`cache_snapshot_max_waiters_per_entry` bounds concurrent readers waiting for
the first response, and `cache_snapshot_fill_timeout_ms` bounds that wait.
Successful responses become sticky for the run; Redis errors are delivered to
current waiters but are not retained.

Source-proven process-level HTTP polling can be classified through a
self-contained native rule:

```yaml
id: config-refresh
match: {}
effect:
  kind: process_owned
  source_revision: ''
  selector:
    protocol: http
    authorities: [config.internal]
    methods: [GET]
    path_prefixes: [/refresh]
proof:
  source: src/config/refresh.rs:42
  fact: A process scheduler refreshes this exact endpoint independently of APIs.
```

Initialization creates an empty policy and adds no service-specific ownership
rules. Vintage configuration and naming HTTP calls remain ordinary Case dependencies;
response capture and protocol decoding do not grant process ownership.
HTTP, Motan and Memcached ownership preserves their existing finite
consumption. Redis snapshot-producing selectors affect capture and runtime;
new authorization conservatively requires fresh recording. Classification-only
changes may derive a report from immutable complete Source evidence, while
Target context obligations still require Replay. The plan enumerates these
obligations instead of inferring success from reclassification.

The coordinator also detects an already-finalized attempt whose effective
dependency view is clean but whose persisted errors still contain the obsolete
strict dirty-finalize result. `backend-rewrite next` removes only that
dependency-derived error, preserves genuine lifecycle errors, revises the same
attempt, and completes the API without rerunning E2E.

Use a finalized replay report to create the AI-managed rule instead of editing
the table directly:

```bash
traffic-e2e config recorder apply process-owned-dependencies \
  --target-root . \
  --name config-refresh \
  --case-source <exact-finalized-case-source> \
  --source-revision 0123456789abcdef \
  --evidence 'src/config/refresh.rs:42 process-level scheduled refresh' \
  http \
  --authority config.internal \
  --method GET \
  --path-prefix /refresh
```

The action requires at least one matching unused case HTTP exchange and rejects
a selector that also matches unmatched or unsupported target requests. It
replans against the current recorder config and replay report immediately
before its atomic write. Automated planning remains exact to one authority,
method, and path prefix. When an existing multi-selector rule already covers
that selector, planning reuses the existing rule instead of adding an
overlapping rule.

Source-proven process-owned Motan traffic uses one exact RPC identity:

```bash
traffic-e2e config recorder apply process-owned-dependencies \
  --target-root . \
  --name kunpeng-refresh \
  --case-source <exact-finalized-case-source> \
  --source-revision 0123456789abcdef \
  --evidence 'MapiConfigLoader.java:init scheduled refresh unrelated to selected API' \
  motan \
  --group kunpeng-config-rpc \
  --interface-name com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc \
  --method-name getConfigByName
```

The rule stores no node hostname, port, Vintage alias, or request payload. It
matches Motan exchanges with the exact Vintage service group, interface, and
method. Planning requires a matching unused case exchange and rejects the
selector when the same RPC command appears in unmatched, unsupported, or unsafe
target traffic.

A process-owned Redis scheduler using exact keys can use a command-specific
`get`, `scard`, or `hgetall` selector:

```bash
traffic-e2e config recorder apply process-owned-dependencies \
  --target-root . \
  --name startup-cache-warm \
  --case-source <exact-finalized-case-source> \
  --source-revision 0123456789abcdef \
  --evidence 'src/cache/warm.rs:init loads response-driving local state' \
  redis \
  get \
  --port 20917 \
  --key cache:init:a \
  --key cache:init:b \
  --initial-load-timeout-ms 60000
```

Planning requires every configured exact key in replay-safe immutable
evidence. When old Global bootstrap evidence and every matching Case response
are byte-consistent, Replay derives a read-only snapshot overlay and reuses one
referenced Global seed for repeated exact target, session, command, and
argument matches. Otherwise a fresh recording is required; Recorder forwards
the first successful matching read and holds that response for the rest of the
run. Neither path inherits the source connection binding or earlier unrelated
lane commands. Case and unmarked bootstrap exchanges retain connection-order
semantics.

For example, replace `get` above with `scard` or `hgetall` while retaining the
same `--port`, repeated `--key`, and `--initial-load-timeout-ms` inputs. These
selectors do not accept key prefixes, patterns, fields, or a generic command
argument.

Breeze-backed Memcached profile or local-cache warm traffic uses a bounded
numeric key series:

```bash
traffic-e2e config recorder apply process-owned-dependencies \
  --target-root . \
  --name planet-video-cache-warm \
  --case-source <exact-finalized-case-source> \
  --source-revision 0123456789abcdef \
  --evidence 'TopUserServiceImpl.java:691 scheduled local-cache warm' \
  memcached \
  --breeze-resource user-video \
  --key-start 0 \
  --key-end 4095 \
  --key-separator . \
  --key-suffix pl_video \
  --initial-load-timeout-ms 60000
```

The tool requires one compatible Breeze `mc` descriptor, persists its complete
stable identity without the dynamic port, and resolves the port when the
source-created descriptor is available. Runtime matching uses port as a coarse
filter, then requires Memcached `get` and the exact bounded numeric key series.
The numeric prefix bounds are unsigned 64-bit values, including UID-derived
keys above `4294967295`. The source revision remains in plan evidence rather
than runtime configuration. If the cache warm affects API behavior, implement
the source-compatible target cache lifecycle separately from this ownership
rule.

Bootstrap Redis `HGET`/`HMGET` rules do not add an initial-load wait. They
combine optional exact keys with compact `prefix<digits>suffix` patterns and
require the exact field sequence. Applying one through the rewrite coordinator
still requires a fresh externally produced standard recording so its first-value
seed is explicit.

Process-owned Redis `HSCAN` rules likewise use exact keys or compact
`prefix<digits>suffix` patterns, but have no field selector or initial-load
wait because cursor and scan options are response-driven. They require unused
Case evidence and a fresh recording: Recorder then writes matching HSCAN
traffic as connection-independent Global `background_rule` evidence, so it
cannot block later target commands in the source connection lane. Existing
Case-only recordings are not rewritten to fabricate that Global evidence.

An applied rule with `initial_load_timeout_ms` delays source case admission
while Recorder observes its initial load. Redis exact-key `GET`, `SCARD`, and
`HGETALL` rules count each configured exact key once;
Memcached counts `key_end - key_start + 1` completed replay-safe matches. The
observations include matches before HTTP readiness. After the ready probe,
Recorder observes for at most `initial_load_timeout_ms` (60000 by default),
logs progress every 10 seconds, and warns but continues case admission when
the load remains incomplete. Without an initial-load timeout there is no
additional observation window. This source-recording wait does not classify
response causality and does not apply to target-local cache initialization
during Replay.

Recognized MySQL connection maintenance is not a required business dependency. The
strict built-in fingerprints are protocol `COM_PING`, c3p0's exact
empty-database `SHOW FULL TABLES` probe using the `PROBABLYNOT` sentinel, and exact
`SELECT 1` with an optional trailing semicolon. Their raw `mysql_query` and
`mysql_response` records remain in the applicable case or Global debug
JSONL. COM_PING exchanges also remain in semantic dependency JSONL as explicit
connection sequence/status proof for read-only session classification; summaries
and required-exchange counts omit them. The probe queries' derived exchanges
are omitted from semantic JSONL. Replay handles the same fingerprints without a
recorded exchange: ping returns OK, `SELECT 1` returns one integer row, and the
c3p0 empty-database probe returns MySQL error 1102.

MySQL has no per-command response correlation ID, so Recorder preserves every
response-bearing command in a connection-local FIFO and assigns server packets
only to its oldest pending command. This covers clients that send a query and
then `COM_PING` before the query result arrives without misclassifying the
query as incomplete or assigning its resultset to the ping. The FIFO is bounded
to 64 commands and 16 MiB of retained request payload per connection; exceeding
either bound fails the connection rather than guessing response ownership.
Intrinsic no-response commands do not consume or flush the FIFO.

MySQL recording flushes each complete forwarded wire packet, including TLS
ciphertext, independently of semantic response completion. This keeps delivery
working when a response form is not recognized by the semantic tracker; it does
not extend semantic recording or replay support for those forms. Completion
events are published only after the corresponding downstream flush succeeds.
Motan replay connections and HTTP readiness probes use TCP_NODELAY, consistent
with the other engine request paths.

Redis and Memcached dependencies are semantic `redis_connection`,
`redis_exchange`, `memcached_connection`, and `memcached_exchange` records.
Successful Redis authentication/session initialization is handled by replay
and omitted from case dependencies; failed initialization remains as redacted
evidence. When an otherwise matching business command has a recorded authenticated
username but no observed target authentication, Replay reports an authentication
state mismatch and suggests checking password configuration and client wiring.
This does not establish that a password was omitted, and Replay does not validate
password values. Other username, database, and protocol differences remain strict.
Any truncated frame, parse/correlation failure, unsupported cache
mode, or unsafe cache connection prevents a case from being published and
prevents unsafe Global replay from starting. The recording directory is
sensitive because ordinary cache keys and values are needed for exact replay.

Well-formed `CLIENT SETINFO LIB-NAME` and `CLIENT SETINFO LIB-VER` announcements
are SDK metadata, not business dependencies, whether Redis returns success or
an error (including servers or proxies without SETINFO support). With full traffic
logging enabled, Recorder retains these exchanges in `traffic.jsonl`, while
excluding them from semantic case
and Global dependencies. Replay also excludes them when loading older recordings,
without changing the files or requiring re-recording. Target SDKs may omit the
announcements or send their own library name and version; Replay accepts valid
announcements with `+OK`. Authentication and database selection failures remain
strict. This exemption requires a well-formed announcement and a complete response;
it does not bypass unsafe or truncated capture validation.

Redis Pub/Sub support is intentionally bounded to a single RESP2 subject
argument for `SUBSCRIBE`, `PSUBSCRIBE`, `SSUBSCRIBE`, `UNSUBSCRIBE`,
`PUNSUBSCRIBE`, or `SUNSUBSCRIBE`. Recorder accepts only the exact three-element
confirmation (or an ordinary Redis error): command and binary-safe subject must
match the request, with a positive subscription count or a nonnegative
unsubscription count. Successful confirmations add or remove only that channel,
pattern, or shard channel; errors do not change subscriptions. Recorder forwards
matching RESP2 `message`, `pmessage`, or `smessage` pushes without treating them as ordinary
request responses. Confirmed pushes are retained as finite semantic evidence;
Replay delivers them after the matching subscription, and correlated RPC
callbacks retain their request admission. See [Redis Pub/Sub](redis-pubsub.md)
for process ownership, identity translation and historical-recording limits. The entire recorded Pub/Sub lane stays bound to one target
connection, including ordinary commands after unsubscription. Removing the last
subscription restores ordinary response handling on the recorded connection.
A malformed push or one that does not match an active subscription remains a
capture error. Multiple subject arguments, no-argument unsubscribe-all commands,
and RESP3 push frames remain unsupported. Re-record cases rejected by an older
Recorder for unsupported unsubscription; existing failed evidence is immutable.

Case-owned Memcached matching treats recorded physical connections as source
lanes, not as a required one-to-one connection topology. One target connection
may consume matching exchanges from multiple recorded source lanes, which
allows source and target connection pools to have different widths. Replay
still preserves the order within every recorded source lane and still requires
the exact target, wire protocol, command, key, arguments, value, CAS, quiet,
and noreply semantics.

Redis also permits ordinary data commands (including GET/MGET, hash reads,
SET and DEL) to span recorded physical connections. One pooled target connection
can consume multiple short source lanes, and multiple target connections can
consume one source lane in recorded order. Endpoint, database, authenticated
username, RESP version, command and exact arguments remain strict. Repeated
requests consume separate recorded exchanges; pool compatibility does not
make responses reusable or relax case/Global ownership. Successful SDK setup
and CLIENT SETINFO metadata retain their existing handling.

Ordinary EVAL/EVALSHA and their read-only variants also permit pool reuse.
SCRIPT LOAD/EXISTS/FLUSH/KILL/HELP operate on the Redis server's script subsystem,
so they do not by themselves require a physical connection claim. Recorded
NOSCRIPT failures, script loading and retries remain finite exchanges in source
lane order; Replay does not simulate a script cache or interpret Lua. Script
body/SHA, keys and arguments still match exactly unless an explicit dependency
rule covers a field such as a lock ownership token.

Replay classifies source lanes before serving requests. A lane containing a
retained session operation, WATCH/MULTI/EXEC, subscription, blocking operation,
WAIT, SCRIPT DEBUG or unknown command/subcommand retains connection binding for
the entire lane, including its ordinary-command prefix and suffix. A stateful
source lane belongs to one target connection within the active case; another
target connection cannot steal its next exchange. This does not split a
recorded transaction into independently replayable fragments. Explicit
process-owned background/snapshot rules retain their existing behavior.

No rule, new recording, or per-call target connection workaround is needed for
ordinary Redis pool differences. If such a difference alone fails replay,
investigate the engine version and matching evidence instead of duplicating
the source pool size or connection lifetime in target code.

Motan also preserves every recorded source lane's order. When concurrent target
connections or multiplexed frames arrive in a different order, Replay keeps a
bounded per-connection pending queue. A request matching a later exchange waits
briefly for the recorded predecessors instead of failing immediately.
Completing a predecessor wakes blocked connections and retries queued frames in
lane order. If a predecessor never arrives, Replay retains the `lane_blocked`
diagnostic. Non-ordering mismatches still fail immediately.

Semantic MySQL, Redis, Memcached, Kafka, and Motan business exchanges also carry
`outcome` and `duration_ms`. Replay waits the recorded duration before a normal
response. If `outcome` is `client_terminated`, replay sends no response and
consumes the exchange only after the SDK closes or resets the same connection
near the recorded time; replay itself does not initiate that close. Intrinsic
no-response commands remain `no_response` and are not treated as timeouts.

New recordings additionally support structured `terminated` outcomes carrying
the observed peer, mechanism and scope. Server EOF/reset is replayed as a server
action; client termination requires Target's own action. Supported delivered
response prefixes retain their original timing. Capture interruption and
unsupported partial framing remain separate failures. See the
[shared dependency termination contract](dependency-termination.md).

HTTP and HTTPS dependencies also support `outcome: client_terminated` when a
complete request was captured but the client closed or reset its connection
while awaiting the buffered upstream response. This applies to the explicit
proxy (including CONNECT/TLS) and the fake-IP HTTP/HTTPS gateway. Cancellation
preserves the request and its original Case/Global admission ownership in
`dependencies.jsonl`; recorder task cancellation without observed client
termination remains a capture error. HTTPS upstream certificate verification
remains strict.

HTTP timeout replay matches the ordinary method, endpoint, path, body, and
header contract, then sends zero response bytes. It consumes the exchange only
after the client closes or resets the connection. All supported dependency
protocols use the same timing tolerance: at most 50ms earlier or 1000ms later
than the recorded `duration_ms`. A client that closes too early, too late, or
never closes leaves the exchange dirty; the upper bound only limits cleanup,
and engine-initiated cleanup is not successful client termination. This
contract does not support a call-level timeout that leaves the connection
open. Legacy HTTP client-termination evidence with missing timing, truncated
requests, response bytes/headers or capture errors is rejected. Version-2 HTTP
stream evidence can retain response headers and a timed prefix before the
recorded peer termination. Legacy successful HTTP
records without `outcome` retain their response behavior; missing historical
timeout exchanges cannot be recovered by upgrading Replay.

Legacy Motan dependencies are semantic `motan_connection` and
`motan_exchange` records. Recorder recognizes the F1F1 outer frame containing
the F0F0 inner frame, supports codec versions 1 and 2 (including gzip-compressed
codec-2 method metadata), correlates responses by request ID, and records exact
binary request/response frames plus method identity. Replay matches business
calls by codec, method identity, and recorded connection order, waits the
recorded duration, and patches both response request IDs to the live request.
Standard Motan heartbeat exchanges stay in `dependencies-debug.jsonl` and out
of semantic dependencies and summaries; replay may use a recorded debug
heartbeat response as a reusable template across nodes in the same pool.
This legacy dependency path supports only the nested Motan1 framing and fails
closed on Motan2. The primary `motan_gateway` path described above separately
supports both Motan1 and Motan2 through `breeze/motan`. Recorder deliberately
does not deserialize arbitrary Java arguments: it preserves exact frame bytes
and replay uses method identity plus recorded connection order. Those frames
may contain sensitive business objects, so protect the recording directory as
production data.

Kafka dependencies are semantic `kafka_connection`, `kafka_produce`,
`kafka_fetch`, and `kafka_delivery` records. Each Fetch exchange records its
requested topics, outcome, duration, and associated deliveries, including
empty and client-terminated Fetches. V1 is a constrained dependency facade
rather than a full Kafka broker: use an E2E client profile with
`security.protocol=PLAINTEXT`, `compression.type=none`,
`enable.idempotence=false`, and `acks=1`. Replay advertises one broker and one
partition, synthesizes control-plane responses, matches Produce by exact topic,
key, headers, and value bytes, and delivers each recorded Fetch result once.
Transactions, Admin APIs, compression, TLS/SASL, rebalance behavior, retries,
and Kafka failure injection are unsupported and fail closed. Schema Registry
remains an ordinary HTTP dependency. Kafka payloads and headers are sensitive
because exact bytes are required for replay.

Case dependency summaries are generated when each case is published.
Startup Global dependency files are flushed before case admission opens, while
the writer remains available for runtime background matches. The potentially
large Global summary is generated only when the run finishes; summaries are
not rebuilt after every cache exchange.

## Dependency preparation

See [dependency-index.md](dependency-index.md) for persistent indexes, case loading,
cache budgets and the separate index/Replay readiness deadlines. Managed Replay
uses these defaults for existing version-18 configurations.

## Testing Guidance

Add unit tests near the parser or module being changed. Add integration tests in
`tests/proxy_integration.rs` when changing externally visible proxy behavior.

Useful focused test commands:

```bash
cargo test mysql::wire
cargo test recorder::mysql::semantic
cargo test proxy_integration
cargo test redis::
cargo test memcached::
cargo test replay::command_protocol_tests
cargo test kafka::
cargo test motan
```

Network or root-requiring behavior should be covered with isolated unit tests
where possible. Do not require host iptables changes for automated tests.

## Replay execution failures and idle time

Control clients may cancel observation requests or close before reading a reply.
Their EOF/reset/broken pipe is isolated to that connection; Replay keeps serving
the active case. A committed finalize still publishes and stops if its reply has
no reader. Incomplete runtime publication takes precedence over earlier case
failures in rewrite routing, while preserving their response observations and
the most recent bounded lifecycle errors for diagnosis.

An actual unmatched dependency or failed Replay delivery interrupts only the
current primary request. Ordinary HTTP, streaming HTTP, WebSocket, Socket.IO
and Motan use the same execution feedback; a business HTTP 5xx is not required.
The case records `execution_failure.kind: dependency_unmatched` and
`request_completed: false`, with bounded protocol/event diagnostics. An already
observed primary status remains a separate fact. Complete stream observations
and interrupted framed prefixes remain protected evidence. Already started
case I/O retains its normal drain barrier; unused Source calls remain unused.
An unmatched Redis, MySQL or Memcached request closes its dependency connection
without synthesizing a protocol business error; an unmatched HTTP request returns
502. The native dependency report retains the rejected command and its matching
diagnostic. Recorded business errors still replay as ordinary protocol replies.
After cleanup, finite and interaction requests continue under the per-API failure
limit (`verification.max_failed_cases_per_api`, default 10). A missing dependency
call or unclean primary closure fails the current Case without ending the whole
attempt. A no-progress failure preserves every unused Source dependency and
drains accepted I/O before releasing Case ownership. An actual cleanup or Replay
infrastructure failure still reports an interrupted attempt. No failed Case or
partial coverage becomes a pass. Public `diagnosis.execution_failures`
and the dirty-cluster evidence query expose these causes before downstream
missing responses, stream events or unused calls. No expected output drives
request execution and no response or ACK is synthesized.

Backend rewrite issue selection prioritizes these actual execution failures over
response assertions and opens dependency investigation. The evidence overview
also exposes same-attempt execution failures for retained response issues, with
the dependency diagnosis command first. It preserves issue identity and does not
borrow failures from newer attempts. Other cases retain their independent
response differences; unused inventory alone does not change issue priority.
Global-format plan failures identify Source self-validation versus independent
Target validation, the response/dependency surface and original case or trace
record. Dependency comparisons retain witness and slot references; differences
retain their logical JSON pointers. These locations expose no payload values.

The overview's `dependency_witness_query` supplies the protected detail entrypoint:
`backend-rewrite evidence --api <API> --witness <id> --pointer /client_ip`.
It requires the confirmed current assignment and finalized attempt, authenticates
the original Source exchange and private witness, and returns only the requested
JSON value (up to 4096 bytes). `--value-index` selects a document in multi-value
operations. Redis/HTTP/Memcached use logical JSON; MySQL uses the explicitly named
native witness JSON envelope. Derived delivery is never labeled an independent
Target observation. Null, missing and unavailable remain distinct.
`recorded_request_context.header_names` includes encrypted interaction headers'
actual names without their values; an empty public `headers` placeholder is not
evidence that a forwarding or authentication header was absent. No plaintext
artifacts are written by this query.

For an unmatched Redis call without a paired Source witness, use the overview's
`redis_target_argument_query`: `backend-rewrite evidence --api <API>
--redis-target-event <case-id>:<target-event-index> --argument-index <index>`.
The zero-based argument index excludes the command name. An optional `--pointer`
selects one JSON member inside that argument. The query authenticates independent
Target observations and correlates the exact native request fingerprint within
the confirmed assignment's finalized attempt. It returns at most 4096 bytes of
the selected value, with separate missing, null and unavailable states. Identical
requests can retain multiple observation IDs; the result does not assert a unique
occurrence, Source counterpart or asynchronous task origin. It writes no plaintext
artifact and changes no matching or acceptance result.
`target_observations` retains up to sixteen authenticated observation IDs and
their Case/dependency clocks, so admission time can be correlated with transport
evidence without reading the private witness graph. A clock does not prove which
application task initiated the call.

`append_stream_progress` summarizes up to sixteen Source key fingerprint groups
for that same Case, with each group's last retained APPEND admission cursor and
up to eight original Source connection/sequence fragments. Grouping does not
infer physical resource or state epoch ownership. Omitted groups, fragments and
report-wide audit omissions remain explicit. These audits contain fingerprints and byte
offsets, never stream contents. Admission does not prove transport delivery or
Source consumption, and an omitted audit can advance a cursor beyond the last
retained row. The selected unmatched call gains no inferred Source counterpart.

Dependency-primary and Replay issues with a response representative also expose
the existing bounded `case-response-differences` query. Dirty dependencies remain
the first diagnosis; status, header and body differences remain independently
queryable even when another Case was interrupted by a dependency rejection.

For a suspected MySQL response-stream alignment defect, set
`RUST_LOG=info,traffic_e2e::replay::mysql::wire_diagnostics=debug` on the normal
engine workflow command. The existing replay log then includes a diagnostic
connection ID, peer and connection-local command counter, receive/send packet
sequence, payload length and response leading byte. The encoder's response kind
and generated connection status flags distinguish PrepareOK metadata from an
ordinary OK, which both start with zero. It records transport flush
success and client EOF separately. A buffered message is not proof of a flush
or client parsing. This trace is disabled by default and contains no SQL,
parameters, column names or row values; no matching or protocol behavior changes.

With Socket.IO `preserve_input_timing: false`, recorded client idle offsets are
not slept. Explicit completion and actual server-event ACK bindings still gate
inputs; native requested receipts drain before namespace disconnect without
serializing overlapping business events. Dependency response durations continue
to use the recorded resource timing. `preserve_input_timing: true` retains
intentional client timing. HTTP closes bound to an actual terminal message also
omit their post-completion idle gap in fast mode; an absolute timed client
cancellation remains an explicit input contract.

Normal WebSocket close retains the Case until the peer actually closes or
terminates the connection. Merely flushing the client's close can leave a prior
Socket.IO namespace disconnect running, so its later dependencies must not enter
the next Case. This is bounded close I/O, not a replay of recorded idle offsets
or a wait for missing recorded calls. Cleanup timeout is reported explicitly;
an actual dependency rejection interrupts a pending close and preserves its
original incomplete-execution cause.

Recording retains Source's WebSocket transport through the same real close
operation. Calls that begin during Source namespace cleanup remain in the
recorded Case even when no dependency was in flight at the initial client close.
The finalizer bounds this by its existing cleanup deadline and records incomplete
cleanup on expiry. This cannot restore cleanup exchanges missing from an older
recording; missing Source effects still require fresh recording evidence.

For recognized Python ASGI Source peers, a WS close echo can precede application
disconnect cleanup, and logical Engine.IO CLOSE need not initiate WS close.
The recorder therefore confirms a live SID's native upgraded-session NOOP first,
then observes its application-disconnected status before completing the WS
handshake. These bounded read-only control requests use the live SID, never a
recorded identity; a missing/invalid SID alone is insufficient. The existing
cleanup deadline bounds this observation. A failed confirmation or transport
operation marks capture incomplete instead of certifying a truncated contract.


Global JSON rule preflight composes already declared Redis script scalar times
with payload formats. EVAL/EVALSHA permissions retain the exact script identity,
key selector, KEYS/ARGV boundary, argument count and independent dependency
clocks. Only declared ARGV clocks use their native time contract; every other
argument and JSON remainder stays strict. Adding a JSON field cannot turn an
existing native script clock into an undeclared byte difference, or authorize
an unrelated argument change.
