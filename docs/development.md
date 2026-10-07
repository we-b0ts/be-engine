# Development Guide

Use this file for local commands, runtime behavior, recording, replay, and
testing details. Keep `AGENTS.md` as the short navigation map.

MySQL replay driver compatibility and process-owned read rules are documented in
[mysql-replay.md](mysql-replay.md).

Cross-case HTTP initialization dependencies use explicit Replay scope rules; see
[HTTP cross-case replay](http-cross-case-replay.md) for discovery, plan/apply,
strict matching and fresh verification.
Source-proven arrays in outbound JSON requests use [HTTP unordered rules](http-unordered-rules.md).

Redis JSON/Protobuf values and source-proven collection ordering use
[Redis value rules](redis-value-rules.md), with the same discovery and plan/apply lifecycle.
Source-proven expiry drift in Redis JSON read responses uses explicit
[Redis time-shift rules](redis-time-shift-rules.md), discovered through worker
source diagnosis without heuristic hints.

## Rust Tooling

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

`cargo build --features online-recording --bin recording-online` additionally
builds the independent [online recording service](online-recording.md). Its
adapter tests run with `cargo test --features online-recording`; include that
feature when running Clippy for online recording changes.

All binaries report the package version, build revision, and exact pinned
target-runtime image from `--version`. Git checkouts derive the revision
automatically and append `-dirty` for uncommitted content. Builds without Git
metadata should set `TRAFFIC_E2E_BUILD_REVISION` to a 1-64 character release
revision containing only ASCII letters, digits, `.`, `_`, `+`, or `-`.

## Shared Container Images

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

`backend-rewrite review check --worktree /absolute/worker --api 'GET /api'`
performs the mandatory worker handoff review. Register the worktree during
`worker confirm --worktree /absolute/worker`; the engine records the dispatch
base. Use `--process-output ID` for a process-output worker. After the final
edit and commit, supply the returned report through `worker report ...
--activity handoff_ready --review-report /absolute/report.json`.

When the configured target is a subdirectory of a larger Git repository, keep
`--target-root` pointed at that project subdirectory. `--worktree` may point at
either the outer Git worktree root or the corresponding project subdirectory;
the engine normalizes it to the project subdirectory. By default source diffs,
review paths, fingerprints, and Replay-isolation checks remain scoped to that
project. Add target-relative sibling directories to
`project.delivery.managed_paths` when the target and a rapidly changing local
dependency must be delivered together. Every managed directory must exist,
belong to the same Git repository, and be disjoint from the target and the
other managed directories. Managed sibling files are reported relative to the
target, for example `../backend-rs/src/lib.rs`. Once managed paths are present,
a candidate with tracked changes outside the target and those paths is rejected.

Review runs the same complete quality implementation for worker and integration
deliveries. It enforces complete changed production Rust files <=1000 lines.
Added Tokio spawn paths
require structured startup ownership evidence via `--evidence`; request-owned
and unknown ownership cannot pass. The scanner uses syntax, ordinary imports and
source spans; it does not expand macros, infer types or prove call graphs.
It also performs the mandatory Replay-isolation and source-sensitive public
domain checks, including `demo.test` occurrences in test fixtures, then executes
every configured repository gate with its exact arguments in the delivery
worktree. Configuration comes from the canonical target, so changing a worker's
local gate configuration cannot skip checks. Worker review checks the frozen
dispatch ancestry and uses the same full PR diff baseline as integration review.
See the [API implementer review protocol](../plugins/ai-software-engineering/skills/backend-rewrite/references/api-implementer-review.md).

Code integrators check their committed merged candidate using `review check
--integration --worktree /absolute/integration --api 'GET /api' --handoff-id ID`
(or `--process-output ID`). After publishing that exact candidate, the coordinator
reports `worker report ... --activity integrated --review-report
/absolute/integration-report.json`. This requires an integration report for the
original accepted handoff, not its earlier worker report. Global evidence-only
or final quality review uses `review check --integration --worktree
/absolute/integration` without scope or handoff ID; after publication the
coordinator admits it using `review accept --report /absolute/report.json`.
`BACKEND_REWRITE_REVIEW_WORKTREE` and `BACKEND_REWRITE_REVIEW_REPORT` supply those
paths for returned action commands. Check execution requires an explicit
delivery worktree; the coordinator validates receipts without rerunning checks.

`review show` reads the current integrated report and `review rework --finding
ID --owner 'api:GET /api'` (or `process-output:ID`) routes a finding to its
responsible worker, including a completed retained work item.
For a failing unpublished integration candidate, add `--report
/absolute/failed-candidate-report.json` to `review rework`. Routing validates
the candidate's code, commit, workflow and canonical base without publishing or
accepting it. Source findings use their `findings[].id`; configured command and
isolation/domain failures use the accepted handoff's `rework_required` path with
exact logs or source locations, not fabricated source finding IDs.
An executed review returns JSON with `passed`, `changes_required` or
`evidence_required`; inspect `status`, not merely the command exit status.
Checks and evidence reports are not traffic evidence and never change recordings.
Quality results are bound to candidate code, canonical check configuration,
runtime inputs, rules and the diff base. Publication admission matches actual
code content without substituting a worker's private runtime fingerprint for the
canonical identity. Code or input changes invalidate the report. Old workflow
states remain readable but old source-only reports do not waive full checks.
Admission requires the exact reviewed commit. After admission, an ordinary
progress-only commit may retain that receipt: the reviewed commit must remain
an ancestor, with code, canonical inputs, rules and the diff base unchanged,
and no new `Hardcode-Source-Evidence` commit trailers.
The engine checks this automatically; do not manufacture another handoff or
rerun checks merely to publish progress metadata.

After external changes are published on the canonical migration branch, prepare
the retained integration worktree at that current commit for a global quality
refresh. Preserve divergent or unfinished work; do not create an empty merge to
refresh an obsolete integration branch. If review needs no new code or evidence
commit, its candidate is the current canonical commit and can be admitted
without another merge. Otherwise publish the exact reviewed candidate before
admission, even when its files equal the canonical files. Admission errors show
the published HEAD, reviewed HEAD and reviewed canonical base so the coordinator
can finish publication or reconcile a changed base instead of repeating checks.

Use `traffic-e2e config ... init` for one-time target configuration and
`traffic-e2e prepare|run-api|run|status|recover|abort` for the standard
workflow. Use `traffic-e2e config recorder|replay|comparison plan|apply` for
evidence-driven managed rule changes. Use `traffic-e2e diagnose ...` only for
recorder development or focused low-level diagnosis. Managed record, replay,
target isolation, and host interception are implemented in the `traffic-e2e`
binary.
Repository scripts are development checks or explicit host trust-store tools
only.

Use the `backend-rewrite` binary and its `next`, `status`, `inventory`,
`evidence`, `rule`, `dependency-rule`, `route`, `repair`, `recording`,
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
route, repeat `next --api 'GET /api/attachments/task/*/all' --source-route
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
source-route confirmation. An explicit `source_baseline_changed` recording request
discards retained source routes while recorded patterns remain usable. Restarting
the coordinator session does not clear bindings.

## Running Locally

Record baseline/candidate responses from live frontend traffic with:

```bash
traffic-e2e record-comparison \
  --target-root /path/to/initialized-target
traffic-e2e record-comparison \
  --target-root /path/to/initialized-target \
  --duration-seconds 60 \
  --api 'GET /api/widgets/*' \
  --per-api-case-limit 250
traffic-e2e record-comparison \
  --target-root /path/to/initialized-target \
  --baseline-recheck
```

The default comparison recording duration is 60 seconds. AI and automated
invocations must pass `--duration-seconds 60` or another positive integer
explicitly.

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

```toml
[recording]
encrypt_request_headers = ["authorization"]
```

JWT expiration between recording and Replay can be handled by an explicit
`verification.yaml` request rule. See [JWT request rules](jwt-request-rules.md)
for the coordinator evidence, plan/apply, target key sources, and replay-only
revalidation flow. No new standard recording is required for this rule.

Header-name matching is case-insensitive, so this protects `Authorization` as
well. Managed preflight, recording, Comparison, and Replay create and reuse one
project key at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`. The ignored
directory is mode `0700` and the strict Base64-encoded 32-byte key is mode
`0600`. An explicitly supplied `TRAFFIC_E2E_ENCRYPTION_KEY_B64` is imported
only when the managed key is absent; a later mismatch is rejected.

The configured request header value is written only as versioned ciphertext in
`request.json`. Request encryption takes precedence over any explicitly configured
redaction; response headers follow `redact_headers`. Missing,
invalid, or wrong managed key material blocks Replay. The system passes the key
only to Recorder and Comparison processes; it is never injected into source,
target, Breeze, commands, or policy.

Comparison recording returns the baseline response and records the request
plus baseline and candidate responses under
`<artifacts.root_dir>/comparison-recordings/<run-id>/`. It uses
`http_gateway.matched_upstream` as the baseline unless
`comparison_recording.baseline_upstream` is explicitly set. It does not load
response rules in the capture path, publish dependencies, or initialize a MITM
CA. Managed recording evaluates published cases under the verification policy
for its online failure limit; file-only comparison reports the finalized verdict. Managed comparison installs only the cache-port interception needed for
configured Redis process-owned rules; source and candidate share a new run-local
first-value snapshot independent of standard Replay evidence. It validates the
verification policy; source rechecks are enabled only by explicit recorder
configuration or `--baseline-recheck`. The policy defaults to `verification.yaml`
next to the recorder config and may be provided explicitly with `--policy`.
Response bodies are decoded according to their own `Content-Encoding` before
being stored for
semantic comparison, while the baseline response returned to the frontend
retains its original encoding. Comparison request and response bodies each
default to a 64 MiB limit.
Explicit named HTTP gateway rules and methods are required. Comparison
recording accepts every method declared by the selected HTTP gateway rule and
sends each admitted request to both upstreams without a separate read-only
method restriction. Reaching an API case limit stops later requests for that
API from reaching either upstream.

Managed comparison waits for the cache-snapshot recorder to report ready
before it opens case admission. Recorder readiness includes a 15-second quiet
window after its readiness probe succeeds: every configured background Redis
request restarts that window, and a 180-second hard deadline prevents a
periodic task from blocking the run forever. The comparison snapshot probes
the candidate, which starts after the source, so this boundary means both are
ready. Standard managed recording uses the same barrier after source readiness.

Comparison recording requires
`http_gateway.fallback_mode = "fixed_response"`. A request is admitted only
when it is selected, both upstreams are ready, the single managed case slot is available,
and its API still has case quota. An admitted request reaches both source and
candidate and creates one case. A request that is unselected, excluded,
unmatched, not ready, overloaded, or over quota reaches neither upstream and
receives the configured fixed response. The runtime never intentionally
forwards comparison traffic only to the source.

By default the source baseline is requested once. Set
`comparison_recording.baseline_recheck: true` or use the enable-only
`--baseline-recheck` flag to capture a second source response for diagnosis.
The first source and candidate dispatches use the run's pair-balanced random
schedule; the source recheck follows both. The frontend receives the first
source response after the complete comparison case is captured and published.
The recheck adds `expected-response-after.json` and reports source changes,
but never supplies an alternate acceptance oracle. It runs only for admitted
cases.

Comparison always checks the candidate against the first source response under
the active response rules. `response_settings.comparison.source_match` supports
only `before` (the default). The removed `before_or_after` value is rejected;
existing configurations must remove that setting or change it to `before`.
A difference still requires source-code diagnosis even when source-after changes
at the same location or matches the candidate. Standard Replay ignores this
comparison-only setting.

Comparison recording artifacts carry `case-kind.json` with
`kind = comparison_recording` and are not replay inputs. `prepare`, case
grouping, and replay reject them explicitly. The process creates one run for
its lifetime; start it again or provide a new `--run-id` to reset case quotas.
With `--duration-seconds`, the timer begins only after both configured
readiness probes succeed, then shutdown finalizes
`comparison-recording-run.json`. Archive and remove old runs externally.
When one or more APIs are selected explicitly, reaching every selected API's
case limit finalizes the run early and records
`completion_reason = per_api_case_limit_reached`; the duration remains the
upper bound. Coordinator-managed comparison can instead reuse a finite
standard-recording request source. For that finite-input mode only, the HTTP
comparison gateway reuses the configured gateway port but binds it to
`127.0.0.1`; environment traffic sent to the host address cannot enter the
comparison run. The input driver sends the recorded requests serially over
that loopback listener. API selection includes matching cases across all
recorded member directories, filters by method and path, and sends overlapping
selections only once. If the input process fails, managed comparison stops and
cleans up immediately instead of waiting for the recording duration.
After the final comparison case is published, it
keeps source, candidate, and the cache snapshot alive for a three-second final
quiet period before recording `completion_reason = input_exhausted`. The run
becomes `completed_with_errors` if the number of delivered templates differs
from the number of published cases. Comparison without finite managed input
continues to use the configured listener and observe the full duration.

The target repository provides no recording or comparison wrapper.
`traffic-e2e record-comparison` owns the adapted source application,
optional Breeze runtime and candidate Breeze mounts, the candidate's fixed
start/stop contract, recording, signals, finalization, and cleanup. The source
keeps the host recording namespace while the candidate runs in a run-owned
bridge namespace, so both applications use their native HTTP and Motan ports
without a host bind conflict. The managed Breeze shares the candidate namespace
so Breeze registry endpoints that advertise `127.0.0.1:<port>` retain their
normal meaning. A namespace-scoped ingress mapping sends connections to the
candidate bridge IP into that loopback, so the adapted source reaches the same
Breeze without knowing its dynamic ports. A run-scoped forwarding and
masquerade guard gives the candidate namespace its normal dependency network
even on Docker hosts configured with `iptables=false`. The candidate's bridge
IP and comparison origin exist only for that run and are never persisted in
`project.yaml` or recording artifacts. AI and
automated invocations pass an explicit duration, run ID, and API scope.

Each published comparison recording case contains:

```text
request.json
expected-response.json        # source baseline before candidate
response.json                 # candidate
expected-response-after.json  # optional source baseline recheck
```

After the run finalizes, compare all cases offline with the same verification
policy already used by E2E:

```bash
traffic-e2e compare \
  .traffic-e2e/local/artifacts/comparison-recordings/<run-id> \
  --policy .traffic-e2e/verification.yaml
```

The command writes `comparison-report.json` in the run directory by default
and exits non-zero when a candidate response differs from the first source
response under the active rules, an applicable response rule is unused, or a
case cannot be evaluated. Source-before/source-after drift is diagnostic and
never makes a differing candidate pass. The field rules under `response_rules`
participate in this phase; dependency matching rules remain
replay-only. Comparison applies JSON `timestamp`, `duration`, `uuid`, `random`,
`unordered`, and `counter` rules plus configured protobuf, Hessian2, and DOCX rules. A failed response report includes one
top-level `representative_difference` with the API, case ID, Pointer,
difference kind, and bounded source-before/candidate/source-after values. A
response-rule applicability failure appears in
`representative_policy_mismatch`. The report records
`matched_source` for a passing case and groups cases by the recorded
`METHOD + api_pattern`; `apis_passed` is the current validation-success count,
while both stage progress files use the generic `passed` wording. Generated-scalar
and unordered candidates, plus source-proven live counters, can be fed back through the
evidence-validating response-rule workflow:

```bash
traffic-e2e config replay plan response-rule \
  --kind uuid \
  --source-evidence 'src/token.rs:issue_token UUID generation' \
  --source-example '<redacted UUID from source>' \
  --target-example '<redacted UUID from target>' \
  --api "GET /api/token" \
  --json-pointer /token \
  --comparison-run .traffic-e2e/local/artifacts/comparison-recordings/<run-id>
```

`compare` is file-only. Managed `record-comparison` uses the fixed traffic UID
and cache-port-only interception when Redis process-owned rules are configured;
target bridge traffic is added to that same run-local Redis snapshot by a
source-IP-scoped `PREROUTING` rule. Comparison does not enable DNS interception,
fake-IP routing, MITM, or dependency Replay. Standard Replay retains its
host-network target and existing fixed-user DNS/fake-IP/egress interception;
the comparison namespace does not change recorded fake IPs or replay lookup.

AI must diagnose a failed comparison before changing code or policy. A stable
source recheck plus a candidate mismatch is stronger implementation-defect
evidence. A changed source recheck is `source_change` only for candidate
differences at the same response location; unrelated candidate differences
remain target behavior. Ordinary mutable business data must be re-recorded in
a quieter or snapshot-consistent window, not exempted. Only source-proven
current-time/random scalar fields or order-insensitive arrays may use concrete
generated-scalar/unordered rules. A live count may use
`config comparison ... --kind counter` only with exact API/Pointer,
comparison-report evidence, source ownership evidence, and two different
observations. The resulting `response_rules.json.<API>.counter` rule checks
presence and representation class only during comparison; standard replay
remains exact. Number matches only number, string matches only string, and an
empty string does not match a nonempty string.

Run the service with:

```bash
cargo run -- diagnose recorder --config config/project.example.yaml
```

Install the binary and run managed recording from an initialized target:

```bash
cargo install --path .
traffic-e2e record --target-root /path/to/target
traffic-e2e record --target-root /path/to/target \
  --api 'GET /api/widgets/*'
```

For a Docker-free recording in an existing host or container environment, let
traffic-e2e start Source in the current network namespace:

```bash
traffic-e2e record-source --target-root /path/to/target \
  --duration-seconds 60 -- ./source --port 7171
```

The command starts Recorder listeners before Source, runs Source as `998:998`,
projects the generated CA to common SDK trust variables (and a Java truststore
when `keytool` is present), waits for configured Source readiness, and starts
the duration only then. Recorder finalizes before Source receives SIGTERM. It
does not keep Source alive or install passthrough after recording. Omit
`--api` for the configured full scope. The canonical output is
`.traffic-e2e/local/artifacts/recordings/<run-id>` under `--target-root`.

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
enabling the gateway when the default is not correct. Source and target use the
same native port because managed Comparison isolates the target network
namespace; the gateway port must remain distinct from that native port.
Repeating the same command returns `status: unchanged`; changing the gateway
port updates only owned keys and preserves the native endpoint, Motan rules,
and recorder comments. Its result uses `validation_status: not_run`:
configuration alone does not claim that real Motan traffic has been validated.
Set `motan_gateway.enabled = false` to keep HTTP-only recording temporarily.

Motan has no `candidate_upstream` setting. Comparison's candidate is an HTTP
primary-request endpoint; Motan gateway traffic is recorded/replayed through
`listen` and `matched_upstream`, and the system does not expose a second Motan
primary-request dispatcher.

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

`record` and `record-comparison` accept a positive `--per-api-case-limit N` for one
run. When present, it replaces both the configured default and every
pattern-specific override in memory, so every resolved API or static path uses
`N`; it is not a run-wide total when multiple APIs are recorded, and it never
rewrites the project or coordinator YAML documents.
For explicitly selected APIs, both recording modes stop admission and finalize
normally after all selected APIs reach `N`. Standard managed recording also
ends its outer Platform lifecycle at that point instead of waiting out the
remaining duration. Without explicit selectors, the limit continues to
suppress over-quota cases but never shortens the recording window.

After an upstream HTTP response completes, Recorder continues accepting new
case dependencies for the fixed
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

On recorder shutdown, case matching enters a quiescing phase before run
finalization. New matching requests use the fallback upstream while the current
case is allowed to finish for up to
`recording.shutdown_case_drain_timeout_ms`. If the timeout expires, the
remaining staging case is retained under `failed/` with
`recording_incomplete_at_shutdown`.

`recording.max_body_bytes` is the system-wide body limit. It bounds comparison
requests and responses, recorded wire bodies and dependency captures, and
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

For ordinary JSON URL fields, the coordinator writes compact rules in
`.traffic-e2e/source-traffic-policy.yaml`:

```yaml
http_response_rewrite:
  - name: cs.wegent.intra.demo.test
    rules:
      - path_pattern: GET /executor-manager/sandboxes/*
        pointer: /base_url
        source_evidence: sandbox_id varies; consume base_url
      - path_pattern: GET /another-api/*
        pointer: /base_url
        source_evidence: another API with dynamic IDs
```

`name` is the upstream authority and appears once per domain. Its `rules` list
contains multiple path entries. Each `path_pattern` contains the HTTP method
and path; `pointer` selects one JSON URL field. Use separate path entries for
other methods or fields. `source_evidence` records
the short note supplied during path review. The recorder overlays these rules
on the static configuration in `project.yaml`. The previously generated
`authorities` / `methods` / `pointers` list format is not accepted in this
managed policy section. Omitted `enabled` enables configured rules; an explicit
`enabled: false` still disables them. Rules are loaded at recording startup;
new addresses are discovered on each matching response, without hot reload.

The path part of `path_pattern` matches the request path excluding its query.
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
a source-controlled `.traffic-e2e/verification.yaml`, not product code or recorded fixture
overrides. Initialize it once and load it explicitly:

```bash
traffic-e2e config init --target-root ../target \
  --source-pod <pod> --namespace <namespace>
traffic-e2e replay --policy ../target/.traffic-e2e/verification.yaml path/to/case-dir
```

See [replay-policy.md](replay-policy.md) for the policy schemas,
assertion-only `expected-response.json` contract, dependency rule scoping,
runner-owned generated-scalar and unordered response fields, and dirty-evidence
behavior.

Coordinator-owned host exceptions for API-independent process-level tasks live
in the target repository's `.traffic-e2e/source-traffic-policy.yaml`, not
`.traffic-e2e/project.yaml` or `.traffic-e2e/verification.yaml`. Apply an add-only host after source inspection
proves that all traffic to that host belongs to a task that is unrelated to API
handlers:

```bash
traffic-e2e config recorder apply allowed-unused-http-hosts \
  --target-root ../target \
  --host cs.aliyuncs.com
```

The tool updates the global HTTP policy in the wholly coordinator-managed
source traffic policy document. Apply replans against current evidence and is
add-only, sorted, deduplicated, atomic, and safe against concurrent changes to
either config document. One host applies to every HTTP case, independent of which recording
rule or active API window happened to capture the process-level task.

When a response-driving source hostname is absent from dependency evidence but
occurs in the configured Breeze snapshot, preview and enable its logical
resource instead of listing dynamic ports or backend domains:

```bash
traffic-e2e config recorder plan breeze-resource-capture \
  --target-root ../target \
  --resource usercounter \
  --source-revision <source-commit> \
  --evidence 'src/UserCounter.java:load uses usercounter'

traffic-e2e config recorder apply breeze-resource-capture \
  --target-root ../target \
  --resource usercounter \
  --source-revision <source-commit> \
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
trigger one full-scope standard recording; callers must not request a separate
recording per rule.

Pass the recorder config for direct replay:

```bash
traffic-e2e replay \
  --policy ../target/.traffic-e2e/verification.yaml \
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
Dirty event details remain complete, and unused MySQL entries reference bounded SQL
previews plus fingerprints instead of copying arbitrarily large SQL strings.
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

To narrow one recording invocation, repeat
`--api 'METHOD /path-or-pattern'` on `record` or `record-comparison`. The
selectors are run-local and intersect the configured HTTP rules. They are
persisted in the run summary and used as the selected cases' `api_pattern`, but
never rewrite `.traffic-e2e/project.yaml` or
`.traffic-e2e/source-traffic-policy.yaml`; no plan/apply workflow is needed for a temporary
recording scope. Use `--per-api-case-limit N` when the same positive run-local case
limit must apply to every selected API. Explicitly selected runs finalize when
all selectors reach `N`; runs without selectors continue for the full duration.

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

## Migration E2E Runner

Use the rewrite coordinator as the normal AI-facing migration command. It
keeps engine-managed state under `.traffic-e2e/local/runtime/` and exposes one
active issue. Coordinator APIs are the primary interface:

```bash
backend-rewrite next
# Or explicitly narrow the workflow to one API:
backend-rewrite next --api 'GET /api/widgets/*' \
  --source-route '/api/widgets/:id'
backend-rewrite status
backend-rewrite status --api 'GET /api/widgets/*'
backend-rewrite status --process-output metrics-profile
backend-rewrite inventory
backend-rewrite evidence <query-id>
BACKEND_REWRITE_CASE_PATH_PATTERNS_JSON='["/api/tasks/*/tree"]' \
  backend-rewrite case-pattern apply <batch-id>
backend-rewrite recording request \
  --kind standard \
  --reason user-requested \
  --duration-seconds 60 \
  --per-api-case-limit 100
backend-rewrite recording execute <action-id>
backend-rewrite repair verify <repair-id>
BACKEND_REWRITE_SUBAGENT_HANDLE='<replacement-handle>' \
  backend-rewrite worker transfer --previous-agent-handle '<old-handle>' \
  --reason 'stored handle is unavailable after session replacement' \
  --approve-ownership-transfer
backend-rewrite verification request \
  --api 'GET /api/widgets/*' \
  --reason 'shared response mapper changed'
```

Rewrite action schema v30 always returns `action.kind`, `action.summary`,
`action.details`, and `action.commands`. Variant facts exist only under
`details`; executable argv exist only under coordinator command roles such as
`execute`, `status`, `advance`, `recover`, `apply`, and `acceptance`.
Unscoped and scoped `status` and `next` expose scheduling state and short issue
summaries. They contain neither diagnostics nor an evidence command.

The coordinator dispatches the implementation-worker role, exact API or
process-output scope, canonical target root, and absolute assigned worktree.
Workers fetch their own current context and evidence:

```bash
backend-rewrite --target-root /path/to/target evidence --api 'GET /api/widgets/*'
backend-rewrite --target-root /path/to/target evidence --process-output metrics-profile
```

Exactly one selector or opaque query ID is required. These read-only selectors
resolve the requested item without switching the active API or advancing state,
including parked APIs. Unknown items and items with no current issue fail
explicitly. Dispatch confirmation still gates evidence; workers wait for the
coordinator to confirm and retry the same query if they start too early.
Evidence schema v4 overviews include `context` with canonical target root,
workflow/recording identity, revision, comparison requirement, and the worker's
binding/dispatch identity. `facts.issue` retains the complete bounded issue.
API overviews supply further exact commands in `queries`; process-output
overviews expose `facts.issue.comparison_observation` and no API queries.
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
returned by a specific evidence query.
Schema v24 added top-level `pending`, counting only coordinator actions executable
now. Inventory summaries rename their old `pending` count to `unverified`.
Persisted state remains version 1, with optional worker observations and a
worker-event revision cursor; legacy confirmed bindings require an actual runtime
status check. Update AI skills with the binary when adopting this schema.
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

Worker transfer is an exceptional compare-and-swap ownership change. It is
valid for an unresolved `implementation_required` API or process-output
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

`next` returns an opaque standard/comparison
`action.commands.execute` recording action. `action.details.run_id` identifies
the preallocated run. The coordinator either reuses one exact-scope atomic
real-traffic input or opens a fresh external-live-traffic recording window;
callers do not add curl loops, replayers, shell pipelines, backgrounding, or
driver parameters. `execute` starts a detached coordinator-owned worker and
returns immediately. A start report that requires delayed observation includes
`status_poll_after_seconds`; wait that interval and execute its exact `status`
command without repeating `execute`. `already_completed` omits the delay so
its status can be queried immediately. While the worker remains live,
`recording_in_progress.action.details.status_poll_after_seconds` carries the
same polling delay and `action.commands.wait` performs the bounded wait.
After waiting, reconcile task-runtime worker events and refresh global status. `advance_required` means finalization and cleanup completed, so its
exact `action.commands.advance` can advance coordinator state. It does not mean
rerunning the completed action. Historical
input is reused only when its API selector exactly equals the requested
selector; recordings are never split or merged. When no exact atomic input
exists, `action.details.input_mode=external_live_traffic` opens a fresh
recording window and includes bounded candidate/rejection diagnostics under
`action.details.recording_input_diagnosis`. When startup omits `--api`, recorder
configuration limits the standard run and the coordinator derives a stable
API inventory from its published cases. `next` and `status` expose only its
bounded summary (`total`, `completed`, `unverified`, `active`, `implementation_required`,
`system_repair_required`, `awaiting_recording_refresh`, `revalidation_pending`,
`current_index`, and `current_api`) so their size does not grow with API count.
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
APIs and dependent process outputs remain incomplete, with bindings/evidence
retained. Resume with global status after repair; the engine cannot wake a
stopped AI session. Other explicit failures retain their recovery/retry contracts.
The engine selects across the whole inventory, including parked implementation
issues. The coordinator does not scan `unverified` to choose work. `inventory`
expands the English `details.ready` and `details.waiting` breakdown and dedicated
worker bindings; ready counts sum to `pending`.

Each implementation issue has one persistent worker handle and isolated
worktree. There is no coordinator worker limit; the task runtime controls
concurrency and accepted queuing. Dispatch/resume a real worker, then execute
`commands.confirm_worker` with its actual handle and assigned `--worktree`.
Confirmation of one API never
blocks dispatch or feedback for another. Workers own evidence, diagnosis,
implementation, local tests, and the complete delivery review; the coordinator supplies only the assignment
fields described above and retains the original delivery report.

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

When exactly one API implementer is actually running, and more than
two hours have passed since its last code integration (or initial binding), the
engine returns `expert_required`. Queued and ended tasks do not count as running;
unknown, stale, or unconfirmed runtime status requires reconciliation first.
The count uses current API work scopes, including parked APIs, rather than all
historical bindings. It does not predict workers needed after future Replay.
The trigger has no convergence or attempt-count condition. `status`, `next`, and
bounded `wait` checks evaluate it, including during traffic operations; `wait`
still requires runtime-event reconciliation before the next status decision.

The coordinator must not initiate expert assistance based on elapsed time,
difficulty, or its own judgment. Only an engine-issued `expert_required` action
authorizes the assistance flow. Execute `commands.prepare` to reserve the
returned API. Preparation rechecks
eligibility under the worker feedback lock. The resulting `dispatch_required`
action asks for one read-only `api-expert`, with its API worktree and evidence
command in `details.apis`. Recover an existing runtime task for `expert_id`
before submitting, then execute `commands.confirm_expert` once the task is
accepted, including queued work. Continue engine work while the expert runs.

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

Worker confirmation uses `worker confirm --api 'GET /api' --agent-handle HANDLE
--worktree /absolute/worker` (or `--process-output ID`). The engine persists the
actual implementation handle and returns `agent_handle` with its work scope in
status and inventory. Returned commands already include a known handle. First
binding and a binding whose raw handle is not yet recorded require the actual
runtime handle. Successful confirmation/reporting records it. Display names
are not identifiers; use the runtime's addressable handle (Codex's canonical
`agent_name` when its tools accept that target).

Runtime observations use `worker report --agent-handle HANDLE --activity ACTIVITY`.
No binding or dispatch ID is accepted as a command argument. Internal IDs remain
in evidence and review reports; the engine validates deliveries against them.
Running, queued and idle describe a fresh runtime observation, not a delayed
callback relabeled as current. Set
`BACKEND_REWRITE_SUBAGENT_HANDLE` and `BACKEND_REWRITE_WORKER_ACTIVITY` to
`running`, `queued`, `idle`, or `handoff_ready`. Handoffs also require
`BACKEND_REWRITE_WORKER_HANDOFF_ID` and a passing `--review-report` for the final
delivery. Scoped reviews return a separate report path on each check, preserving
the original workflow, scope and dispatch through retries. Retain that path;
never substitute a new report for an old callback. The coordinator inspects the
spawn evidence before accepting it.
`integration_required` asks the coordinator
to delegate that identified handoff and required inputs to the code integrator,
publish its exact checked candidate, then report `integrated` with the same ID
and the integrator's passing `--review-report`. A worker ending without a handoff is `idle` and
requires resuming its existing binding. Integration conflicts return the ready
handoff via `rework_required` with its handoff ID and original worker or integration
`--review-report`; the engine issues a new dispatch to
the same worker and rejects callbacks for the superseded dispatch. Integration
is acknowledged only while the verification resource is free.

When any recorded API still has zero focused verification attempts, its first-pass
Replay is scheduled before ready handoff integration or integrated-handoff
acceptance. This discovery barrier exposes independent API failures early so their
workers can run in parallel. Dispatch, resume, runtime-status, and feedback actions
remain immediate. After every API has an attempt, integration and acceptance resume,
followed by the existing unified target-fingerprint revalidation.

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
Quality gates execute during worker and integration review before delivery.
The coordinator admits version-bound integration reports; the legacy
`target-quality run` entry point only validates an existing receipt.
One admitted integrated API handoff schedules that API's Replay and the
current batch's required Comparison. Final unified verification handles shared
changes after ordinary work drains.

An enabled `project.process_outputs` entry records the supported metrics
profile during each API comparison:

```yaml
process_outputs:
- id: metrics-profile
  path: /data1/weibo/logs/profile.log
  enabled: true
```

The comparison contract is engine-owned rather than business configuration.
It starts fresh source and target containers for each API comparison, waits
`comparison_recording.process_output_flush_after_last_case_ms` after its final
case (15 seconds by default), captures both files, and makes the result part of
that API's comparison gate. Focused Replay does not capture the profile.
A missing source output rejects the owning recording as an engine input
problem. A missing target output becomes a target-code
`implementation_required` work item. `enabled: false` retains the stable
project entry without capturing or comparing it.

The fixed profile comparator reads timestamp-prefixed JSON records by record
`type` and `name`. Each selected record's `total_count`
and `slowThreshold` accepts either a JSON unsigned integer or its decimal
string representation. Comparison starts at a 60-second recording duration;
shorter diagnostic recordings may capture the file but do not validate its
presence or metrics. The fixed policies are `exact_total_count` for
`RPC_SERVICE_WHOLE`, and `source_positive_exists` for `HTTP` and the logical
Motan client group `RPC_SERVICE_CLIENT`.

`exact_total_count` sums every `total_count` in each `(type, name)` group and
requires equal sums, treating a group absent from one side as a numeric zero.
Consequently, a zero-count group present on only one side is equal to absence,
while a positive-count group present on only one side remains a mismatch. When
a group is present on both sides, their sets of `slowThreshold` values must
share at least one value; the individual records do not need to align. Records
without a source `slowThreshold` are ignored by both policies; this excludes
non-latency rows that reuse a selected type, such as MC socket-pool snapshots.
`source_positive_exists` is one-way: for every
source `(type, name)` group whose summed `total_count` is greater than zero, the
target must contain that type/name group. It intentionally ignores target
counts and extra target groups. `RPC_SERVICE_CLIENT` expands internally to
`RPC_SERVICE_CLIENT`, `RPC_SERVICE_CLIENT_V2`, `RPC_SERVICE_CLIENT_REAL`, and
`RPC_SERVICE_CLIENT_REAL_V2`; they are checked independently but reported as
one logical type with one representative example. For HTTP only,
`all_http://x` and `http://x` (likewise HTTPS) share one logical allowance,
while their observed counts remain separate.

An implementation may allow one source-positive metric to be absent from the
target only when source revision evidence proves that an indirect dependency
emits it independently. Before returning rule inputs, the target AI must inspect
the relevant source startup/configuration and dependency-emitter paths and
confirm both that source code does not start the interaction and that the
interaction does not affect source behavior. Either finding requires target
implementation. These conclusions are eligibility preconditions, not persisted
booleans. Add an allowance with the evidence-validating plan/apply workflow; do
not hand-edit the policy:

```bash
traffic-e2e config comparison plan allow-target-missing \
  --target-root <target> \
  --process-output metrics-profile \
  --metric 'HTTP.http://telemetry.example/ping' \
  --source-revision 0123456789abcdef \
  --dependency-path 'com.example:client:1.0.0' \
  --dependency-path 'com.vendor:telemetry:2.0.0' \
  --emitter-evidence '{"inspected_paths":["pom.xml","vendor/src/com/vendor/TelemetryInitializer.java"],"description":"TelemetryInitializer independently emits /ping without affecting source behavior"}' \
  --comparison-run <exact-finalized-comparison-run>
```

The command writes target-specific policy under
`.traffic-e2e/verification.yaml`:

```yaml
process_output_rules:
  metrics-profile:
    allow_target_missing:
    - metric: HTTP.http://telemetry.example/ping
      source_revision: 0123456789abcdef
      dependency_path:
      - com.example:client:1.0.0
      - com.vendor:telemetry:2.0.0
      emitter_evidence:
        inspected_paths:
        - pom.xml
        - vendor/src/com/vendor/TelemetryInitializer.java
        description: TelemetryInitializer independently emits /ping without affecting source behavior
```

The plan proves that the exact finalized capture has a positive source metric
and that the entire logical metric is absent on target. Apply is rejected if
project configuration, verification policy, or either capture changes after
planning. An allowance cannot apply to an exact-count metric. A failed profile
comparison reports the number
of compared and mismatched types, the total number of mismatched `(type, name)`
groups, and one deterministic example for every mismatched type. Each per-type
entry identifies its policy and full difference count. The example includes
the relevant counts or thresholds and is selected by name order, so evidence is
stable and bounded by the maximum number of configured profile types.

After status returns
`advance_required`, the returned `next` validates the
preallocated run, prepares the current API, runs focused E2E, and returns
either one bounded implementation issue or the next validation action.

Regression settings are local to the target repository in
`.traffic-e2e/regression.yaml`. Initialization generates this file with
`require_comparison: true` and adds it to `.gitignore` and `.dockerignore`.
It does not need a commit and is explicitly excluded from code and target
fingerprints, even if manually tracked. Existing projects without the file use
all recorded APIs and require Comparison; old workflow latch/batch fields no
longer control the requirement.

```yaml
# Optional: directly reuse this completed standard recording.
# recording_run_id: "20260911093000"
# Omitted or empty only selects every API in the recorded inventory.
only:
  - "GET /api/users/*"
  - "POST /api/users"
skip:
  - "POST /api/users"
require_comparison: true
```

`only` and `skip` can be combined: first select `only` (or all APIs when absent or empty),
then remove `skip`. Selectors must be exact canonical API names from `inventory`,
including the method and recorded path pattern; `*` is part of that inventory
identity, not a glob over other APIs. Unknown names, duplicate entries within a
list and unknown fields are errors. Omitting `only`, `only:`, `only: null` and
`only: []` all select every recorded API before applying `skip`. An empty `skip`
list excludes nothing. Removing the file restores all APIs and Comparison=true.

Set `recording_run_id` to a 14-digit standard recording ID under
`.traffic-e2e/local/artifacts/recordings/`. The coordinator directly validates
and uses that recording as the regression baseline. It does not start a source
recording or use the historical requests to collect a replacement. Missing,
unfinished, failed, empty or unusable recordings block `status` / `next`; no
other recording is selected as a fallback. `only` / `skip` select APIs from this
recording's inventory. Comparison remains controlled by `require_comparison`.

Switching the ID resets current API and process-output verification and retains
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
honored. `only`/`skip` and Comparison policy continue to apply.

The coordinator only confirms purpose. The engine generates a unique
`replay/yyyyMMdd-<seq>` or `record/yyyyMMdd-<seq>` branch, creates and switches to it,
using the machine-local date and one above the largest local/remote sequence for
that purpose and day (starting at 1). It returns `work_branch` and `next`. No
branch name is required. Confirmation consumes the entry permission by entering the work branch;
subsequent `status` / `next` calls continue there. Returning to `pr_base` always
requires a new confirmation, even with unchanged code and an unfinished workflow.

Existing worker bindings, failures, review receipts and expert assignments are
archived under ignored runtime history and replaced with a new workflow identity.
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
and can complete without a source-review receipt, including when an old or broken
`source-review.json` remains on disk. Committing engine progress files does not
create a source-review obligation. New committed, staged, working-tree or untracked
source/configuration changes require a current accepted integration review before
verification and final delivery. Pending handoff/finding admission retains its
ordinary review contract; the exemption does not admit an unpublished candidate.
Source review and engine-standard quality commands belong to the delegated integrator,
not the coordinator's startup path.

An actual active/stale engine operation must finish or recover before replacement;
this is the serialized traffic lease, not an old task-runtime liveness check.
Failure to create the work branch while still on base restores the previous state.
`status` remains read-only throughout. The legacy `regression begin` CLI is hidden;
coordinators should use the purpose command returned by `status`.

`status`, `inventory` and `next` use the current settings between traffic
operations. Excluded APIs are reported as `skipped`, do not dispatch workers or
block completion, and retain original progress/evidence for later re-inclusion.
A scoped `status --api` or `next --api` for an excluded API returns `complete`
with an explicit skipped explanation and false current-verification flags.
Global completion is restricted to the selected scope, with separate verified
and skipped counts; skips never become passing traffic observations.

`workflow.require_comparison` exposes the current local requirement. When false,
a passing Replay completes the API without generating Comparison evidence.
When switched to true, selected APIs missing valid Comparison become pending;
still-current Replay evidence is reused. Turning it off removes Comparison-only
blocking without changing historical traffic results. Running traffic finishes
before new settings apply. Requirements are not frozen into recording batches,
and there is no automatic change after first completion.

Both modes can return `terminal_allowed=true` once selected APIs and the existing
process-output, quality-review and delivery-publication gates are satisfied.
Changing this local policy does not invalidate code or Replay fingerprints;
newly selected APIs and newly required Comparison are scheduled explicitly.

When Comparison is required, passing Replay requests Comparison; once it
passes, the following `next` prepares the next inventory item from the same
standard recording. A repository or policy content change makes prior
E2E/comparison evidence stale. Completed APIs become `revalidation_pending`
and receive lower scheduling priority than executable ordinary work. When
ordinary actions are waiting and verification resources are free, the engine
selects one stale API in inventory order. Worker execution and API-scoped system
repair do not block unrelated revalidation. A target failure creates worker
work; a system failure can be parked with its exact repair identity. Completed
APIs are not repeated at an unchanged target fingerprint. Later integrations
still invalidate stale successes for the final verification epoch. A commit that
preserves the effective worktree content does not change the fingerprint.
`verification request` remains available for an explicit caller request to
verify selected stale APIs early; ordinary coordination already uses idle
verification capacity; the returned advance command starts
their normal Replay/comparison flow, and final whole-inventory coverage remains
mandatory. `terminal_allowed` is false until every API inventory item has
passing E2E and, when required by its batch, comparison evidence, and every process output has passing
evidence for the same target content fingerprint. A process-output repair can
invalidate completed APIs, so the final epoch reruns stale APIs before the
process output is compared again.

After a finalized unscoped standard recording, the coordinator compares its
concrete APIs with a persistent historical API catalog canonicalized by current
`case_path_patterns`. Only new uncovered APIs produce one
`case_pattern_identification_required` batch. Its fixed apply command receives
the complete JSON pattern list through
`BACKEND_REWRITE_CASE_PATH_PATTERNS_JSON`; `[]` confirms that every candidate is
static. This action has no source-revision or evidence input. Apply updates the
managed source traffic policy and the catalog, while existing recording files
remain immutable. The current recording inventory is then derived again under
the updated policy.

Recording, focused Replay, and comparison share one serialized traffic-runtime
lease. Global status first returns any executable worker dispatch or feedback
action. When resources or running workers are the only remaining activity,
schema v30 returns `wait_required` with
the requested and blocking APIs, the live operation when available, a retry
delay, and the exact `commands.wait` argv. This lease serializes each traffic
operation, not a complete API lifecycle: while worker A implements, the
orchestrator may run Replay for API B and dispatch worker B. No worker may start
a traffic operation. If code changes during Replay, that result is discarded;
later code changes defer already-completed API evidence to the final epoch.

`status [--api | --process-output]` is read-only and returns the selected work
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
by apply. Worker and integration `review check` run the engine-standard format,
workspace tests, Clippy, and mandatory source/Replay-isolation suite before delivery. The
coordinator admits the integration report for the exact published candidate;
`advance_required` then starts Replay. Missing or stale proof returns
`source_review_required` for the code integrator, including before revalidation
when code or required inputs have changed. Initial diagnostic Replay can run
before the workflow has a delivery report. Repository-specific development
requirements belong in `AGENTS.md` or `CLAUDE.md`; project configuration cannot
replace or disable the engine-standard quality checks.

A failed focused E2E attempt reuses the same finalized standard cases after the
target changes. A passing attempt advances to a newly allocated comparison
recording. Every fresh standard recording requires explicit user authorization.
Use `backend-rewrite recording request --kind standard` only after that
authorization.
The request accepts positive duration and per-API case-limit values, invalidates state
derived from the old baseline without deleting its artifacts, and returns a
new exact recording action. Omitting `--api` means all APIs admitted by recorder
configuration, even when the prior workflow was narrowed; explicit `--api`
keeps the fresh recording single-API. An identical pending request returns the existing
action and run. A different pending request is rejected unless
`--replace-pending` is explicit; a matching completed manifest returns an advance action.
The coordinator defaults both standard and comparison recording actions to 60
seconds and 100 cases.

After a focused attempt, `next` and `status` expose
`latest_focused_e2e.execution_mode` as either `fresh_standard_cases` or
`reused_standard_cases`. The same bounded object identifies the standard
recording run, exact case-source directory, case-inventory ID when available,
previous/current attempt numbers, and whether the latest attempt passed. It
describes the latest completed attempt, so a repeated `next` with no target
change returns the same evidence without claiming another replay occurred.

Workers fetch the overview through `backend-rewrite evidence --api` or
`--process-output`, bound to their canonical target root. Further gate and
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
When more are available it returns the next opaque evidence command instead of
an open cursor. The `representatives` result includes the representative case
ID, its exact immutable standard or comparison `case_dir`, and a structured
response difference. A focused E2E difference contains expected and actual
observations; a comparison difference contains source-before, candidate, and
source-after observations. It does not duplicate the complete Replay response
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
Memcached dirty-cluster
evidence currently exposes `protobuf-timestamp`, whose help command is:

```bash
backend-rewrite --target-root ../target dependency-rule plan memcached protobuf-timestamp --help
```

The rule planner requires current dirty-cluster evidence and source proof for
the selected protobuf field. It owns the fixed five-second timestamp window;
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

Use `backend-rewrite rule plan|apply` for a source-proven response rule and
`backend-rewrite route` for a source-proven missing recorded resource,
Recorder/Replay capability gap, external-data blocker, or source change. For a
missing dependency, use `--cause missing-recorded-resource --endpoint
'hostname[:port]'`; the coordinator resolves the endpoint through configured
Breeze snapshots and returns a recorder-capture plan only when the unique
resource is currently bypassed. Query IDs and evidence IDs are bound to the
workflow revision and active issue, so stale evidence is rejected.

An accepted system/source repair route snapshots a coordinator-defined revision
and returns `repair verify <repair-id>`. The caller cannot provide an acceptance
command, and `next` or `recording request` cannot bypass the repair. Successful
verification decides whether to rerun the same cases or allocate fresh standard
recording evidence. A successful `missing-recorded-resource` route instead
returns the existing recorder-capture apply command and never enters system
repair.

A fresh standard recording allocated by repair verification also takes over
any pending capture refresh. The coordinator retains applied rules, the old
baseline reference until validation succeeds. `next`
reconciles older repair states with an unbound refresh to their already reserved
recording, including a finalized one. It does not allocate duplicate traffic
merely because the old scheduling revision differs. Publication and scope
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
upstream, managed Comparison candidate, target readiness endpoint, and Replay
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
`.traffic-e2e/source-traffic-policy.yaml`, and `.traffic-e2e/verification.yaml`.
When the root `Cargo.toml`, `Cargo.lock`, and `src/main.rs` are all absent, it
also generates a runnable readiness-only Rust target using `http-server`
`v0.0.2` with its `macros` feature. `ReadinessApi` exports the configured GET
route through `#[api(auth = none)]` and `#[http_server::get(...)]`, returns
an empty `200` response, and starts with `Server::bind` / `serve_until` for
graceful shutdown. The generated route must be a literal path without captures,
query, fragment, whitespace, or a trailing slash (except `/`). Implement
business APIs with the same macros in their owning modules and combine them
with `http_server::Router::new(ReadinessApi).merge(business_api)`.
The bootstrap also includes a temporary `src/startup_probe.rs` initialization
module. Keep that module and its
`src/main.rs` call through initialization preflight, then delete the module,
declaration, and call when real target implementation begins. It generates
`.traffic-e2e/Dockerfile.e2e` only when absent and creates or safely extends the
root `.gitignore` and `.dockerignore` with canonical local-state, Rust build,
recording, data, credential, and environment-file exclusions; existing regular
target files are preserved.
`project.yaml` combines project settings with the static recorder settings;
`source-traffic-policy.yaml` is wholly AI/coordinator managed. Project settings
have explicit source, target, replay, verification, recording,
delivery, and state sections. `verification.max_failed_cases_per_api` defaults
to `10`; Replay and Comparison stop admitting additional cases for an API once
that many cases have not passed. Remaining Replay cases stay unexecuted rather
than being reported as failed. A typical
target section is:

```yaml
target:
  dockerfile: .traffic-e2e/Dockerfile.e2e
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
Docker context; consume an additional context explicitly in `Dockerfile.e2e`,
for example `COPY --from=sibling-backend src /build/backend-rs/src`. Context
names must be unique lowercase Docker identifiers of at most 64 ASCII
characters. The engine does not infer repository layout or copy an additional
context into an image automatically.

Target readiness path and status come from the project document's
`recorder.http_gateway.ready` section. Target startup readiness uses
`project.target.startup_timeout_seconds`, which defaults to 180 seconds when
omitted and accepts values through 1800 seconds. Target request timeout comes
from `comparison_recording.upstream_timeout_ms`; the Replay service startup
timeout remains a coordinator-owned default. The target's native HTTP port is the port in
`recorder.http_gateway.matched_upstream`; Replay uses it on loopback and Comparison uses
it on the run-owned target bridge IP.

`review check` owns the quality standard; `project.yaml` has no configurable
quality-command field. For each Rust target, it runs format, workspace tests,
and Clippy. It applies the same checks to every managed directory that
contains `Cargo.toml`, using the target-relative `--manifest-path` so that
directory is tested independently instead of merely compiled as a dependency.
Repository-specific development requirements belong in `AGENTS.md` or
`CLAUDE.md` and do not replace the engine standard.

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
backend-rewrite --target-root <target> init preflight
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
`source-traffic-policy.yaml`, `verification.yaml`, either Dockerfile, target
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
revision and allocates fresh standard recording evidence; the administrator
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

The initialized target repository contains `.traffic-e2e/Dockerfile.e2e`. It
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
directory below `.traffic-e2e/local/runtime-outputs/`. Managed `record` mounts
the path into the source container. Managed `record-comparison` mounts separate
`source/<id>` and `target/<id>` directories into the source and target
containers, respectively; Replay mounts only `target/<id>`. Replay uses the
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

For standard recording, the managed runtime keeps a target-scoped
source-adaptor cache image. `.traffic-e2e/local/source/` is authoritative for
the immutable local image ID and captured Kubernetes runtime inputs; preflight,
recording, and comparison do not contact the original Pod. The target repository
owns the reviewed `.traffic-e2e/Dockerfile.recording` build contract. Adaptor
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
matching adaptor image. Comparison recording uses the same adaptor image,
snapshotted runtime inputs, and fixed `998:998` source identity as standard
recording, so cache-only interception observes both source and target traffic.
Initialization and managed runtime do not provision a Breeze sidecar, inject
Mesh connection settings, or ship Java class patches. Existing projects must
remove the retired `project.breeze` setting and any obsolete patch-copy steps
from `Dockerfile.recording`. Application-specific startup inputs use the normal
startup declarations; Breeze SDK use and Vintage response rewrite rules remain
independent of this startup contract.

Changes confined to `.traffic-e2e/source-traffic-policy.yaml` (including case
pattern discovery) do not require code review or invalidate an accepted code
review receipt. The policy remains part of the configuration commit gate and
traffic verification fingerprints; changed source, startup inputs and other
configuration still require the usual review. Candidate publication still
requires the exact reviewed commit.

Before worker and integration delivery, `review check` runs the same built-in
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
environment, readiness, replay requests, and comparison requests. Comparison
keeps source in the host recording namespace and places the target in one
run-owned bridge namespace. Replay starts the target once for
the selected cases, intercepts dependency traffic by fixed UID, and prevents
uncontrolled external egress.

After initialization has generated the target template and the initialization
AI has reviewed and completed the generated `Dockerfile.recording` scaffold,
run the authoritative preflight:

```bash
backend-rewrite init preflight
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
Java probe command has a 10-second execution bound. Ordinary recording and
comparison do not repeat this initialization gate, and Motan business traffic
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
new standard batch from live traffic increases run and case coverage. Replay,
comparison recording, and any retries only settle that standard batch's current
result; even one hundred verification attempts never add another run or case.

Progress is published in two steps. Recording completion immediately increases
`executed` coverage, exposes the latest batch with `passed: null`, and clears
the global streak plus only the per-API streaks covered by that batch. APIs not
present in the recording keep their streaks. A terminal result then updates
`passed` counts. Success reconnects the streak that existed before recording
only when the batch never failed; after any failed attempt, later success for
the same batch starts at one run and that batch's successful case count. A
retry never increases `executed`.

The committed file contains only business aggregates and the latest batch
summary. Replay/comparison provenance, pending state, failure barriers,
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
Existing `replay-progress.yaml` coverage is migrated once and both split files
are removed after `progress.yaml` is durably published. Historical comparison
counters are execution detail, so they are not added to business coverage.

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
coordinator-managed delivery file is committed: `source-traffic-policy.yaml`,
`verification.yaml`, and `progress.yaml`. The action lists only the dirty
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

The current logical run passes only with complete response, replay, and
dependency gates. When a rewrite batch requires Comparison, Replay success
does not replace its Comparison evidence.
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

New recorder configurations use one shared artifact root. Standard and
comparison recording runs are kept in sibling directories so a target
repository needs only one generated-data directory:

```text
<artifacts.root_dir>/
  recordings/<run-id>/
  comparison-recordings/<run-id>/
```

Existing configurations without `[artifacts]` remain supported:
`recording.output_dir` is the recording run root and its
`comparison-recordings/` subdirectory is the comparison recording run root.

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
deduplicated DNS names resolved by the source and the exact `host:port`
endpoints actually reached through the TCP or UDP gateway. Replay requires
this run-level manifest and does not derive a compatibility allowlist from
semantic dependency files. A recording without the manifest must be recorded
again. During Replay, an endpoint outside the manifest may resolve and accept a
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

Source-proven process-level HTTP polling can be classified before recording:

```toml
[[recording.process_owned_dependencies]]
name = "config-refresh"
protocol = "http"
authorities = ["config.api.demo.test"]
methods = ["GET"]
path_prefixes = ["/1/config/service"]
source_evidence = "src/config/refresh.rs:42 process-level scheduled refresh"
```

All three selector dimensions and `source_evidence` are required. HTTP rules
accept bounded, non-empty authority and path-prefix lists and match their
explicit cross-product with the configured method. Repository initialization
installs the system-owned `breeze_vintage` rule for the Weibo Vintage
configuration and naming endpoints. The source revision remains in the plan
report instead of runtime configuration. A
matching exchange is not attributed to an active API case and therefore does
not enter that case's `dependencies.jsonl` or summary. The ordinary run-level
`traffic.jsonl` continues to retain the exchange only when
`recording.traffic_jsonl` permits it. It also enters
`global-dependencies.jsonl` with `reason=background_rule` and a
`bootstrap|runtime` phase. HTTP, Motan, and Memcached rules change ownership
only. A Redis rule also enables the bounded first-value snapshot; it does not
change response capture limits or protocol debugging. Add a rule only after
response assertions pass and
source inspection proves process ownership and case independence. Low-level
Recorder use applies the rule during future capture. In the managed
`backend-rewrite` workflow, non-Redis dependency-rule apply can derive a
current case/global ownership view from the existing immutable capture,
rewrite only the generated replay report and dependency-evidence sidecar, and
revise the same focused attempt. Redis rule apply first attempts a read-only
snapshot overlay from the existing immutable capture. The overlay groups
matching Global and Case exchanges by exact target/session/command/arguments,
requires a successful untruncated `bootstrap_window` Global seed, rejects
conflicting responses or ambiguous/unsafe evidence, and references one
original exchange without rewriting or copying the recording. Replay then
reuses that seed with first-value semantics. If any configured key or observed
logical identity cannot be proved safe, the coordinator keeps the existing
behavior and queues the affected API for one consolidated fresh standard
recording.
The coordinator also detects an already-finalized attempt whose effective
dependency view is clean but whose persisted errors still contain the obsolete
strict dirty-finalize result. `backend-rewrite next` removes only that
dependency-derived error, preserves genuine lifecycle errors, revises the same
attempt, and resumes at comparison without rerunning E2E.

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
  --authority config.api.demo.test \
  --method GET \
  --path-prefix /1/config/service
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
still queues a fresh standard recording so its first-value seed is explicit.

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

Recognized MySQL connection maintenance is not a semantic dependency. The
strict built-in fingerprints are protocol `COM_PING`, c3p0's exact
empty-database `SHOW FULL TABLES` probe using the `PROBABLYNOT` sentinel, and exact
`SELECT 1` with an optional trailing semicolon. Their raw `mysql_query` and
`mysql_response` records remain in the applicable case or Global debug
JSONL, while their derived `mysql_exchange` records are omitted from semantic
dependency JSONL and summaries. Replay handles the same fingerprints without a
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
request responses. These process notifications are not semantic Replay evidence;
Replay returns the recorded confirmation and keeps the connection open without
synthesizing pushes. The entire recorded Pub/Sub lane stays bound to one target
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

Replay classifies source lanes before serving requests. A lane containing a
retained session operation, WATCH/MULTI/EXEC, subscription, blocking operation,
WAIT, script or unknown command conservatively retains connection binding for
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
open. HTTP termination evidence with missing timing, truncated request bytes,
response bytes/headers, or a capture error is rejected. Legacy successful HTTP
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
