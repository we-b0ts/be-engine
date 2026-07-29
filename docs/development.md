# Development Guide

Use this file for local commands, runtime behavior, recording, replay, and
testing details. Keep `AGENTS.md` as the short navigation map.

## Rust Tooling

Use the standard Cargo workflow:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
plugins/ai-software-engineering/skills/backend-engineering/scripts/check-code-organization
cargo build
```

The repository includes `.cargo/config.toml` for the configured crates.io
mirror. Do not replace that registry configuration unless explicitly asked.

## Shared Recording Images

The repository owns the Dockerfiles for the two project-independent recording
images:

```text
docker/network-anchor/Dockerfile
docker/recorder-runtime/Dockerfile
```

Published Linux/amd64 references:

```text
registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62
registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107
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
`traffic-e2e record --artifact-owner "$(id -u):$(id -g)"` so finalization
assigns only the exact run tree back to the invoking host user.

## CLI Boundaries

Use `traffic-e2e config ... init` for one-time target configuration and
`traffic-e2e prepare|run-api|run|status|recover|abort` for the standard
workflow. Use `traffic-e2e config recorder|replay|comparison plan|apply` for
evidence-driven managed rule changes. Use `traffic-e2e diagnose ...` only for
recorder development or focused low-level diagnosis. Managed record, replay,
target isolation, and host interception are implemented in the Rust binary.
Repository scripts are development checks or explicit host trust-store tools
only.

## Running Locally

Record baseline/candidate responses from live frontend traffic with:

```bash
traffic-e2e record-comparison --config config/recorder.example.toml
traffic-e2e record-comparison \
  --config config/recorder.example.toml \
  --duration-seconds 60 \
  --api 'GET /api/widgets/*' \
  --case-limit 250
traffic-e2e record-comparison \
  --config config/recorder.example.toml \
  --baseline-recheck
```

The default comparison recording duration is 60 seconds. AI and automated
invocations must pass `--duration-seconds 60` or another positive integer
explicitly.

Sensitive request headers can remain replayable without storing plaintext:

```toml
[recording]
encrypt_request_headers = ["authorization"]
```

Header-name matching is case-insensitive, so this protects `Authorization` as
well. Set a Base64-encoded 32-byte AES-256-GCM key before standard recording,
comparison recording, and replay:

```bash
export TRAFFIC_E2E_ENCRYPTION_KEY_B64="$(openssl rand -base64 32)"
```

The value is written only as versioned ciphertext in `request.json`. Keep
`authorization` in `redact_headers` too: request encryption takes precedence,
while response headers remain redacted. If encrypted headers are configured
and the environment variable is missing, invalid, or decodes to any length
other than 32 bytes, recording startup fails. Replay also fails with missing
or wrong key material. Repository wrappers must preserve the variable for
Recorder or `record-comparison`, not inject it into source, candidate, or
supporting services.

Comparison recording does not compare responses. It returns the baseline
response and records the request plus baseline and candidate responses under
`<artifacts.root_dir>/comparison-recordings/<run-id>/`. It uses
`http_gateway.matched_upstream` as the baseline unless
`comparison_recording.baseline_upstream` is explicitly set. It does not load
the verification policy, record dependencies, install interception rules, or
initialize a MITM CA. Response bodies are decoded according to their own
`Content-Encoding` before being stored for semantic comparison, while the
baseline response returned to the frontend retains its original encoding.
Explicit named HTTP gateway rules and methods are required. Only GET, HEAD, and
OPTIONS may be mirrored. Any configured POST, PUT, PATCH, DELETE, or other
non-read method fails configuration validation before the listener starts, so
comparison recording cannot duplicate a write across both upstreams. Reaching
an API case limit stops later requests for that API from reaching either
upstream.

Comparison recording requires
`http_gateway.fallback_mode = "fixed_response"`. A request is admitted only
when it is selected, both upstreams are ready, a concurrency slot is available,
and its API still has case quota. An admitted request reaches both source and
candidate and creates one case. A request that is unselected, excluded,
unmatched, not ready, overloaded, or over quota reaches neither upstream and
receives the configured fixed response. The runtime never intentionally
forwards comparison traffic only to the source.

By default the source baseline is requested once. Set
`[comparison_recording].baseline_recheck = true` to capture the same read-only
request in strict source-before, candidate, source-after order. The frontend
still receives the first source response without waiting for the later
captures. The recheck adds `expected-response-after.json` and is diagnostic
evidence for source-time drift by default. It runs only for admitted cases.
Use the enable-only `--baseline-recheck` flag for one run without changing the
source-controlled default.

The verification policy separately controls source-observation acceptance:

```yaml
response_rules:
  comparison:
    source_match: before_or_after
```

The default is `before`. `before_or_after` requires a source recheck for every
case and passes only when the candidate matches one complete source response
under the active response rules. It never combines fields from source-before
and source-after. Standard replay ignores this setting.

Comparison recording artifacts carry `case-kind.json` with
`kind = comparison_recording` and are not replay inputs. `prepare`, case
grouping, and replay reject them explicitly. The process creates one run for
its lifetime; start it again or provide a new `--run-id` to reset case quotas.
With `--duration-seconds`, the timer begins only after both configured
readiness probes succeed, then shutdown finalizes
`comparison-recording-run.json`. Archive and remove old runs externally.

`traffic-e2e config recorder init` emits required AI actions for creating
`scripts/<project>-cli` with `start/status/stop` and
`scripts/start-recording-comparison`. Before project code exists, the project
CLI's `start` command serves a fixed response on the configured candidate port.
The wrapper accepts and passes through `--duration-seconds` and
`--baseline-recheck`, accepts `--brz-no-fallback <true|false>`, defaults the
duration to 60 seconds and Breeze no-fallback to `true`, and later keeps using
the stable project CLI contract when the mock is replaced by the genuine
service. The Platform wrapper starts exactly one Breeze instance shared by the
source and candidate containers; it consumes the Breeze option locally rather
than passing it to `traffic-e2e`. AI and automated wrapper calls always pass
the duration explicitly.

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
  .traffic-e2e/artifacts/comparison-recordings/<run-id> \
  --policy .traffic-e2e/verification.yaml
```

The command writes `comparison-report.json` in the run directory by default
and exits non-zero when a response differs from every permitted source
observation, source-before/source-after drift makes a case inconclusive, or a
case cannot be evaluated. The comparison behavior and field rules under
`response_rules` participate in this phase; dependency matching rules remain
replay-only. Comparison applies both shared response rules and rules nested
under `response_rules.comparison`. The report records
`matched_source` for a passing case and groups cases by the recorded
`METHOD + api_pattern`; `apis_passed` is the current validation-success count,
while E2E progress uses only replay `passed` wording. Dynamic and unordered
candidates, plus source-proven live counters, can be fed back through the
evidence-validating response-rule workflow:

```bash
traffic-e2e config replay plan response-rule \
  --kind dynamic \
  --dynamic-mechanism uuid \
  --source-evidence 'src/token.rs:issue_token UUID generation' \
  --source-example '<redacted UUID from source>' \
  --target-example '<redacted UUID from target>' \
  --api "GET /api/token" \
  --json-pointer /token \
  --comparison-report .traffic-e2e/artifacts/comparison-recordings/<run-id>/comparison-report.json
```

Neither `record-comparison` nor `compare` enables the fixed recording user,
DNS/iptables interception, fake-IP routing, MITM, dependency replay, or any
other isolation workflow.

AI must diagnose a failed comparison before changing code or policy. A stable
source recheck plus a candidate mismatch is stronger implementation-defect
evidence. A changed source recheck is `source_change` only for candidate
differences at the same response location; unrelated candidate differences
remain target behavior. Ordinary mutable business data must be re-recorded in
a quieter or snapshot-consistent window, not exempted. Only source-proven
current-time/random scalar fields or order-insensitive arrays may use replay
dynamic/unordered rules. A live count may use
`config comparison ... --kind counter` only with exact API/Pointer,
comparison-report evidence, source ownership evidence, and two different
observations. The resulting `response_rules.comparison.counter` rule checks
presence and representation class only during comparison; standard replay
remains exact. Number matches only number, string matches only string, and an
empty string does not match a nonempty string.

Run the service with:

```bash
cargo run -- diagnose recorder --config config/recorder.example.toml
```

Install the binary and run managed recording:

```bash
cargo install --path .
traffic-e2e record --config config/recorder.example.toml
traffic-e2e record --config config/recorder.example.toml \
  --api 'GET /api/widgets/*'
```

Automation should publish Recorder lifecycle state on a Unix socket and wait
through the public lifecycle commands:

```bash
traffic-e2e record \
  --config config/recorder.example.toml \
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
the configured HTTP gateway source readiness probe. Neither command parses
recorder configuration or probes listener ports. `--timeout-seconds` defaults
to `300`.

`traffic-e2e record` enables local DNS capture and fake-IP TCP/UDP redirect by
default, which modifies local DNS/iptables state. Use this when you
intentionally want the recorder to intercept local traffic. To skip those
rules:

```bash
traffic-e2e record --config config/recorder.example.toml --no-dns
```

Managed recording uses `dns_mock.upstream_dns` from the Recorder TOML for both
fake-DNS forwarding and the local DNS interception bypass. It does not require
or read a separate `UPSTREAM_DNS` environment variable.

`traffic-e2e record` always limits DNS and fake-IP interception to the
dedicated Unix user `trp-record`. Run the source service as that user so
bootstrap and case dependencies are not polluted by unrelated local processes.
The owner scope cannot be overridden by CLI options, environment variables, or
recorder configuration.

HTTP gateway recording is intentionally conservative. Until the configured
ready probe succeeds, matching traffic uses the configured fallback strategy
and no case is created. After ready, only one matched case can be active at a
time; overlapping matching requests also use fallback so dependencies are not
shared across cases.

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

The gateway also limits successfully published cases per resolved case pattern
within one recorder run. The default is
`http_gateway.case_limits.default = 100`. Static paths are counted
independently by exact URI path; a URI matched by `case_path_patterns` is
counted under that configured pattern. Pattern-specific limits use exact keys:

```toml
[http_gateway.case_limits]
default = 100

[http_gateway.case_limits.overrides]
"/api/resource/token" = 25
"/api/namespaces/**" = 50
```

Dynamic override keys must already exist in a recording rule's
`case_path_patterns`. Once the published count reaches the effective limit,
later matching requests use the configured fallback strategy without creating
a case. Failed cases do not consume the limit, and restarting Recorder starts
a new run with fresh counts.

`record` and `record-comparison` accept a positive `--case-limit N` for one
run. When present, it replaces both the configured default and every
pattern-specific override in memory, so every resolved API or static path uses
`N`; it never rewrites the recorder TOML.

After an upstream HTTP response completes, Recorder continues accepting new
case dependencies for the fixed
`recording.case_dependency_post_response_window_ms` interval. This captures
synchronous server-side after-hooks that start dependencies only after writing
the response; set it to `0` when the target completes all relevant work before
the response. When the interval ends, Recorder closes dependency admission so
continuous background traffic cannot extend the case, then waits only for
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

`recording.max_body_bytes` bounds wire bodies and dependency captures.
`recording.max_decoded_body_bytes` may independently allow a larger decoded
HTTP case body, such as compressed JSON; when omitted it inherits
`max_body_bytes`. Content decoding reads at most the decoded limit plus one
byte, so highly compressed input cannot cause unbounded decompression.

### Rewriting HTTP Responses

HTTP response rewriting is an opt-in recording feature for responses that
publish a later connection target. The `pluto-eci-kubeconfig` built-in plugin
rewrites the Kubernetes API server in Pluto ECI's
`user_config` JSON response from an IPv4 address to a synthetic `.test` domain.
The `vintage-naming` plugin rewrites legacy Motan node addresses published by
Vintage naming responses.

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
`vintage-node-<address>.trp.test` alias. The rewritten HTTP exchange records the
alias, original IP, fake IP, port, service, and cluster. Replay reserves the
same fake IP before assigning any other target, so an SDK that caches the
recorded naming response still connects to the Motan replay endpoint. A fake-IP
collision or an address outside the configured replay CIDR fails replay
startup instead of silently routing to a different target.

Enable the example `[http_response_rewrite]` configuration in
`config/recorder.example.toml` and ensure the configured `kubectl_binary` is
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

Rules are evaluated in configuration order and only the first matching rule is
run. Version one accepts complete, identity-encoded HTTP response bodies; a
matched response with compression is rejected instead of being partially
rewritten. Plugin parse or rewrite failures fail the HTTP exchange and active
case, so an original IP-bearing response is never silently published. On
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
traffic-e2e config replay init --target-root ../target
traffic-e2e replay --policy ../target/.traffic-e2e/verification.yaml path/to/case-dir
```

See [replay-policy.md](replay-policy.md) for the policy schemas,
assertion-only `expected-response.json` contract, dependency rule scoping,
runner-owned dynamic and unordered response fields, and dirty-evidence
behavior.

Recorder-owned host exceptions for API-independent process-level tasks remain
in the target repository's `.traffic-e2e/recorder.toml`, not
`.traffic-e2e/verification.yaml`. Apply an add-only host after source inspection
proves that all traffic to that host belongs to a task that is unrelated to API
handlers:

```bash
traffic-e2e config recorder apply allowed-unused-http-hosts \
  --target-root ../target \
  --rule record-api \
  --host cs.aliyuncs.com
```

The tool bootstraps and then owns an
`AI-MANAGED ALLOWED UNUSED HTTP HOSTS` block inside the selected named
`[[http_gateway.rules]]` entry. Apply replans against current evidence and is
add-only, sorted, deduplicated, atomic, and safe against concurrent config
changes. One host applies to every case selected by that recording rule,
independent of which active API window happened to capture the process-level
task.

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

Pass the config and rule together for direct replay:

```bash
traffic-e2e replay \
  --policy ../target/.traffic-e2e/verification.yaml \
  --recorder-config ../target/.traffic-e2e/recorder.toml \
  --recording-rule record-api \
  path/to/case-dir
```

Replay reads the rule once at startup. A case-owned recorded HTTP exchange for
an allowed host that remains unconsumed is moved from
`unused_case_http_exchanges` to
`allowed_unused_case_http_exchanges`, which is retained as a non-blocking
diagnostic. A target request that is unmatched or unsupported remains dirty,
including requests sent to an allowed host. Restart replay after applying a
new host; running sessions do not hot-reload recorder configuration.

`traffic-e2e replay` also uses the fixed `trp-record` owner filter. Run the
dependency-producing target process as that user. Build steps, replay itself,
and replay-control commands may remain under the developer account. If the
target cannot run as `trp-record`, intercepted replay is blocked; do not widen
the owner scope to the login user or all local users.

For a prebuilt in-process E2E command, use `traffic-e2e target exec` rather than
granting the fixed user access to the workspace or build cache:

```bash
traffic-e2e target exec \
  --env-file .traffic-e2e/runtime/.env \
  --copy-env APP_CONFIG=.traffic-e2e/runtime/config/application.yaml \
  --copy-env REPLAY_CA=path/to/replay-ca.pem \
  --path-env CASE_DIR=path/to/readable/case-group \
  --write-dir logs \
  -- path/to/prebuilt-e2e --case-id <case-id>
```

The caller must have non-interactive sudo permission for staging ownership and
for running as the recorder's fixed user. Copied inputs are read-only to the
target; the temporary work tree is writable and removed after execution.
Environment files use dotenv syntax. Later files override earlier files, and
same-named caller environment values or explicit `--env` assignments override
file values. Reserved identity, path, shell-hook, and replay-session variables
are rejected.
`--path-env` does not widen source permissions and fails when the fixed user
cannot already read the path. The
helper clears inherited proxy and shell-hook variables, verifies the effective
UID, and never accepts a user or UID option. Keep replay lifecycle commands
outside the target process.

For a case collection, start one replay session and control active case
ownership through the CLI:

```bash
traffic-e2e replay path/to/recordings/<run-id>/<rule>/<uri-group>
traffic-e2e replay path/to/recordings/<run-id>
traffic-e2e replay --case-id <case-id> path/to/recordings/<run-id>
traffic-e2e diagnose replay-control wait-ready
traffic-e2e diagnose replay-control cases
traffic-e2e diagnose replay-control begin <case-id>
traffic-e2e diagnose replay-control end <case-id> --fail-on-dirty
traffic-e2e diagnose replay-control finalize --fail-on-dirty --fail-on-incomplete
```

Successful `finalize` writes a version-six report with its session id,
timestamps, exact selected case ids, and `finalized: true`, then stops replay.
The command returns success only after atomically publishing that exact report;
a report-write failure leaves the session open for retry. If finalization
fails, preserve the diagnostic report and use
`traffic-e2e diagnose replay-control stop` only for cleanup. Default replay
reports are retained under a unique
`.replay/sessions/<attempt>/replay-report.json` directory.
Protocol traffic requests live snapshots through one coalescing writer, which
writes at most once per second; lifecycle commands and finalization force an
immediate snapshot. Version six keeps exact success counters while retaining
at most `success_detail_limit` successful event details per category. Dirty
event details remain complete, and unused MySQL entries reference bounded SQL
previews plus fingerprints instead of copying arbitrarily large SQL strings.

For a collection, multi-case selection, or multiple sessions, generate one
deterministic coverage and dependency summary from the recording source root.
Select the exact final case and session ids so older attempts cannot satisfy the
gate:

```bash
traffic-e2e diagnose replay-aggregate \
  --case-source recordings/<run-id>/<rule> \
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
  --case-source /path/to/recordings/<run-id>/<rule> \
  --case-dir /path/to/recordings/<run-id>/<rule>/<current-uri-group> \
  --method GET \
  --source-route '/api/users/:id' \
  --pattern '/api/users/*' \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --output ../target/.traffic-e2e/run-reports/<run-id>-case-groups.json \
  --recorder-config ../target/.traffic-e2e/recorder.toml \
  --rule record-api
```

For an exact static route, omit `--pattern`, `--recorder-config`, and `--rule`.
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
  --rule record-api \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'
```

The selected rule must already contain exactly one explicit
`BEGIN/END AI-MANAGED CASE PATH PATTERNS` block. The command preserves all text
outside that block, sorts and deduplicates patterns, validates the complete
recorder config, and replaces the file atomically. Every authority mode is
add-only: a full case source or full replay does not authorize deleting patterns
that were not observed.

Delete only a specifically proven-invalid entry already inside the AI-managed
block. Name it explicitly, attach single-line source-route evidence, and include
`--allow-delete`:

```bash
traffic-e2e config recorder apply case-path-patterns \
  --target-root ../target \
  --rule record-api \
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
never rewrite
`.traffic-e2e/recorder.toml`; no plan/apply workflow is needed for a temporary
recording scope. Use `--case-limit N` when the same positive run-local case
limit must apply to every selected API.

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

## Migration E2E Runner

Use `traffic-e2e` as the high-level migration replay command. Initialize the
target project configuration after the recorder and replay documents, project
facade, ignored local root, and `dev-migration` branch exist:

```bash
traffic-e2e config project init --target-root ../target
```

The command validates the conventional inputs and generates
`.traffic-e2e/project.yaml`:

```yaml
version: 5
project_cli: scripts/<project>-cli
replay_policy: .traffic-e2e/verification.yaml
replay_startup_timeout_seconds: 60
pr_base: dev-migration
recorder_config: .traffic-e2e/recorder.toml
recording_rule: record-api
local_root: local
```

`replay_startup_timeout_seconds` controls how long the runner waits for replay
to finish loading cases and publish its ready session; it defaults to 60 when
omitted from an older config. The runner prints `loaded_cases=0` when dependency
loading starts, then relays progress about every 5% by loaded case count while
retaining the complete replay log in the run reports directory.

Replay E2E progress reports `passed`, not `verified`: E2E proves the recorded
contract can execute, but does not retire an API from future validation.
Comparison reports are the authority for current validation success and
include both case-level and API-level passed counts.

Existing configuration is never overwritten. If the file is missing, every
other runner command points back to `config project init`; if any required
field is missing or the configured PR base no longer resolves, every command
fails before using traffic E2E state. Replace an obsolete generated version
explicitly with
`traffic-e2e config --target-root <target> project init --force`.
`prepare`, `run-api`, and `run` require a
named feature branch different from `pr_base`. Do not hand-write it. Prepare
each API only after confirming whether its source URI is static or dynamic:

```bash
traffic-e2e prepare \
  --target-root ../target \
  --case-source recordings/<run>/<rule> \
  --case-dir recordings/<run>/<rule>/<group> \
  --method GET \
  --source-route '/api/widgets/:id' \
  --pattern '/api/widgets/*' \
  --source-revision <revision>
```

Use the returned group id for the focused migration loop:

```bash
traffic-e2e run-api \
  --target-root ../target \
  --case-source recordings/<run>/<rule> \
  --api 'GET /api/widgets/*'
```

Run the current complete API group only until it passes, then stop. Focused
attempts replace the selected API's terminal contribution to the current
logical run in `e2e-progress.yaml`; repeating one run does not add runs or
cases. Focused evidence never replaces the global full-round `latest`.

After every published case is prepared exactly once and every focused group
passes, the grouped result is sufficient unless behavior-affecting code changed
after an earlier group pass. In that case, run the complete regression round:

```bash
traffic-e2e run \
  --target-root ../target \
  --case-source recordings/<run>/<rule>
```

The full command starts replay once, loads bootstrap and all selected cases
once, starts the target once, executes cases sequentially, finalizes and
aggregates once, atomically publishes
`.traffic-e2e/local/<run-key>/latest/`, and updates the Git-eligible
`.traffic-e2e/e2e-progress.yaml`.

Progress reaches `status: complete` when every grouped API in the current
logical run has finalized, complete, clean passing evidence. This is an E2E
pass, not a long-term verification terminal state. A grouped focused pass is
sufficient unless later behavior changes
may invalidate it; then use one full regression round. Use `status`, `abort`,
and `recover` for interrupted global rounds. Generated local JSON/YAML is
tool-owned and must not be edited by AI or by target scripts.

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
- `.traffic-e2e/artifacts/`
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
<run-id>/errors.jsonl
<run-id>/global-dependencies.jsonl
<run-id>/global-dependencies-summary.json
<run-id>/global-dependencies-debug.jsonl
<run-id>/<rule-name>/<uri-group>/<case-id>/request.json
<run-id>/<rule-name>/<uri-group>/<case-id>/expected-response.json
<run-id>/<rule-name>/<uri-group>/<case-id>/dependencies.jsonl
<run-id>/<rule-name>/<uri-group>/<case-id>/dependencies-summary.json
<run-id>/<rule-name>/<uri-group>/<case-id>/dependencies-debug.jsonl
<run-id>/failed/<rule-name>/<uri-group>/<case-id>/
```

Every newly published case contains `dependencies.jsonl` and
`dependencies-summary.json`, including cases with no semantic third-party
dependencies. For a zero-dependency case, `dependencies.jsonl` is empty and
the summary has `total_events: 0`. This distinguishes a confirmed empty
dependency contract from missing capture evidence.

Failed cases are diagnostic artifacts, not replay fixtures. A case with a
truncated request or expected response body is kept under `<run-id>/failed`
with `recording-error.json` instead of being published. Successfully published
cases remain in their normal rule directories when another case fails. A clean
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
background-rule matches. Replay discovers them by walking upward from a case
directory, prefers Case before Global, and consumes every exchange once.

Completed protocol events are moved by unique ownership into one asynchronous
JSONL writer. `recording.writer_queue_capacity` bounds this queue by event count
(default `65536`); it does not impose a byte budget. Producers never wait for
free queue capacity. A full or closed queue marks the recording as failed so
traffic forwarding is not delayed and an incomplete recording cannot be
published as successful. Case and run finalization send ordered flush commands
through the same writer, so queued dependency reservations remain in flight
until their records have been persisted.

Source-proven process-level HTTP polling can be classified before recording:

```toml
[[recording.background_dependencies]]
name = "config-refresh"
protocol = "http"
authorities = ["config.api.demo.test"]
methods = ["GET"]
path_prefixes = ["/1/config/service"]
source_revision = "0123456789abcdef"
source_evidence = "src/config/refresh.rs:42 process-level scheduled refresh"
response_role = "independent"
```

All three selector dimensions and both source-evidence fields are required. A
matching exchange is not attributed to an active API case and therefore does
not enter that case's `dependencies.jsonl` or summary. The ordinary run-level
`traffic.jsonl` continues to retain the exchange only when
`recording.traffic_jsonl` permits it. It also enters
`global-dependencies.jsonl` with `reason=background_rule` and a
`bootstrap|runtime` phase. The rule changes ownership only; it does not alter
forwarding, response capture, body limits, or protocol debugging. Add an
independent rule only after response assertions pass and source inspection
proves API independence, then create a new recording run.

Use a finalized replay report to create the AI-managed rule instead of editing
the table directly:

```bash
traffic-e2e config recorder apply background-dependencies \
  --target-root . \
  --protocol http \
  --name config-refresh \
  --authority config.api.demo.test \
  --method GET \
  --path-prefix /1/config/service \
  --replay-report <same-finalized-replay-report.json> \
  --source-revision 0123456789abcdef \
  --evidence 'src/config/refresh.rs:42 process-level scheduled refresh'
```

The action requires at least one matching unused case HTTP exchange and rejects
a selector that also matches unmatched or unsupported target requests. It
replans against the current recorder config and replay report immediately
before its atomic write. One rule owns one exact authority, method, and path
prefix; use separate rules for distinct request families.

A source scheduler that builds response-driving local cache state can instead
use the current narrow Breeze Memcached rule:

```bash
traffic-e2e config recorder apply background-dependencies \
  --target-root . \
  --protocol memcached \
  --name planet-video-cache-warm \
  --breeze-resource user-video \
  --command get \
  --key-start 0 \
  --key-end 4095 \
  --key-separator . \
  --key-suffix pl_video \
  --initial-load-timeout-ms 60000 \
  --replay-report <same-finalized-replay-report.json> \
  --source-revision 0123456789abcdef \
  --evidence 'TopUserServiceImpl.java:691 scheduled local-cache warm'
```

The tool requires one compatible Breeze `mc` descriptor, persists its complete
stable identity without the dynamic port, and resolves the port when the
source-created descriptor is available. Runtime matching uses port as a coarse
filter, then requires Memcached `get` and the exact bounded numeric key series. Apply this
`runtime_state` rule during response repair when the cache warm is a proven
cause; do not wait for responses to pass.

An applied Memcached rule also delays source case admission until Recorder has
counted `key_end - key_start + 1` completed replay-safe matches. The count
includes matches observed before HTTP readiness. After the ready probe,
Recorder observes for at most `initial_load_timeout_ms` (60000 by default),
logs progress every 10 seconds, and warns but continues case admission when
the count remains incomplete. The rule is the opt-in: without an applied
Memcached rule there is no additional observation window. This source-recording
wait does not apply to target-local cache initialization during Replay.

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

Redis and Memcached dependencies are semantic `redis_connection`,
`redis_exchange`, `memcached_connection`, and `memcached_exchange` records.
Successful Redis authentication/session initialization is handled by replay
and omitted from case dependencies; failed initialization remains as redacted
evidence. Any truncated frame, parse/correlation failure, unsupported cache
mode, or unsafe cache connection prevents a case from being published and
prevents unsafe Global replay from starting. The recording directory is
sensitive because ordinary cache keys and values are needed for exact replay.

Semantic MySQL, Redis, Memcached, Kafka, and Motan business exchanges also carry
`outcome` and `duration_ms`. Replay waits the recorded duration before a normal
response. If `outcome` is `client_terminated`, replay sends no response and
consumes the exchange only after the SDK closes or resets the same connection
near the recorded time; replay itself does not initiate that close. Intrinsic
no-response commands remain `no_response` and are not treated as timeouts.

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
Motan2 framing is unsupported and fails closed. Recorder deliberately does not
deserialize arbitrary Java arguments: it preserves exact frame bytes and
replay uses method identity plus recorded connection order. Those frames may
contain sensitive business objects, so protect the recording directory as
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
