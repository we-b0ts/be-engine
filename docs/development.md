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
cargo build --bins
```

The repository includes `.cargo/config.toml` for the configured crates.io
mirror. Do not replace that registry configuration unless explicitly asked.
The build produces sibling `traffic-e2e` and `backend-rewrite` executables.
Keep them together in installed packages because detached coordinator actions
delegate engine work to `traffic-e2e`.

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
`traffic-e2e internal recorder-run --artifact-owner "$(id -u):$(id -g)"` so finalization
assigns only the exact run tree back to the invoking host user.

## CLI Boundaries

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
`evidence`, `rule`, `dependency-rule`, `route`, `repair`, `recording`, and
`recover` commands for AI-facing migration orchestration. `traffic-e2e` has no
`rewrite` subcommand; `backend-rewrite` invokes the shared crate directly and
delegates only engine-owned detached work to its sibling executable.

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
response rules while recording, record dependencies, install interception
rules, or initialize a MITM CA. It validates the verification policy and reads
only `response_rules.comparison.source_match` to decide whether source recheck
evidence is required. The policy defaults to `verification.yaml` next to the
recorder config and may be provided explicitly with `--policy`. Response bodies
are decoded according to their own `Content-Encoding` before being stored for
semantic comparison, while the baseline response returned to the frontend
retains its original encoding.
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
Use the enable-only `--baseline-recheck` flag for one diagnostic run without
changing the source-controlled default. A policy with
`source_match: before_or_after` enables the recheck automatically.

The verification policy separately controls source-observation acceptance:

```yaml
response_rules:
  comparison:
    source_match: before_or_after
```

The default is `before`. `before_or_after` automatically records a source
recheck for every admitted case and passes only when the candidate matches one
complete source response under the active response rules. It never combines
fields from source-before and source-after. Standard replay ignores this
setting.

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
upper bound. An unscoped run always observes the full duration.

`traffic-e2e config init --source-container <container> --breeze` installs the
Breeze-aware recorder defaults together with project and verification
configuration. The target repository provides no recording or comparison
wrapper. `traffic-e2e record-comparison` owns the
genuine source, one Breeze shared with the candidate, the candidate's fixed
start/stop contract, recording, signals, finalization, and cleanup. AI and
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
and exits non-zero when a response differs from every permitted source
observation, source-before/source-after drift makes a case inconclusive, or a
case cannot be evaluated. The comparison behavior and field rules under
`response_rules` participate in this phase; dependency matching rules remain
replay-only. Comparison applies both shared response rules and rules nested
under `response_rules.comparison`. A failed response report includes one
top-level `representative_difference` with the API, case ID, Pointer,
difference kind, and bounded source-before/candidate/source-after values. A
response-rule applicability failure appears in
`representative_policy_mismatch`. The report records
`matched_source` for a passing case and groups cases by the recorded
`METHOD + api_pattern`; `apis_passed` is the current validation-success count,
while both stage progress files use the generic `passed` wording. Dynamic and
unordered candidates, plus source-proven live counters, can be fed back through the
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
  --comparison-run .traffic-e2e/local/artifacts/comparison-recordings/<run-id>
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

Install the binary and run managed recording from an initialized target:

```bash
cargo install --path .
traffic-e2e record --target-root /path/to/target
traffic-e2e record --target-root /path/to/target \
  --api 'GET /api/widgets/*'
```

The managed runtime publishes Recorder lifecycle state on a Unix socket and
waits through its internal process contract:

```bash
traffic-e2e internal recorder-run \
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

The internal Recorder process enables local DNS capture and fake-IP TCP/UDP
redirect by default inside its managed container. For focused low-level
development without those rules:

```bash
traffic-e2e diagnose recorder --config config/recorder.example.toml
```

Managed recording uses `dns_mock.upstream_dns` from the Recorder TOML for both
fake-DNS forwarding and the local DNS interception bypass. It does not require
or read a separate `UPSTREAM_DNS` environment variable.

The legacy fixed-user local interception path limits DNS and fake-IP interception to the
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

Dynamic override keys must already exist in a recording rule's
`case_path_patterns`. Once the published count reaches the effective limit,
later matching requests use the configured fallback strategy without creating
a case. Failed cases do not consume the limit, and restarting Recorder starts
a new run with fresh counts.

`record` and `record-comparison` accept a positive `--per-api-case-limit N` for one
run. When present, it replaces both the configured default and every
pattern-specific override in memory, so every resolved API or static path uses
`N`; it is not a run-wide total when multiple APIs are recorded, and it never
rewrites the recorder TOML.
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
Vintage naming responses. The `vintage-cache-config` plugin rewrites cache
node addresses published inside Vintage `/1/config/service` responses.

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
traffic-e2e config init --target-root ../target --source-container <container> [--breeze]
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
  --env-file .traffic-e2e/local/boot/.env \
  --copy-env APP_CONFIG=.traffic-e2e/local/boot/config/application.yaml \
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

`.traffic-e2e/local/boot/` is input-only transport for source-proven startup inputs.
Its name or Git-ignore status does not authorize generating content from a
source process, remote response, recording, log, debug output, or diagnostic.

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
  --output ../target/.traffic-e2e/local/run-reports/<run-id>-case-groups.json \
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
recording scope. Use `--per-api-case-limit N` when the same positive run-local case
limit must apply to every selected API. Explicitly selected runs finalize when
all selectors reach `N`; runs without selectors continue for the full duration.

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

## Migration E2E Runner

Use the rewrite coordinator as the normal AI-facing migration command. It
keeps internal state under `.traffic-e2e/local/ai-forbidden/`, exposes one active
issue, and never returns raw internal report paths. Target rewrite agents must
not read, search, or list that directory:

```bash
backend-rewrite next
# Or explicitly narrow the workflow to one API:
backend-rewrite next --api 'GET /api/widgets/*' \
  --source-route '/api/widgets/:id'
backend-rewrite status
backend-rewrite status --api 'GET /api/widgets/*'
backend-rewrite inventory
backend-rewrite evidence <query-id>
backend-rewrite recording request \
  --kind standard \
  --reason user-requested \
  --duration-seconds 60 \
  --per-api-case-limit 100
backend-rewrite recording execute <action-id>
backend-rewrite repair verify <repair-id>
```

Rewrite action schema v8 always returns `action.kind`, `action.summary`,
`action.details`, and `action.commands`. Variant facts exist only under
`details`; executable argv exist only under role-named `commands` such as
`execute`, `status`, `advance`, `recover`, `evidence`, `apply`, and `acceptance`.
Status does not duplicate an `active_issue` or publish an unconditional
top-level `next`. Every returned command contains a canonical `cwd` plus exact
argv. The argv includes the canonical absolute `--target-root`, so executing a
read-only evidence command from an isolated worker worktree still addresses the
single coordinator state.

The binary writes one compact JSON object per command by default. Pass global
`--pretty` only for interactive human inspection. This keeps automation output
atomic and avoids reconstructing one response with `head` and `tail`.

`next` returns an opaque standard/comparison
`action.commands.execute` recording action. `action.details.run_id` identifies
the preallocated run. The coordinator either reuses one exact-scope atomic
real-traffic input or opens a fresh external-live-traffic recording window;
callers do not add curl loops, replayers, shell pipelines, backgrounding, or
driver parameters. `execute` starts a detached coordinator-owned worker and
returns immediately. Poll
`backend-rewrite status`; `recording_in_progress` never returns a second execute action,
and `advance_required` means finalization and cleanup completed, so its exact
`action.commands.advance` can advance coordinator state. It does not mean
rerunning the completed action. Historical
input is reused only when its API selector exactly equals the requested
selector; recordings are never split or merged. When no exact atomic input
exists, `action.details.input_mode=external_live_traffic` opens a fresh
recording window and includes bounded candidate/rejection diagnostics under
`action.details.recording_input_diagnosis`. When startup omits `--api`, recorder
configuration limits the standard run and the coordinator derives a stable
API inventory from its published cases. `next` and `status` expose only its
bounded summary (`total`, `completed`, `pending`, `implementation_required`,
`current_index`, and `current_api`) so their size does not grow with API count.
The read-only `backend-rewrite inventory` command returns the full ordered
per-API list. Every `implementation_required` action is assigned to an isolated
subagent, including a single-API workflow. The main orchestrator dispatches
before executing evidence, and each worker owns evidence, diagnosis, target
code, and local tests for only its API. With multiple APIs, the orchestrator
uses `backend-rewrite inventory` to choose an exact pending item and continues
with `next --api` after dispatch rather than waiting for the current worker.
After status returns
`advance_required`, the returned `next` validates the
preallocated run, prepares the current API, runs focused E2E, and returns
either one bounded implementation issue or the next comparison action. Once
comparison passes, the following `next` prepares the next inventory item from
the same standard recording. A repository or policy change makes prior
E2E/comparison evidence stale and causes `next` to
rerun the required stage. `terminal_allowed` is false until every inventory
item has both passing E2E and comparison evidence for the same target revision.

Recording, focused Replay, and comparison share one serialized traffic-runtime
lease. When another API owns it, action schema v8 returns `wait_required` with
the requested and blocking APIs, the live operation when available, a retry
delay, and the exact `commands.status` argv. This lease serializes each traffic
operation, not a complete API lifecycle: while worker A implements, the
orchestrator may run Replay for API B and dispatch worker B. No worker may start
a traffic operation. If code changes during Replay, that result is discarded;
later code changes also requeue already-completed API evidence.

`status [--api]` is read-only and returns the selected API's `action` from the
persisted workflow revision. Before execution starts it reconstructs the same
run ID and argv; owner status for a live detached worker may return
`recording_in_progress`, and only a
finalized manifest returns `advance_required`. A running manifest without a live
owner returns `recovery_required`; `backend-rewrite recover` removes only that run's
managed resources and allocates a replacement run. A pending rule plan produces
`plan_apply_required` with only the stored plan ID. The persisted plan keeps
the evidence validation performed at plan time, so its own workflow revision
does not make apply stale. A corrected plan using the same evidence ID replaces
the pending preview before apply; recorder configuration is still changed only
by apply. A target repository change also returns `advance_required` with
`backend-rewrite next`.

A failed focused E2E attempt reuses the same finalized standard cases after the
target changes. A passing attempt advances to a newly allocated comparison
recording. Use `backend-rewrite recording request --kind standard` only for an explicit
new-traffic request, a changed Recorder contract, or a changed source baseline.
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

Only use returned `backend-rewrite evidence` query IDs for coordinator gate and
aggregate facts. The `representatives` result includes the representative case
ID, its exact immutable standard or comparison `case_dir`, and a structured
response difference. A focused E2E difference contains expected and actual
observations; a comparison difference contains source-before, candidate, and
source-after observations. It does not duplicate the complete Replay response
or expose a Replay-local result directory. The AI may inspect all persisted
files under `.traffic-e2e/local/artifacts/`, starting with the representative case for
efficiency. Artifacts remain read-only, and coordinator results remain
authoritative for the active run and legal transitions.

For a dependency issue, `representatives` and `dirty_clusters` read a bounded
Replay dependency sidecar instead of the complete Replay report. The sidecar
contains only case-scoped unmatched, unsupported, unsafe, and unused-case
events, grouped by protocol and `host:port`, with bounded operation counts and
one exact representative `case_dir`. Each compact cluster has a stable
`cluster_id` and the correlated startup interaction count. Full source data
interactions recorded before readiness are returned only by the separate
`pre_readiness_traffic` query. They do not affect the case gate.
`unused_global` events and target activity outside an active case remain
aggregate diagnostics and do not make a case dirty.

Dependency evidence can be projected without parsing the JSONL directly:

```bash
backend-rewrite case dependencies <representative-case-dir>
```

The summary is grouped by stable target ID and includes an exact
`detail_command` for every target. Executing that command returns only the
selected target's bounded operation details and representative exchanges. Redis
exchanges keep keys, arguments, and responses associated; response previews are
capped at 256 bytes and retain encoding, original length, and truncation
metadata. Complete small Redis scalar frames also expose a decoded
`response_value`. Keys are labeled only for understood command shapes. Memcached
representative keys and outcomes are returned together, but flags are
intentionally neither interpreted nor exposed. Dependency `representatives` and `dirty_clusters` evidence also
return the appropriate summary command so an AI does not need to reconstruct
argv or write an ad hoc artifact parser.

Use `backend-rewrite rule plan|apply` for a source-proven response rule and
`backend-rewrite route` for a proven Recorder/Replay capability gap, external-data
blocker, or source change. Query IDs and evidence IDs are bound to the workflow
revision and active issue, so stale evidence is rejected.

An accepted route snapshots a coordinator-defined system or source revision and
returns `repair verify <repair-id>`. The caller cannot provide an acceptance
command, and `next` or `recording request` cannot bypass the repair. Successful
verification decides whether to rerun the same cases or allocate fresh standard
recording evidence.

The lower-level commands in the remainder of this section are the traffic
engine interface used by the coordinator and by traffic-e2e maintainers. They
are not the normal rewrite-AI workflow.

Initialize all three generated documents once:

```bash
traffic-e2e config init --target-root ../target \
  --source-container <existing-source-container> [--breeze]
```

From the target root, `--target-root` is unnecessary. `--breeze` uses the
conventional existing container named `breeze`; use `--breeze=<container>` only
for a non-standard name. Defaults are source port `8080`, target port `8081`,
readiness `/healthz` with status `404`, and upstream DNS `10.10.10.11:53`.
Override a default only when the inspected application contract proves it is
different. Source and Breeze containers need only be inspectable, not running.

The command atomically generates version-9 `.traffic-e2e/project.yaml`,
`.traffic-e2e/recorder.toml`, and `.traffic-e2e/verification.yaml`. Project
configuration has explicit source, optional Breeze, target, replay, recording,
delivery, and state sections. A typical
target section is:

```yaml
target:
  cli: scripts/<project>-cli
  boot_dir: .traffic-e2e/local/boot
  http_host: 127.0.0.1
  port: 8081
  readiness_path: /healthz
  readiness_status: 404
  startup_timeout_seconds: 60
  request_timeout_seconds: 30
  max_response_bytes: 33554432
```

Existing configuration is never overwritten. If any generated file exists,
the whole initialization refuses without creating another file. In-place
migration of obsolete versions is a separate future command. The initializer
idempotently adds `/.traffic-e2e/local/` to the repository `.gitignore`; all
non-versioned runtime data lives below that root. It records
`.traffic-e2e/local/boot` but neither requires nor creates it. Do not hand-write
generated state.

The target exposes only:

```text
scripts/<project>-cli start --e2e --start-breeze off \
  --boot-dir .traffic-e2e/local/boot --port <configured-port>
scripts/<project>-cli stop
```

For Breeze-aware standard recording, the managed runtime keeps one
target-scoped source-adapter cache tag. Each run fingerprints the inspected
source image ID and complete adapter build context: a matching image is reused,
while a missing or stale image is rebuilt. Cleanup removes the run-private
context and containers but retains the matching adapter image. Comparison
recording continues to use the genuine source image directly.

Each `start --e2e` invocation must run the project's normal compile command
once before launch, even when an artifact already exists. If that compile
command supports `--release`, pass `--release` to the compile command and
launch the resulting release artifact. Do not append `--release` to the
`start` command itself. The compile runs once per target start, not once per
replayed case.

The runner sends HTTP requests itself; the target CLI does not read cases or
write response reports. The configured port is shared by target start,
readiness, replay requests, and comparison requests.

Prepare each API after confirming whether its source URI is static or dynamic:

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

One attempt starts Replay once, starts the target once, executes every selected
case through the runner-owned HTTP driver, stops the target once, and finalizes
Replay. The terminal JSON reports independent `responses`, `replay`, and
`dependencies` gates plus a bounded `diagnosis` containing counts, clustered
Pointer/kind differences, and one representative expected/actual observation.
Value presence explicitly distinguishes JSON null, missing, unavailable, and
not-applicable evidence.

Normal AI operation starts with the bounded terminal result. Representative
evidence links directly to an immutable recorded case for request, expected
response, and dependency inspection, and the AI may inspect any other artifact
as needed. A target rewrite agent must not read, search, or list
`.traffic-e2e/local/ai-forbidden/**`; use coordinator output instead. Engine
maintainers may inspect it only under this repository's `AGENTS.md`. Generated
assertion details, aggregate reports, `.active`, and `latest` are internal
surfaces rather than ordinary migration evidence.

Run the current complete API group only until it passes, then stop. Focused
attempts replace the selected API's terminal contribution to the current
logical run, while each finalized attempt is counted once in
`replay-progress.yaml`. Reprocessing the same published attempt is idempotent.
The committed progress file contains aggregate and latest-run evidence; its
per-run idempotency ledger is stored in the ignored
`.traffic-e2e/local/artifacts/progress/replay-counted-runs.yaml` sidecar. Comparison
progress uses the sibling `comparison-counted-runs.yaml` sidecar. Focused
evidence never replaces the global full-round `latest`.

After every published case is prepared exactly once and every focused group
passes, the grouped result is sufficient unless behavior-affecting code changed
after an earlier group pass. In that case, run the complete regression round:

```bash
traffic-e2e run \
  --target-root ../target \
  --case-source recordings/<run>/<rule>
```

The full command uses the same single target lifetime for the complete round,
atomically publishes runner-owned evidence, and updates
`.traffic-e2e/replay-progress.yaml`.

The current logical run passes only with complete response, replay, and
dependency gates. Replay success does not replace current comparison evidence.
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
<run-id>/errors.jsonl
<run-id>/global-dependencies.jsonl
<run-id>/global-dependencies-summary.json
<run-id>/pre-readiness-traffic-summary.json
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
`pre-readiness-traffic-summary.json` is a bounded projection of only source
`bootstrap` data interactions grouped by `host:port`. It excludes connection
lifecycle events and known ping, heartbeat, and setup exchanges. The rewrite
coordinator exposes the projection through its opaque evidence-query API, so a
target AI does not need to read this file or the Global JSONL directly.

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
source_evidence = "src/config/refresh.rs:42 process-level scheduled refresh"
```

All three selector dimensions and `source_evidence` are required. The source
revision remains in the plan report instead of runtime configuration. A
matching exchange is not attributed to an active API case and therefore does
not enter that case's `dependencies.jsonl` or summary. The ordinary run-level
`traffic.jsonl` continues to retain the exchange only when
`recording.traffic_jsonl` permits it. It also enters
`global-dependencies.jsonl` with `reason=background_rule` and a
`bootstrap|runtime` phase. The rule changes
ownership only; it does not alter forwarding, response capture, body limits,
or protocol debugging. Add a rule only after response assertions pass and
source inspection proves process ownership and case independence. Low-level
Recorder use applies the rule during future capture. In the managed
`backend-rewrite` workflow, dependency-rule apply also derives a current
case/global ownership view from the existing immutable capture, rewrites only
the generated replay report and dependency-evidence sidecar, and revises the
same focused attempt. A clean result advances without a new standard recording;
only missing semantic capture, a genuine Recorder contract change, or a source
baseline change requires fresh traffic.
The coordinator also detects an already-finalized attempt whose effective
dependency view is clean but whose persisted errors still contain the obsolete
strict dirty-finalize result. `backend-rewrite next` removes only that
dependency-derived error, preserves genuine lifecycle errors, revises the same
attempt, and resumes at comparison without rerunning E2E.

Use a finalized replay report to create the AI-managed rule instead of editing
the table directly:

```bash
traffic-e2e config recorder apply background-dependencies \
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
before its atomic write. One rule owns one exact authority, method, and path
prefix; use separate rules for distinct request families.

Source-proven process-owned Motan traffic uses one exact RPC identity:

```bash
traffic-e2e config recorder apply background-dependencies \
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
traffic-e2e config recorder apply background-dependencies \
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

Planning requires every configured exact key in replay-safe, unused case
evidence. Replay consumes each response once and matches the exact target,
command, and key, without inheriting the source connection binding or earlier
unrelated lane commands. Case and bootstrap-only exchanges retain
connection-order semantics.

For example, replace `get` above with `scard` or `hgetall` while retaining the
same `--port`, repeated `--key`, and `--initial-load-timeout-ms` inputs. These
selectors do not accept key prefixes, patterns, fields, or a generic command
argument.

Breeze-backed Memcached profile or local-cache warm traffic uses a bounded
numeric key series:

```bash
traffic-e2e config recorder apply background-dependencies \
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
