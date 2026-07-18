# Development Guide

Use this file for local commands, runtime behavior, recording, replay, and
testing details. Keep `AGENTS.md` as the short navigation map.

## Rust Tooling

Use the standard Cargo workflow:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
scripts/check-code-organization
cargo build
```

The repository includes `.cargo/config.toml` for the configured crates.io
mirror. Do not replace that registry configuration unless explicitly asked.

## Running Locally

Run the service with:

```bash
cargo run -- --config config/recorder.example.toml
```

For watch-mode recording, install the repo-level command and run
`traffic-record`:

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
traffic-record --config config/recorder.example.toml
```

`traffic-record` enables local DNS capture and fake-IP TCP/UDP redirect by default,
which modifies local DNS/iptables state through the setup scripts. Use this
when you intentionally want the recorder to intercept local traffic. To skip
those rules:

```bash
traffic-record --config config/recorder.example.toml --no-dns
```

`traffic-record` always limits DNS and fake-IP interception to the dedicated
Unix user `trp-record`. Run the source service as that user so bootstrap and
case dependencies are not polluted by unrelated local processes. The owner
scope cannot be overridden by CLI options, environment variables, or recorder
configuration.

HTTP gateway recording is intentionally conservative. Until the configured
ready probe succeeds, matching traffic is sent to `fallback_upstream` and no
case is created. After ready, only one matched case can be active at a time;
overlapping matching requests are also sent to fallback so dependencies are not
shared across cases.

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
later matching requests are sent directly to `fallback_upstream` without
creating a case. Failed cases do not consume the limit, and restarting Recorder
starts a new run with fresh counts.

After an upstream HTTP response completes, Recorder keeps the case active until
captured dependencies are idle for
`recording.case_dependency_quiet_period_ms`. This captures synchronous
server-side after-hooks that start dependency requests only after writing the
response. The quiet timer restarts when dependency activity begins or ends, and
in-flight MySQL queries retain their original case ownership through the
semantic exchange. If the case does not become quiet within
`recording.case_dependency_drain_timeout_ms`, Recorder fails the case instead
of publishing incomplete dependency evidence. Matching requests continue to
use the fallback upstream while the previous case drains.

### Rewriting HTTP Responses

HTTP response rewriting is an opt-in recording feature for responses that
publish a later connection target. The first built-in plugin,
`pluto-eci-kubeconfig`, rewrites the Kubernetes API server in Pluto ECI's
`user_config` JSON response from an IPv4 address to a synthetic `.test` domain.
That domain is registered in the recorder's fake-DNS registry and routed to a
local `kubectl proxy`, allowing the later HTTPS traffic to pass through the TCP
gateway and be recorded. The rewritten kubeconfig uses HTTPS and replaces its
cluster CA with the Recorder CA so client-go retains the TLS credentials and
trusts the Recorder-generated certificate for the synthetic domain. The
original kubeconfig, including its original CA and Kubernetes server IP, is
passed unchanged to the managed `kubectl proxy`.

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

Enable the example `[http_response_rewrite]` configuration in
`config/recorder.example.toml` and ensure the configured `kubectl_binary` is
installed. The rewrite feature requires `dns_mock`, `tcp_gateway`, and
`tcp_gateway.record_http` to be enabled. The configured `proxy_listen` address
must not already be occupied.

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
cargo build
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/debug/traffic-recorder-proxy" "$HOME/.local/bin/traffic-recorder-proxy"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
ln -sf "$PWD/scripts/traffic-replay" "$HOME/.local/bin/traffic-replay"
ln -sf "$PWD/scripts/traffic-replay-target" "$HOME/.local/bin/traffic-replay-target"
ln -sf "$PWD/scripts/traffic-replay-policy" "$HOME/.local/bin/traffic-replay-policy"
ln -sf "$PWD/scripts/traffic-replay-cli" "$HOME/.local/bin/traffic-replay-cli"
ln -sf "$PWD/scripts/traffic-replay-aggregate" "$HOME/.local/bin/traffic-replay-aggregate"
ln -sf "$PWD/scripts/traffic-recorder-config" "$HOME/.local/bin/traffic-recorder-config"
ln -sf "$PWD/scripts/traffic-case-group" "$HOME/.local/bin/traffic-case-group"
ln -sf "$PWD/scripts/traffic-e2e-run" "$HOME/.local/bin/traffic-e2e-run"
traffic-replay path/to/case-dir
traffic-replay --no-intercept path/to/case-dir
```

Target-specific dynamic UUID, timestamp, and signed-query matching belongs in
a source-controlled `config/replay.yaml`, not product code or recorded fixture
overrides. Validate and load it explicitly:

```bash
traffic-replay-policy validate --policy ../target/config/replay.yaml
traffic-replay --policy ../target/config/replay.yaml path/to/case-dir
```

See [replay-policy.md](replay-policy.md) for the policy schemas,
assertion-only `expected-response.json` contract, dependency rule scoping,
runner-owned dynamic and unordered response fields, and dirty-evidence
behavior.

Recorder-owned host exceptions for API-independent process-level tasks remain
in the target repository's `recorder.toml`, not `replay.yaml`. Preview and
apply an add-only host after source inspection proves that all traffic to that
host belongs to a task that is unrelated to API handlers:

```bash
traffic-recorder-config allowed-unused-http-hosts plan \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --host cs.aliyuncs.com \
  --format json

traffic-recorder-config allowed-unused-http-hosts apply \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --host cs.aliyuncs.com \
  --format json
```

The tool bootstraps and then owns an
`AI-MANAGED ALLOWED UNUSED HTTP HOSTS` block inside the selected named
`[[http_gateway.rules]]` entry. Plans are add-only, sorted, deduplicated, and
safe against concurrent config changes. One host applies to every case selected
by that recording rule, independent of which active API window happened to
capture the process-level task.

Pass the config and rule together for direct replay:

```bash
traffic-replay \
  --policy ../target/config/replay.yaml \
  --recorder-config ../target/config/recorder.toml \
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

`traffic-replay` also uses the fixed `trp-record` owner filter. Run the
dependency-producing target process as that user. Build steps, replay itself,
and replay-control commands may remain under the developer account. If the
target cannot run as `trp-record`, intercepted replay is blocked; do not widen
the owner scope to the login user or all local users.

For a prebuilt in-process E2E command, use `traffic-replay-target` rather than
granting the fixed user access to the workspace or build cache:

```bash
traffic-replay-target \
  --copy-env APP_CONFIG=path/to/e2e.yaml \
  --copy-env REPLAY_CA=path/to/replay-ca.pem \
  --path-env CASE_DIR=path/to/readable/case-group \
  --write-dir logs \
  -- path/to/prebuilt-e2e --case-id <case-id>
```

The caller must have non-interactive sudo permission for staging ownership and
for running as the recorder's fixed user. Copied inputs are read-only to the
target; the temporary work tree is writable and removed after execution.
`--path-env` does not widen source permissions and fails when the fixed user
cannot already read the path. The
helper clears inherited proxy and shell-hook variables, verifies the effective
UID, and never accepts a user or UID option. Keep replay lifecycle commands
outside the target process.

For a case collection, start one replay session and control active case
ownership through the CLI:

```bash
traffic-replay path/to/recordings/<run-id>/<rule>/<uri-group>
traffic-replay path/to/recordings/<run-id>
traffic-replay --case-id <case-id> path/to/recordings/<run-id>
traffic-replay-cli wait-ready
traffic-replay-cli cases
traffic-replay-cli begin <case-id>
traffic-replay-cli end <case-id> --fail-on-dirty
traffic-replay-cli finalize --fail-on-dirty --fail-on-incomplete
```

Successful `finalize` writes a version-five report with its session id,
timestamps, exact selected case ids, and `finalized: true`, then stops replay.
The command returns success only after atomically publishing that exact report;
a report-write failure leaves the session open for retry. If finalization
fails, preserve the diagnostic report and use
`traffic-replay-cli stop` only for cleanup. Default replay reports are retained
under a unique `.replay/sessions/<attempt>/replay-report.json` directory.
Protocol traffic requests live snapshots through one coalescing writer, which
writes at most once per second; lifecycle commands and finalization force an
immediate snapshot. Version five keeps exact success counters while retaining
at most `success_detail_limit` successful event details per category. Dirty
event details remain complete, and unused MySQL entries reference bounded SQL
previews plus fingerprints instead of copying arbitrarily large SQL strings.

For a collection, multi-case selection, or multiple sessions, generate one
deterministic coverage and dependency summary from the recording source root.
Select the exact final case and session ids so older attempts cannot satisfy the
gate:

```bash
traffic-replay-aggregate \
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

`traffic-replay-cli` is a thin facade over `traffic-recorder-proxy
replay-control`; the Rust binary owns the control protocol and Unix socket
client. The script should stay small and should not implement JSON/socket
protocol logic.

Before migrating a dynamic API from a collection, persist its exact immutable
case grouping outside the recording source:

```bash
traffic-case-group ensure \
  --case-source /path/to/recordings/<run-id>/<rule> \
  --case-dir /path/to/recordings/<run-id>/<rule>/<current-uri-group> \
  --method GET \
  --source-route '/api/users/:id' \
  --pattern '/api/users/*' \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --output ../target/.migration/run-reports/<run-id>-case-groups.json \
  --recorder-config ../target/config/recorder.toml \
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
a target repository. Preview focused, add-only feedback before applying it:

```bash
traffic-recorder-config case-path-patterns plan \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'

traffic-recorder-config case-path-patterns apply \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'
```

The selected rule must already contain exactly one explicit
`BEGIN/END AI-MANAGED CASE PATH PATTERNS` block. The command preserves all text
outside that block, sorts and deduplicates patterns, validates the complete
recorder config, and replaces the file atomically. Focused feedback cannot
remove patterns. Authoritative feedback may remove them only when the case
collection is declared authoritative and `apply` includes `--allow-delete`.
Use `--format json` for machine-readable feedback. The command never modifies
recordings or existing case directories.

A focused plan with no `--pattern` is valid and returns `no_candidates: true`
with no config diff. This provides mandatory no-change evidence without
rewriting the managed block or its source revision.

After the final aggregate and target response-assertion report exist, ensure
the recorder exclusion deterministically:

```bash
traffic-recorder-config verified-excludes ensure \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --method GET \
  --pattern '/api/users/*' \
  --aggregate-report ../target/.migration/run-reports/run.json \
  --assertion-report ../target/.migration/run-reports/assertions.json \
  --format json
```

`ensure` returns `below_threshold` without changing the config, returns
`already_present` for an existing exact entry, or atomically applies an
eligible entry and replans before returning `applied`. Dirty, incomplete, or
mismatched evidence fails the command. `plan` and `apply` remain available for
diagnostics, but migration automation must not reimplement their eligibility
branching.

The threshold and managed exclusions live in `recorder.toml`, never
`replay.yaml`. See [verified-api-excludes.md](verified-api-excludes.md) for the
assertion report schema, exact case-set gate, and runtime behavior.

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

## Migration E2E Runner

Use `scripts/traffic-e2e-run` as the high-level migration replay facade.
Initialize the target repository once:

```bash
traffic-e2e-run init \
  --target-root ../target \
  --project-cli scripts/<project>-cli \
  --replay-policy config/replay.yaml \
  --pr-base <confirmed-base-branch> \
  --recorder-config config/recorder.toml \
  --recording-rule record-api
```

The command requires confirmed `project_cli`, `replay_policy`, and
`pr_base` values, validates that the branch exists locally or as an
`origin` remote-tracking branch, checks that `.migration/local/` is ignored,
and generates `.migration/e2e.yaml`:

```yaml
version: 4
project_cli: scripts/<project>-cli
replay_policy: config/replay.yaml
pr_base: <confirmed-base-branch>
recorder_config: config/recorder.toml
recording_rule: record-api
local_root: local
```

The recorder flags are optional only as a pair. Existing configuration is not
overwritten unless `--force` is explicit. If the file is missing, every other
runner command points back to `init`; if any required field is missing or the
configured PR base no longer resolves, every command fails before using
migration state. `prepare`, `run-api`, and `run` require a named feature branch
different from `pr_base`. Do not hand-write it. Prepare each API only after
confirming whether its source URI is static or dynamic:

```bash
traffic-e2e-run prepare \
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
traffic-e2e-run run-api \
  --target-root ../target \
  --case-source recordings/<run>/<rule> \
  --api 'GET /api/widgets/*'
```

Focused attempts persist only per-API diagnostic evidence. They do not change
the full-round report, progress, or verified excludes.

After every published case is prepared exactly once and focused migration is
ready, run the complete regression round:

```bash
traffic-e2e-run run \
  --target-root ../target \
  --case-source recordings/<run>/<rule>
```

The full command starts replay once, loads bootstrap and all selected cases
once, starts the target once, executes cases sequentially, finalizes and
aggregates once, runs per-API verified-exclude ensure, atomically publishes
`.migration/local/<run-key>/latest/`, and updates the Git-eligible
`.migration/e2e-progress.yaml`.

One terminal full round reaches `status: complete` when every case and API
passes and canonical replay evidence is finalized, complete, and clean. A
failed or interrupted round remains `needs_attention`; after focused repair,
start a new full round from the beginning. Use `status`, `abort`, and `recover`
for interrupted global rounds. Generated local JSON/YAML is tool-owned and must
not be edited by AI or by target scripts.

When using setup scripts directly, always pair `up` with `down`:

```bash
sudo ./scripts/setup_local_dns.sh up
sudo ./scripts/setup_fake_ip_redirect.sh up
sudo ./scripts/setup_fake_ip_redirect.sh down
sudo ./scripts/setup_local_dns.sh down
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
- `recordings/`
- `*.swp`

Do not commit generated CA files, traffic recordings, test captures, or local
swap files.

Each recorder process creates one run directory under `recording.output_dir`
named `YYYYMMDDHHMMSS`. Valid case output is published inside that run:

```text
<run-id>/traffic.jsonl
<run-id>/recording-run.json
<run-id>/errors.jsonl
<run-id>/bootstrap-dependencies.jsonl
<run-id>/bootstrap-dependencies-summary.json
<run-id>/bootstrap-dependencies-debug.jsonl
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
with `recording-error.json` instead of being published. On clean shutdown,
recording exits with an error if the run contains failed cases.

Use `dependencies.jsonl` for replay-oriented semantic data. Use
`dependencies-debug.jsonl` only for protocol-level debugging. UDP datagrams,
including push-metrics side effects, are recorded as semantic dependencies when
captured by the UDP gateway. Run-level
bootstrap dependency files capture replay-oriented dependencies observed before
the service is ready, or before the first case starts when no ready probe is
configured. Replay discovers them by walking upward from a case directory.

Redis and Memcached dependencies are semantic `redis_connection`,
`redis_exchange`, `memcached_connection`, and `memcached_exchange` records.
Successful Redis authentication/session initialization is handled by replay
and omitted from case dependencies; failed initialization remains as redacted
evidence. Any truncated frame, parse/correlation failure, unsupported cache
mode, or unsafe cache connection prevents a case from being published and
prevents unsafe bootstrap replay from starting. The recording directory is
sensitive because ordinary cache keys and values are needed for exact replay.

Kafka dependencies are semantic `kafka_connection`, `kafka_produce`, and
`kafka_delivery` records. V1 is a successful-path dependency facade rather than
a full Kafka broker: use an E2E client profile with
`security.protocol=PLAINTEXT`, `compression.type=none`,
`enable.idempotence=false`, and `acks=1`. Replay advertises one broker and one
partition, synthesizes control-plane responses, matches Produce by exact topic,
key, headers, and value bytes, and delivers recorded Fetch records once.
Transactions, Admin APIs, compression, TLS/SASL, rebalance behavior, retries,
and Kafka failure injection are unsupported and fail closed. Schema Registry
remains an ordinary HTTP dependency. Kafka payloads and headers are sensitive
because exact bytes are required for replay.

Dependency summaries are generated when a case is published, when bootstrap
recording closes, and when the run finishes. They are intentionally not rebuilt
after every cache exchange.

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
```

Network or root-requiring behavior should be covered with isolated unit tests
where possible. Do not require host iptables changes for automated tests.
