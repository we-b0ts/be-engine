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

## CLI Boundaries

Use `traffic-e2e init|prepare|run-api|run|status|recover|abort` for the standard
workflow. Use `traffic-e2e diagnose ...` only for recorder development or
focused low-level diagnosis. Managed record, replay, target isolation, and host
interception are implemented in the Rust binary. Repository scripts are
development checks or explicit host trust-store tools only.

## Running Locally

Run online baseline/candidate mirroring with:

```bash
traffic-e2e compare --config config/compare.example.toml
```

Compare mode does not compare responses. It returns the baseline response and
records the request plus baseline and candidate responses under
`<recording.output_dir>/comparisons/<run-id>/`. It does not load replay policy,
record dependencies, install interception rules, or initialize a MITM CA.
Explicit named HTTP gateway rules and methods are required. Only GET, HEAD, and
OPTIONS may be mirrored unless `[compare].allow_side_effecting_methods = true`;
side-effecting methods must still be explicitly listed in a rule. Reaching an
API case limit suppresses later case files for that API but does not stop
mirroring.

Compare artifacts carry `case-kind.json` with `kind = online_compare` and are
not replay inputs. `prepare`, case grouping, and replay reject them explicitly.
The process creates one run for its lifetime; restart it or provide a new
`--run-id` to reset case quotas. Archive and remove old runs externally.

Run the service with:

```bash
cargo run -- diagnose recorder --config config/recorder.example.toml
```

Install the binary and run managed recording:

```bash
cargo install --path .
traffic-e2e record --config config/recorder.example.toml
```

`traffic-e2e record` enables local DNS capture and fake-IP TCP/UDP redirect by
default, which modifies local DNS/iptables state. Use this when you
intentionally want the recorder to intercept local traffic. To skip those
rules:

```bash
traffic-e2e record --config config/recorder.example.toml --no-dns
```

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
a source-controlled `.traffic-e2e/replay.yaml`, not product code or recorded fixture
overrides. Validate and load it explicitly:

```bash
traffic-e2e diagnose replay-policy validate --policy ../target/.traffic-e2e/replay.yaml
traffic-e2e replay --policy ../target/.traffic-e2e/replay.yaml path/to/case-dir
```

See [replay-policy.md](replay-policy.md) for the policy schemas,
assertion-only `expected-response.json` contract, dependency rule scoping,
runner-owned dynamic and unordered response fields, and dirty-evidence
behavior.

Recorder-owned host exceptions for API-independent process-level tasks remain
in the target repository's `.traffic-e2e/recorder.toml`, not
`.traffic-e2e/replay.yaml`. Preview and apply an add-only host after source
inspection proves that all traffic to that host belongs to a task that is
unrelated to API handlers:

```bash
traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  allowed-unused-http-hosts plan \
  --rule record-api \
  --host cs.aliyuncs.com \
  --format json

traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  allowed-unused-http-hosts apply \
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
traffic-e2e replay \
  --policy ../target/.traffic-e2e/replay.yaml \
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
  --env-file path/to/local.env \
  --copy-env APP_CONFIG=path/to/e2e.yaml \
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

Successful `finalize` writes a version-five report with its session id,
timestamps, exact selected case ids, and `finalized: true`, then stops replay.
The command returns success only after atomically publishing that exact report;
a report-write failure leaves the session open for retry. If finalization
fails, preserve the diagnostic report and use
`traffic-e2e diagnose replay-control stop` only for cleanup. Default replay
reports are retained under a unique
`.replay/sessions/<attempt>/replay-report.json` directory.
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
a target repository. Preview focused, add-only feedback before applying it:

```bash
traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  case-path-patterns plan \
  --rule record-api \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'

traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  case-path-patterns apply \
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
block. Name it explicitly, attach single-line source-route evidence, inspect
and show the plan diff, then apply the same correction with `--allow-delete`
only after the user requested or approved it:

```bash
traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  case-path-patterns plan \
  --rule record-api \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/cases \
  --remove-incorrect-pattern '/api/incorrect/*' \
  --correction-evidence 'router.go@<revision>: route is static /api/incorrect'

traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  case-path-patterns apply \
  --rule record-api \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/cases \
  --remove-incorrect-pattern '/api/incorrect/*' \
  --correction-evidence 'router.go@<revision>: route is static /api/incorrect' \
  --allow-delete
```

Omission from recordings, including an authoritative or full case source, is
never correction evidence. On the initial correction plan, every named pattern
must appear in `removed`. Replanning the same correction after apply reports it
under `corrections_already_absent` with an empty diff. Use `--format json` for
machine-readable feedback. The command never modifies recordings or existing
case directories.

A focused plan with no `--pattern` is valid and returns `no_candidates: true`
with no config diff. This provides mandatory no-change evidence without
rewriting the managed block or its source revision.

After the final aggregate and target response-assertion report exist, ensure
the recorder exclusion deterministically:

```bash
traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  verified-excludes ensure \
  --rule record-api \
  --method GET \
  --pattern '/api/users/*' \
  --aggregate-report ../target/.traffic-e2e/run-reports/run.json \
  --assertion-report ../target/.traffic-e2e/run-reports/assertions.json \
  --consecutive-successful-runs 3 \
  --consecutive-successful-cases 9 \
  --required-consecutive-successful-runs 3 \
  --required-successful-cases 3 \
  --format json
```

`ensure` returns `below_threshold` without changing the config, returns
`already_present` for an existing exact entry, or atomically applies an
eligible entry and replans before returning `applied`. Dirty, incomplete, or
mismatched evidence fails the command. `plan` and `apply` remain available for
diagnostics, but traffic E2E automation must not reimplement their eligibility
branching.

Thresholds live in `.traffic-e2e/e2e.yaml`; `.traffic-e2e/recorder.toml` stores only
the managed verified exclusions. Neither belongs in `.traffic-e2e/replay.yaml`. See
[verified-api-excludes.md](verified-api-excludes.md) for the assertion report
schema, exact case-set gate, and runtime behavior.

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

## Migration E2E Runner

Use `traffic-e2e` as the high-level migration replay command. Initialize the
target repository once:

```bash
traffic-e2e init \
  --target-root ../target \
  --project-cli scripts/<project>-cli \
  --replay-policy .traffic-e2e/replay.yaml \
  --api-verification-consecutive-successful-runs 3 \
  --api-verification-successful-cases 3 \
  --api-verification-override 'GET /api/widgets/*=5,200' \
  --pr-base <confirmed-base-branch> \
  --recorder-config .traffic-e2e/recorder.toml \
  --recording-rule record-api
```

The command requires confirmed `project_cli`, `replay_policy`, and
`pr_base` values, validates that the branch exists locally or as an
`origin` remote-tracking branch, checks that `.traffic-e2e/local/` is ignored,
and generates `.traffic-e2e/e2e.yaml`:

```yaml
version: 4
project_cli: scripts/<project>-cli
replay_policy: .traffic-e2e/replay.yaml
replay_startup_timeout_seconds: 60
api_verification:
  consecutive_successful_runs: 3
  successful_cases: 3
  overrides:
    GET /api/widgets/*:
      consecutive_successful_runs: 5
      successful_cases: 200
pr_base: <confirmed-base-branch>
recorder_config: .traffic-e2e/recorder.toml
recording_rule: record-api
local_root: local
```

`replay_startup_timeout_seconds` controls how long the runner waits for replay
to finish loading cases and publish its ready session; it defaults to 60 when
omitted from an older config. The runner prints `loaded_cases=0` when dependency
loading starts, then relays progress about every 5% by loaded case count while
retaining the complete replay log in the run reports directory.

`api_verification` owns both verification thresholds. The top-level values are
defaults. `overrides` uses the canonical runner API id
`METHOD path_pattern`; each entry replaces both defaults for that exact API.
The repeated `--api-verification-override` flag uses
`METHOD path_pattern=successful-runs,successful-cases`. The successful-case
threshold counts canonical cases covered by trailing successful distinct
published runs. Replaying one run does not advance either threshold. Once an
API's effective thresholds are met, the runner synchronizes it into the managed
recorder exclusion list; `.traffic-e2e/recorder.toml` does not own another
threshold.

The recorder flags are optional only as a pair. Existing configuration is not
overwritten unless `--force` is explicit. If the file is missing, every other
runner command points back to `init`; if any required field is missing or the
configured PR base no longer resolves, every command fails before using
traffic E2E state. `prepare`, `run-api`, and `run` require a named feature branch
different from `pr_base`. Do not hand-write it. Prepare each API only after
confirming whether its source URI is static or dynamic:

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
cases. When distinct published runs reach both effective thresholds, the runner
synchronizes the verified exclude. Focused evidence never replaces the global
full-round `latest`.

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
aggregates once, runs per-API verified-exclude ensure, atomically publishes
`.traffic-e2e/local/<run-key>/latest/`, and updates the Git-eligible
`.traffic-e2e/e2e-progress.yaml`.

Progress reaches `status: complete` when every grouped API in the current
logical run has finalized, complete, clean passing evidence. Verification
thresholds are maintained independently and do not gate the current run or
delivery. A grouped focused pass is sufficient unless later behavior changes
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

A complete zero-length response body is publishable even when its
`Content-Type` advertises JSON. Recorder preserves the empty body and replay
assertions compare it as exact bytes. Non-empty bodies advertised as JSON must
still contain valid JSON.

Use `dependencies.jsonl` for replay-oriented semantic data. Use
`dependencies-debug.jsonl` only for protocol-level debugging. UDP datagrams,
including push-metrics side effects, are recorded as semantic dependencies when
captured by the UDP gateway. Run-level
bootstrap dependency files capture replay-oriented dependencies observed before
the service is ready, or before the first case starts when no ready probe is
configured. Replay discovers them by walking upward from a case directory.

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
```

All three selector dimensions and both source-evidence fields are required. A
matching exchange is not attributed to an active API case and therefore does
not enter that case's `dependencies.jsonl` or summary. The ordinary run-level
`traffic.jsonl` continues to retain the exchange only when
`recording.traffic_jsonl` permits it. When the exchange occurs while bootstrap
is open, it remains normal `bootstrap-dependencies.jsonl` replay evidence. The
rule changes ownership only; it does not alter forwarding, response capture,
body limits, or protocol debugging. Add a rule only after source inspection
proves the traffic is independent of the triggering API, then create a new
recording run.

Use a finalized replay report to create the AI-managed rule instead of editing
the table directly:

```bash
traffic-e2e diagnose recorder-config \
  --config .traffic-e2e/recorder.toml \
  background-dependencies plan \
  --name config-refresh \
  --protocol http \
  --authority config.api.demo.test \
  --method GET \
  --path-prefix /1/config/service \
  --replay-report <finalized-replay-report.json> \
  --source-revision 0123456789abcdef \
  --evidence 'src/config/refresh.rs:42 process-level scheduled refresh' \
  --format json

traffic-e2e diagnose recorder-config \
  --config .traffic-e2e/recorder.toml \
  background-dependencies apply \
  --name config-refresh \
  --protocol http \
  --authority config.api.demo.test \
  --method GET \
  --path-prefix /1/config/service \
  --replay-report <same-finalized-replay-report.json> \
  --source-revision 0123456789abcdef \
  --evidence 'src/config/refresh.rs:42 process-level scheduled refresh' \
  --format json
```

`plan` requires at least one matching unused case HTTP exchange and rejects a
selector that also matches unmatched or unsupported target requests. `apply`
rechecks the recorder config and replay report bytes so a reviewed plan cannot
be applied to stale inputs. One rule owns one exact authority, method, and path
prefix; use separate rules for distinct request families.

Recognized MySQL connection maintenance is not a semantic dependency. The
strict built-in fingerprints are protocol `COM_PING`, c3p0's exact
empty-database `SHOW FULL TABLES` probe using the `PROBABLYNOT` sentinel, and exact
`SELECT 1` with an optional trailing semicolon. Their raw `mysql_query` and
`mysql_response` records remain in the applicable case or bootstrap debug
JSONL, while their derived `mysql_exchange` records are omitted from semantic
dependency JSONL and summaries. Replay handles the same fingerprints without a
recorded exchange: ping returns OK, `SELECT 1` returns one integer row, and the
c3p0 empty-database probe returns MySQL error 1102.

Redis and Memcached dependencies are semantic `redis_connection`,
`redis_exchange`, `memcached_connection`, and `memcached_exchange` records.
Successful Redis authentication/session initialization is handled by replay
and omitted from case dependencies; failed initialization remains as redacted
evidence. Any truncated frame, parse/correlation failure, unsupported cache
mode, or unsafe cache connection prevents a case from being published and
prevents unsafe bootstrap replay from starting. The recording directory is
sensitive because ordinary cache keys and values are needed for exact replay.

Semantic MySQL, Redis, Memcached, and Kafka business exchanges also carry
`outcome` and `duration_ms`. Replay waits the recorded duration before a normal
response. If `outcome` is `client_terminated`, replay sends no response and
consumes the exchange only after the SDK closes or resets the same connection
near the recorded time; replay itself does not initiate that close. Intrinsic
no-response commands remain `no_response` and are not treated as timeouts.

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
