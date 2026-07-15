# Replay Workflow

Use this reference when turning a recorded case into a runnable E2E in another
project.

## Target Project Discovery

Inspect before editing:

- package/build files and existing test commands
- E2E or integration test directories
- app/server startup helpers used by tests
- runtime config, dependency wiring, and environment variables used by tests
- places where database, HTTP, cache, queue, or other external dependency
  endpoints can be pointed at replay listeners
- environment configuration for disabling or isolating real external services

Use the project's existing E2E framework and startup style. If no framework
exists, add the smallest conventional E2E setup for that technology stack and
explain why. Do not introduce a broad new architecture just for one case.

## Target E2E Proxy Isolation

Recorded dependency replay expects the target process to connect directly so
DNS and fake-IP interception can observe its traffic. Make the target project's
recorded E2E entrypoint clear inherited HTTP proxy variables before starting
replay or the target process. When the project has or needs a command facade,
put the isolation inside its `e2e` command:

```bash
e2e() {
  unset \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
    http_proxy https_proxy all_proxy no_proxy

  # Start replay and run the recorded E2E command.
}
```

Keep this inside the recorded E2E command rather than at the script's top level,
so `start`, `build`, `check`, and other commands retain the caller's environment.
Do not change the Agent's global proxy settings or add proxy handling to product
code or normal runtime configuration.

If an existing project has no facade that can own this behavior, apply the same
isolation to the target E2E invocation:

```bash
env \
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
  -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
  <target-recorded-e2e-command>
```

## Managed Replay CLI

Use the repository-level replay commands, not skill-local script paths:

- `traffic-replay` starts one replay session for a case or case collection
- `traffic-replay-cli` controls readiness, active case lifecycle, reports, and
  shutdown
- `traffic-replay-aggregate` recursively summarizes this recorder's standard
  replay reports under one supplied case source

`traffic-replay-cli` is a thin PATH facade over `traffic-recorder-proxy
replay-control`; do not generate it inside the target project.

Before running the target E2E, ensure all commands are available on `PATH`.
For local development, prefer installing, copying, or symlinking them into a
user PATH directory such as `~/.local/bin`.

```bash
command -v traffic-recorder-proxy
command -v traffic-replay
command -v traffic-replay-cli
command -v traffic-replay-aggregate
traffic-replay path/to/case-run-or-collection-dir
traffic-replay-cli wait-ready
```

Pass the selected case directory, collection directory, or run directory
directly. A collection directory is usually
`recordings/<run-id>/<rule>/<uri-group>`; a run directory is
`recordings/<run-id>`. The replay session loads bootstrap dependencies plus the
selected case files. Repeat `--case-id` to load an exact subset from a broader
source. Case dependencies are not a global pool. The active
case is selected with `traffic-replay-cli begin <case-id>` and closed with
`traffic-replay-cli end <case-id> --fail-on-dirty`.

The target E2E facade must require that source through `--case-dir` or an
equivalent explicit CI/environment input. Do not embed a developer-machine
absolute recording path, a known recordings root, or a sample batch as an
implicit default. A missing case source is an input error, not permission to
select an older local recording.

Use `traffic-replay-cli wait-ready` before sending any target request. If the
session cannot bind listeners, install DNS/fake-IP rules, or write its initial
report, treat it as a replay lifecycle/setup failure and stop. Do not continue
with the HTTP assertion, do not debug product behavior from that result, and do
not make each target project hand-roll port allocation, process polling, or
leftover replay cleanup.

Use `--no-intercept` only when the target project already routes dependencies
to the replay listeners.
`traffic-replay` always filters interception to its recorder-owned fixed Unix
user. Resolve that identity with `traffic-replay --print-intercept-user`; do not
copy its current name into the skill or target project. The CLI does not accept
an arbitrary user, UID, environment override, or all-user mode.
Target-project tests, command facades, docs, and
migration state MUST NOT pass, emulate, or recommend `--owner-uid`, `--user`,
`--all-users`, `OWNER_UID`, or any equivalent owner selection.

Before replay, resolve the recorder-owned identity and require it to exist:

```bash
intercept_user="$(traffic-replay --print-intercept-user)"
id -u "$intercept_user"
```

Build and orchestration may run as the developer, but the process that emits
dependency connections MUST run as `$intercept_user`. For an out-of-process
service, verify that service PID. For an in-process E2E, build first as the
developer and execute the prebuilt E2E binary as `$intercept_user`; do not run
the build tool or write shared build caches as the system user. If the
workspace or build output is private,
stage only the executable and required public runtime inputs in a temporary
directory owned by `$intercept_user`; do not make the workspace, build cache,
session file, report, or control socket world-writable. Retain the effective
UID check before sending the first case request.

Keep `traffic-replay-cli` lifecycle orchestration under the developer account.
For an in-process E2E, make one invocation handle exactly one selected case:
the outer facade calls `begin`, executes that case's staged binary as
`$intercept_user`, then calls `end`. The fixed-user test process MUST NOT own
replay lifecycle or require access to the private control socket. If the
existing test loops over cases and calls `traffic-replay-cli` internally,
refactor that recorded-E2E boundary before replay; this is isolation work, not
business-code behavior.

If the user is absent, the dependency-producing process identity cannot be
verified, or the harness cannot run it as `$intercept_user`, stop with
`blocked_replay_isolation`. Never fall back to the login user's UID, a
configurable username, all-user capture, or widened session/socket
permissions. `--no-intercept` is not a bypass; it is valid only when every
dependency is explicitly routed to replay listeners.
Do not hardcode the traffic-recorder-proxy repository path or skill path inside
target-project tests. A test harness may allow `TRAFFIC_REPLAY` or a similar
local override, but the default commands must be `traffic-replay` and
`traffic-replay-cli`.

## Replay Construction

Implement in this order:

1. For a collection or run with multiple canonical input directories, complete
   [case-grouping.md](case-grouping.md) first and select exactly one returned API
   group. Do not expand the whole batch into one simultaneous implementation
   scope. Create or extend a test helper that can load one case from
   `recordings/<run-id>/<rule>/<uri-group>/<case-id>`. If the user supplied a
   collection directory such as `recordings/<run-id>/<rule>/<uri-group>` or an
   entire run directory such as `recordings/<run-id>`, inspect each published
   case's `request.json.uri` and select every case that matches the requested
   API path. Ignore `failed`, `staging`, and `.replay` directories. A matching
   set of cases for one API is a case set, not an ambiguity. If zero cases
   match, or the requested scope itself is unclear, report the candidates and
   ask the user to choose.
2. Build the request from the current case's `request.json`. Use the recorded
   method, URI including query string, headers, and body as the source of truth.
   Do not hardcode auth headers, tenant ids, query params, body fields, cookies,
   or other case-specific request data in the target test helper. Remove or
   override only headers that the target test harness cannot or should not set,
   such as hop-by-hop transport headers (`connection`, `content-length`,
   `host`, `transfer-encoding`) or compression headers that the harness cannot
   reproduce.
3. Start managed dependency replay with `traffic-replay
   <case-run-or-collection-dir>`. It uses `dependencies.jsonl` from each
   selected case and bootstrap dependencies discovered above the case
   directory. The canonical bootstrap file is
   `recordings/<run-id>/bootstrap-dependencies.jsonl`.
4. Wait for readiness with `traffic-replay-cli wait-ready`, then point the app
   under test at the replay listeners and keep real external dependencies
   isolated.
5. For each selected case, call `traffic-replay-cli begin <case-id>`, then send
   the request built from that case or invoke the equivalent route.
6. Assert status and response body compatibility. Assert headers only when
   stable and relevant.
7. End the case with `traffic-replay-cli end <case-id> --fail-on-dirty` and use
   `dependencies-summary.json`, when present, as the dependency coverage
   checklist for replay.
8. After the selected case set finishes, run `traffic-replay-cli finalize
   --fail-on-dirty --fail-on-incomplete`. Require a version-four report with
   the exact selected case ids, its session id, `finalized: true`, and
   `finalized_at`. Successful finalization atomically publishes that exact
   report and stops replay. A validation or report-write failure leaves replay
   running; retain the diagnostic report and use `traffic-replay-cli stop` only
   for cleanup.

After all sessions finalize, run `traffic-replay-aggregate --case-source
<source> --case-id <id> --session-id <id> --output <path>
--fail-on-incomplete --fail-on-dirty` for every collection/run source,
multi-case selection, or source replayed through multiple reports or sessions.
Repeat case and session ids to describe the exact final evidence. Retained
attempts that overlap the same case without an exact session selection are an
error, not evidence to merge or guess. The only allowed exemption is one
published case replayed in exactly one finalized session/report; record it as
`not_applicable_single_case_single_session`. Pass only the exact completion
case source root; do not enumerate report paths or manually add counters. Read
[aggregate-report.md](aggregate-report.md) for coverage and dirty-state
semantics. The aggregate covers recorder replay evidence only; the target
runner still owns its HTTP assertions and process exit status.

Run and inspect recorder-owned commands directly even when a target facade
invokes them. A facade exit code, its summary text, or its self-written state is
not evidence. Do not patch a target facade solely to add or claim this gate.

The replay is complete only when the request returns the expected response while
using dependency behavior replayed from the recorded dependency file, and the
case-owned dependency touch contract is satisfied. HTTP response compatibility
alone is not success.

Redis and Memcached replay uses recorded connection lanes. The first matching
request deterministically binds a live connection to a recorded lane and later
requests must consume that lane in sequence. Redis matching includes RESP
version, selected DB, username, command, and exact arguments. Memcached matching
includes Text/Binary wire protocol and request semantics while ignoring the
live Binary opaque; replay rewrites response opaque to the live value. Cache
unmatched, unsupported, unsafe, and unused evidence is dirty and must fail the
same `end` and `finalize --fail-on-dirty --fail-on-incomplete` gates as HTTP and
MySQL evidence.

Kafka replay uses the standard client wire protocol with a constrained
one-broker, one-partition facade. Use the E2E Kafka profile documented by the
recorder; match Produce records by exact topic/key/headers/value and deliver
recorded Fetch data once. Kafka unmatched, unsupported, unsafe, and unused
records are dirty under the same case and aggregate gates. Do not substitute a
real broker or hand-written queue fixture when the selected case contains Kafka
semantic dependencies.

For collection replay, a passed result means the selected case set passed. Do
not collapse a collection into one representative case. Traffic observed while
no case is active, or while a different case is active, must not be silently
matched to the current case.

For JSON responses, compare parsed JSON values, not serialized bytes. Object
key order and pretty formatting do not matter. Field presence and value type do
matter: missing, `null`, and `""` are all different. Arrays are ordered unless
the product contract or explicit assertion config marks them unordered. Use
byte-level body comparison only for non-JSON bodies or explicit exact-byte
assertion mode.

Recorded dependencies are replay evidence. Do not turn them into the app's
normal runtime data source. For service rewrites, keep the production-like
dependency boundary real and point only the E2E environment at replay listeners.

## Dependency Replay

Default to no real external network, DB, cache, queue, or third-party calls.
Use traffic-recorder-proxy replay as the dependency boundary. If a required
dependency type cannot be replayed from recorded evidence, stop with recorder
feedback instead of hand-writing substitute mock data.

Treat every event in `dependencies.jsonl` as part of the initial touch audit.
The target implementation may use different code structure, but it must touch
equivalent external dependencies for the selected case. Equivalent means the
same dependency role and compatible operation, input shape, state effect,
recorded status, rows or affected rows, and error semantics where applicable.
Do not require mechanical source-code translation or byte-identical SQL
formatting, but do require dependency behavior evidence.

Recorded dependency params are not runtime configuration. Use them to identify
expected inputs, dynamic value patterns, schema, result shape, and replay
coverage, but do not hardcode them into product code or default runtime config.
Examples that must not become normal defaults include fixed business ids,
tenant ids, user ids, request ids, UUIDs, timestamps, elapsed durations, and
monthly table suffixes. If those values are needed only to make replay
deterministic, keep them in E2E-only config with names such as `fixed`,
`override`, `recorded`, or `replay`.

For dynamic recorded values, define the runtime strategy before declaring
success. Examples: current-month table suffix, request-start timestamp,
generated request id, system clock, current authenticated user, or ids derived
from database state. If the strategy is unknown, keep the case incomplete and
report the missing source of truth instead of pinning the recorded value.

Before relying on replay results, classify each recorded dependency:

- `response-driving`: data directly needed to produce the expected response
- `auth/session`: data needed to establish request identity or context
- `required-side-effect`: calls the app must make but whose output does not
  shape the response, such as request logs or audit writes
- `unrelated/background`: process-wide, scheduled, lock, heartbeat, or other
  traffic captured near the request but not owned by the case

Replay response-driving and auth/session dependencies first. Required side
effects must be replayed. If the target intentionally changes a side effect,
for example replacing a legacy DB request log with structured service logs, get
explicit user approval and record it as a behavior-contract change; do not
silently mark the replay as passed. Do not fold unrelated/background
dependencies into business logic or runtime data models. Classify traffic as
unrelated/background only with evidence such as bootstrap ownership, scheduler
ownership, startup timing, source-code ownership, or a replay report showing it
is not exercised by the selected request. If ownership is ambiguous, treat the
replay as incomplete and report a recorder-correlation improvement.

When a dependency touch cannot be traced to the selected request's source-code
path, do not invent a configuration knob that replays the recorded params. Mark
the dependency as unproven case ownership and return a concise
recorder-correlation or source-analysis blocker.

For MySQL:

- Use `mysql_exchange` records as the primary replay source.
- Treat `response.columns` as query-level schema evidence. Use semantic fields
  such as `family`, `sql_type`, `unsigned`, `bits`, and `nullable`; do not
  infer language types from raw protocol flags or protocol type names.
- Match by dependency identity first, then normalized SQL and parsed `params`.
  The MySQL dependency identity is the business/original `target_host`,
  `target_port`, default `database`/schema, and `username`. Do not use fake IPs
  or upstream IPs as the semantic identity. Identical SQL against a different
  business domain, shard, log database, tenant database, or user role is a
  mismatch.
- Return resultset columns and rows for `response.status == "resultset"`.
- Return affected rows and last insert id for `response.status == "ok"`.
- Reproduce error code and message for `response.status == "error"`.
- Preserve dependency order when transactions, locks, repeated SQL, or session
  state matter.
- Normalize dynamic params only when the dependency touch remains equivalent.
  Examples include current timestamps, request ids, UUIDs, elapsed durations,
  and generated ids that are linked across recorded calls. Do not skip a whole
  query or side effect because one parameter is dynamic.
- Treat missing SQL, missing params for prepared execution, missing semantic
  column schema, row truncation, and parse warnings as risk signals.

## Dependency Coverage

Use `dependencies-summary.json` as an acceptance checklist when the case has
one. A target replay should produce a matching replay summary or equivalent test
evidence for:

- response-driving dependency calls
- auth/session dependency calls
- required side effects, including recorded dependency failures that the source
  behavior tolerated
- protocol, CRUD operation, table/host/topic/key-pattern, response status, row
  count, affected rows, and error code/message where applicable
- MySQL business target host, database/schema, and username for every matched
  exchange where those fields are recorded

Do not mark the E2E as passed when replay output contains unexplained
`unmatched` target dependency calls, `unused_case_exchanges`, or equivalent
unused recorded case dependencies. An unused case exchange may mean the target
omitted logic. It can be ignored only after evidence proves it is unrelated
background traffic, or after the user approves a behavior change. If the summary
shows a dependency category that the target test never exercises and it is not
safe to classify it as unrelated, treat the replay as incomplete.

For non-MySQL dependencies:

- Apply the same evidence-first policy: identify the dependency call, expected
  input, recorded output, and ordering or state requirements.
- If semantic data is absent, inspect debug records or project logs only to
  explain what is missing.
- Do not synthesize Redis values, MQ messages, downstream HTTP payloads, or
  cache entries. Treat missing semantic replay support as recorder/replay
  feedback.

## Metrics Dependency Validation

Metrics dependencies are validated by replay or focused exporter checks, not by
target-project mocks. A passing HTTP response is not sufficient when a case
records metrics dependencies or the selected source capability is known to emit
metrics.

Classify metrics by delivery model:

- push metrics are outbound side effects. Replay should validate that the
  target service emits equivalent metric events during the active case window.
  Compare stable semantic fields such as metric name/path, value, tags or
  labels, target identity, and delivery status. Do not byte-compare generated
  timestamps by default; require presence and case-window membership unless the
  timestamp is a business value.
- pull metrics are exported service state. Verify that the target service
  starts the configured exporter or scrape endpoint and that the selected
  request/job updates the expected metric family. Use stable label dimensions
  and avoid adding ignores unless the user approves them.

If recorded metrics evidence is missing, incomplete, or unsupported by replay,
do not invent metric payloads in the target project. Report the missing metrics
evidence as recorder/replay feedback. If metrics are intentionally dropped or
replaced with another telemetry contract, require explicit user approval and
record the behavior-contract change.

## Assertion And Config Fallback

Prefer the target project's existing assertion configuration. If none exists and
the case needs configurable assertion behavior, create `.recorded-e2e.yaml` at
the target project root.

The fallback config is YAML, per case, and limited to assertion behavior plus
external dependency isolation. Use JSONPath selectors for response body ignore
paths. Keep it small; do not use it for broad test orchestration or dependency
payload data.

Use the same source-controlled file as the single replay/assertion policy for
every target orchestration and test layer. The shell facade may pass its path to
the target-language E2E runner, but must not maintain a second copy of case ids,
dependency signatures, or background/noise exceptions. If the target already
has a suitable policy file, reuse it instead of adding `.recorded-e2e.yaml`.
When an evidence-backed dependency exception is necessary, identify it by the
smallest exact case and dependency signature and record the rationale there;
do not turn it into a broad route or process-wide allowlist.

Minimum supported concepts:

- case key: `recordings/<run-id>/<rule>/<uri-group>/<case-id>`
- optional case collection key: `recordings/<run-id>/<rule>/<uri-group>` or
  `recordings/<run-id>` plus a selected case id after matching
  `request.json.uri`
- body assertion mode: strict JSON, exact bytes, semantic fields, or status-only
- ignored response JSONPaths
- ignored or asserted headers
- external dependency isolation flag

Never add ignore JSONPaths automatically. When a mismatch appears unstable,
suggest the JSONPath and wait for explicit user authorization before editing the
config.

## Run Loop

Use at most 3 iterations:

1. Run the focused single-case or selected case-set E2E command.
2. If it fails, classify the failure as incomplete recording, replay routing
   miss, unsupported replay behavior, assertion drift, environment setup, or
   product code bug.
3. Fix replay readiness, lifecycle, command options, target dependency routing,
   or recorder/replay evidence first.
4. Fix product code only when dependency replay is complete and the failure is a
   real behavior defect.
5. Re-run the focused command after each change.
6. Before finishing, note whether replay exposed recorder data quality gaps,
   even if the case now passes.

After the focused case passes, run the broader relevant suite or project-standard
checks that are reasonable for the repository.

When dependency files contain both relevant business calls and unrelated
process-wide traffic, include a short working-note summary of which dependency
classes were replayed, explained, or ignored. Surface recorder feedback if
better dependency attribution, role tagging, or noise filtering would have
reduced manual triage.

If replay passes the HTTP assertion but leaves case dependencies unused, report
the result as partial: response passed, dependency touch incomplete. Include the
unmatched/unused dependency list and do not finish as success.

## Final Response

Start with `complete`, `incomplete`, or `blocked`. On success, keep the final
response short:

- selected recorded case set pass/fail conclusion
- final replay report path and session id
- aggregate status, path, and published/reported/unreported counts
- case-path-pattern plan status and path
- essential changes
- verification command
- concise recorder feedback when replay required guessing, debug-only data, or
  manual reconstruction that better recording could avoid

On blocked replay, include the missing evidence list and recommended next step,
such as re-recording with a dependency enabled or providing a fixture source.
