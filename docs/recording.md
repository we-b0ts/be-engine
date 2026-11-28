# Standalone Source recording

`traffic-e2e record` is the single standalone Source recording service.
It starts a co-located Source as UID/GID 998, starts Recorder, and optionally registers a
reachable HTTP address in coordination Redis for the ready Source. Optional `--config PATH` / `TRAFFIC_E2E_PROJECT_CONFIG`
reuses the Recorder section of `.traffic-e2e/project.yaml` and the single
`project.policy` reference, normally `.traffic-e2e/policy.yaml`.
The app does not inspect Git or start the rewrite coordinator. Ingress selects API traffic. Recorder preserves the configured HTTP include/exclude
rules; their default permits all methods and paths.

Declare the business protocols independently for incoming API requests and
outgoing dependencies. An HTTP API that calls HTTP or HTTPS services can use:

```yaml
recorder:
  capture:
    ingress: [http]
    dependencies: [http]
  dns_mock:
    upstream_dns: 10.10.10.11:53
  http_gateway:
    matched_upstream: http://127.0.0.1:8080
    ready:
      enabled: true
      path: /health
```

`capture.ingress: [http]` enables the primary HTTP gateway.
`capture.dependencies: [http]` enables fake DNS, the transparent TCP gateway,
HTTP dependency parsing and HTTPS MITM. HTTP depends on TCP transport, so an
HTTP-only business integration still needs that internal gateway. The two roles
do not enable each other: an HTTP entry point does not imply HTTP dependencies,
and an outgoing HTTP call does not create an HTTP entry point. In this example,
UDP, the Motan entry gateway and the dedicated MySQL proxy remain disabled.

These declarations select required recording facilities; they are not a traffic
allowlist. Protocol detection still observes incidental native dependencies so
unexpected traffic is retained for analysis. Keep business include/exclude
rules, readiness and timeout settings for the project. Session recording
forwards HTTP responses incrementally and captures their ordered parts.
[Source session regression](session-regression.md)

Transport settings remain optional overrides when a project needs a different
listener, upstream DNS server, CA location or artifact directory. A declaration
that requires HTTP dependency capture conflicts with an explicit
`tcp_gateway.enabled: false`, `record_http: false` or `mitm_https: false`;
configuration loading reports the conflict instead of silently changing it.
The default artifact directory is `.traffic-e2e/local/artifacts`, with the fake
DNS registry under that directory. Serialization keeps the protocol declarations
and differing overrides without expanding derived infrastructure defaults.
Documents without `capture` retain their explicit transport behavior. This
translation happens when configuration is loaded; Replay request processing and
dependency matching use the same effective runtime settings.

Normal SIGTERM/SIGINT shutdown closes ingress, withdraws discovery and gives
admitted requests up to 15 seconds to finish. The recorder records a
`primary_cancel` event with reason `engine_shutdown` for remaining requests,
then stops Source and seals the recording. An actual capture failure leaves
incomplete evidence for diagnosis.

<details>
<summary>Historical Case recording shutdown and tail policies</summary>

These notes describe the Case recorder and earlier capture profiles.

Normal SIGTERM/SIGINT shutdown first withdraws discovery and closes admission of
new cases. Source, Recorder and admitted sessions remain alive for up to **60
seconds**, waiting for primary requests, dependency tails and case publication.
Existing Socket.IO polling follow-ups may finish their admitted session. Stream
idle windows, absolute request deadlines and dependency persistence budgets
continue to apply; a failure requiring Source isolation ends the wait early.
After this wait, the supervisor stops Source and then closes retained dependency
connections as engine cleanup before finalizing the recording.

The run manifest distinguishes external SIGTERM/SIGINT (`shutdown_signal`) from
an internal safety stop (`source_isolation_required`). Source isolation handles
actual dependency capture failures and transport cleanup; waiting for an
uncovered async end does not request isolation. It does not imply that the
operator stopped the container.

If an uncommitted case is still incomplete after 60 seconds, it fails with
`shutdown_case_drain_timeout`. An earlier independent case failure is preserved.
The supervisor writes `recording-shutdown.json` before stopping Source, retaining
the shutdown trigger, elapsed time, outcome and affected case identities. This
also distinguishes case truncation from a subsequent dependency drain error.
Cases already inside their publication commit barrier finish that transaction.
The 60-second limit bounds the normal case wait; process termination and evidence
cleanup follow their existing separate budgets. Low-level Recorder shutdown uses
`recording.shutdown_case_drain_timeout_ms` for its own final drain.

The first admission-close or isolation boundary freezes the sole running Case,
if present. Requests already admitted to that Case retain their original owner;
new requests while its dependency window remains open also belong to the Case.
After that window closes, otherwise unowned teardown requests use a separate
`shutdown` owner with the frozen `origin_case_id`. They are stored once in the
central ledger and referenced by
`indexes/shutdown-scope.json`, independently of the primary Case's result.
Declared process-task ownership and ambiguous selector failures retain priority.

If no Case was running at the first shutdown boundary, teardown requests remain
unattributed (`shutdown_without_running_case`) and still require analysis. A
previously completed Case or a reserved but unstarted input cannot supply the
association later. Associated shutdown evidence does not request repository
analysis, repair a failed Case, supply primary Replay responses, or certify a
WholeSource pass; its unexecuted mandatory dependencies remain visible separately.

Returning the primary response does not end Case ownership while asynchronous
API or stream-tail policies still await their declared completion. This remains
ordinary Case traffic, including during shutdown's Case drain. Runtime traffic
between fully ended Cases remains unattributed; it cannot borrow a later Case or
acquire shutdown association merely because its response arrives after shutdown.
The shutdown association is frozen before awaiting manifest persistence or
notifying failed asynchronous completion, so publication cannot release the last
failed Case before that association is established.

For recognized Python ASGI Socket.IO peers, the recorder also retains a native
live-SID proof from the first observed WebSocket packet. A Source-initiated close
is forwarded promptly and its close echo is flushed, but the original Case stays
open until that exact SID confirms application disconnect completion. Redis or
MySQL calls awaited by `on_disconnect` therefore remain Case dependencies even
when they start after the WebSocket close. The existing cleanup budget still
applies; unknown SIDs, unrelated errors and unconfirmed completion cannot publish
a successful capture.

Every clean Socket.IO connection closure keeps its original Case open for at
least 15 seconds from the close, even when no protocol events are pending.
An admitted business dependency in flight at close or observed during that
window switches the Case to 60 seconds of rolling silence. Heartbeats and
known process traffic do not extend it. At five minutes the recorder closes
admission and the supervisor stops Source before sealing the batch. If
business I/O is still in flight, the last Case is archived as incomplete.
The manifest records `socketio_close_tail_limit`. Previously published Cases
remain usable after successful run finalization.

Socket.IO ACK identities are released when their matching ACK is observed,
independently of pending business completion. Reusing an acknowledged ID while
the earlier business request awaits its terminal event is valid; reuse before
ACK remains a transport failure. Diagnostics retain a bounded error kind and
numeric ACK ID without recording packet payloads in logs.

HTTP request waits and HTTP streaming duration share
`recorder.http_gateway.request_timeout_ms`, default 900000 ms (900 seconds).
`--request-timeout-seconds` overrides the same budget for both. Ordinary HTTP
timeouts retain their case while Source gets the configured
`recording.case_dependency_drain_timeout_ms` recovery budget to finish. If it
cannot finish within that budget, admission closure wakes the supervisor to stop
Source and finalize the failed recording. Source exit is confirmed before the
supervisor closes any remaining dependency connections as engine-owned cleanup.
This HTTP transport budget does not limit asynchronous end observation after a
complete primary response. Such observation uses the end/probe and business-idle
boundaries below, or is explicitly interrupted.

</details>

HTTP include and exclude rules support `paths` for exact, case-sensitive URI
path matching. Query strings are ignored when matching requests and must not
appear in configured paths. `/api/jobs` does not match `/api/jobs/` or
`/api/jobs/42`. Existing `path_prefixes` retain their subtree behavior. All
nonempty filters on one rule must match, including both `paths` and
`path_prefixes` when both are present. Exclusions take priority and use the
configured fallback without recording a case or forwarding to Source:

```yaml
recorder:
  http_gateway:
    exclude_rules:
    - name: skip-job-list
      methods: [GET]
      paths: [/api/jobs]
```

Standalone recording loads the recorder projection of `traffic-policy/v3`
from `--policy PATH` / `TRAFFIC_E2E_POLICY` or the configured `project.policy`.
With `--config`, an explicit `--policy` must name that same file. HTTP gateway
include/exclude rules select ingress and the Source event timeline preserves
background dependencies across responses.

<details>
<summary>Historical Case policy and lifecycle examples</summary>

These examples describe Case capture and its original policy contracts.

An API that returns before its work finishes can retain the ordinary Case with
`recording.async_api` in the same policy:

```yaml
recording:
  async_api:
    POST /api/v1/responses:
      - when_response: {/status: queued}
        end:
          - http:
              method: POST
              endpoint: executor.example.com:80
              path: /submit
      - when: {/background: true}
        when_response: {/status: in_progress}
        end:
          - mysql:
              sql: "UPDATE jobs SET status = 'completed' WHERE id = ?"
          - redis: {operation: DEL, key: 'job:finished:*'}
```

`recording.async_api` and `recording.case_paths` are independent optional fields.
Canonical output places `async_api` before `case_paths`. The old root `async_api`
remains readable, but declaring both locations is rejected, even for empty maps.
Both spellings compile to the same rule identity and fingerprints; moving the
declaration alone does not change capture behavior or invalidate evidence.

These are illustrative ending conditions. After ownership analysis, choose the
last business request templates from the complete effective Case, including
newly attributed tail traffic, and check their Source path and earlier matches.
An initialization access that uses the same key or SQL cannot alone identify
the final occurrence. MySQL matches the full SQL structure and fixed
literals, ignoring whitespace and keyword case. Each `?` matches one scalar;
prepared parameters are decoded before matching. Redis matches the operation
and physical key, with at most one `*`. An optional `occurrence: 2` waits for the
second successful access to the same physical key, database and endpoint when
Source uses the same operation during initialization and final cleanup. Distinct
keys and mirrored evidence cannot be combined to reach that count.
Redis `when_response: {kind: nil}` additionally requires a native Redis null
reply; omitted or `{kind: any}` accepts any complete successful reply. A string
containing `null`, an empty string and missing capture are not native nil.
Occurrence counts include only exchanges satisfying all request/reply conditions
and start at Case admission, not at the beginning of an observed tail. For example:

```yaml
end:
  - redis: {operation: DEL, occurrence: 2, key: 'chat:cancel:*'}
  - redis:
      operation: GET
      key: 'channel:task_callback:telegram:*'
      when_response: {kind: nil}
```

If Source already publishes a terminal JSON message, match its channel and
message fields instead of treating a pub/sub channel as a Redis key:

```yaml
end:
  - redis:
      operation: PUBLISH
      channel: socketio
      when_message: {/method: emit, /event: 'chat:start', /namespace: /chat}
```

Choose the event belonging to the selected Source ending path. PUBLISH ends
require an exact channel, all literal JSON-pointer conditions, complete request
and response captures, and a successful native integer reply; zero subscribers
is still a successful publication. Other messages on that channel do not end
the Case. `when_message` inspects the publication's request JSON, whereas
`when_response` inspects the native reply; PUBLISH accepts only `any` because
a successful publication always returns an integer.

The `end` list contains alternatives: a partial match can enter `ending` without
requiring all ends. Once every end in the selected scenario has matched, Recorder
closes new dependency admission immediately and drains admitted requests, with no
silence interval. A scenario with one end follows this same rule. Match state
respects each end's occurrence requirement and any transaction commit boundary.

While some ends remain unmatched, each fresh end match keeps admission open for
a fixed one-second probe. If another relevant request
starts, the Case must wait for a fresh end match before another probe can permit
closure. Subsequent silence alone never restores that permission. For example,
after the second DEL, a new SQL request cancels the probe; two seconds of silence
after that SQL do not close the Case. A later matching GET can start a new probe.
The same recorded exchange cannot repeatedly grant probes.

A successful probe closes admission only when no relevant requests remain in
flight. Writer queues and unambiguously process-owned requests do not cancel the
probe; unknown ownership cannot be assumed to be process traffic. Closing admission
and checking request starts are atomic. Already admitted I/O and evidence still
drain without losing their original ownership. Later traffic remains available
to independent attribution analysis.

Both observation durations are fixed engine behavior, not policy fields. After
the complete primary response, waiting for the first or next end has no absolute
deadline. If no fresh end arrives, five continuous minutes without relevant
business I/O and with no relevant request in flight close the Case normally.
Each real business activity restarts this idle interval. Writer queues and
unambiguously process-owned traffic do not. The interval cannot start before the
primary response completes. This fallback records that business completion was
not observed, retaining the traffic for rule analysis without stopping Source or
marking a timeout failure. The primary HTTP transport timeout remains separate;
explicit shutdown or actual capture failure can interrupt observation.

A fresh end restores the one-second probe, or closes immediately if it satisfies
the last unmatched end. Merely knowing that additional end alternatives exist
does not extend the probe. Only an actual subsequent request
start switches back to waiting for a fresh end or the five-minute idle fallback.
A completed probe is a capture boundary, not proof that a detached worker
can never issue another request. Do not select an early polling request whose
normal idle gap outlasts the probe; use a later condition for that Source path.

Optional database and endpoint selectors
restrict the physical resource; omitted database selectors match any Source
database. Source and Target still use the same physical connection identity.

Each API accepts an ordered scenario array. `when` matches literal Source request
JSON fields; `when_response` matches literal fields in the complete Source
response JSON. All fields in each condition must match. Optional
`unless_response` excludes a scenario when all its fields match; for example,
`unless_response: {/is_latest: true}` excludes a distinct response variant.
Missing fields differ from JSON null, and strings are not coerced into booleans.
The first scenario satisfying both request and response conditions selects the
lifecycle. Completion resources and occurrence counts are isolated by scenario.
The legacy single-scenario mapping remains accepted. Target response content
never selects an asynchronous lifecycle.

HTTP ends require a complete successful dependency exchange for the declared
method, physical endpoint and exact path; query parameters do not affect path
selection. The default accepts any 2xx status; optional `status_codes: [200, 202]`
restricts successful statuses. A connection or request send alone cannot prove
completion. A submission end covers the acknowledged handoff, not subsequent
work: a later executor callback is a separate inbound HTTP request. Choose
conditions that identify the actual submission branch; `queued` alone is not a
universal executor mode indicator.

Dependencies remain in the ordinary Case after the primary response is sent.
A successful declared end starts ending as described above. Waiting for either
the first end or another end has no absolute deadline after the complete primary
response. Complete business errors remain real retry/cleanup observations; incomplete dependency
capture retains its failure handling. There is no policy timeout or failure toggle.
Known process-owned traffic does not end or become part of the Case. A terminal
access observed before the primary response finishes is retained without
truncating that response. When response conditions select a scenario, its early
events are retained from case admission; an HTTP dependency may finish before,
after, or across the primary response. If no scenario matches, ordinary capture
and dependency drain apply without an asynchronous wait.

Optional `CLIENT SETINFO LIB-NAME` / `LIB-VER` exchanges use the same precise SDK
metadata exemption as semantic dependency recording. An unsupported metadata
reply cannot finish asynchronous business observation or request Source
isolation. Required setup failures (`AUTH`, `SELECT`, `HELLO`), incomplete or
unsafe exchanges retain their capture failure behavior. Complete business-command
errors do not satisfy a successful end condition.

`async-api-observation.json` records `end_reason` as `resource`, `idle`,
`dependency_failure`, or `stopped`, together with the zero-based selected
`scenario_index`. `stopped` records an explicit shutdown or independently observed
Source exit; it does not turn an uncovered end into a failure or a timer into a
successful completion. Historical `timeout` observations remain readable.
Actual capture failure and external stopping retain their supervision behavior.
Admitted I/O retains its original ownership until the real termination and queued
evidence have drained. Resource/probe and business-idle boundaries save an
ordinary Case normally. Explicit shutdown retains its existing drain limits and
incomplete-Case diagnostics; capture corruption or incomplete primary HTTP
traffic retains its existing failure behavior.
Partial-match ending metadata records a completed probe separately from business
completion, preserving the observed candidate and finite dependency inventory.
An `idle` boundary instead records `idle_completion: {quiet_ms: 300000}` and
`business_completion: unobserved`, with no fabricated end match or completed
probe. It is a normal recording boundary that keeps Source running.
If another request cancels the probe and no fresh end arrives, observation waits
for the five-minute business-idle fallback. A missing rule must not produce an
automatic timeout or stop Source.
A timer alone does not prove business completion.

The observation stores the precise Source-stop offset and exact `cleanup_refs`
for admitted requests still unfinished at that boundary. Original outcomes,
errors and partial bytes remain in the semantic trace. Replay retains those
requests through an engine-controlled Target stop and consumes them only after
real Target transport termination. It does not turn Recorder cleanup into a
business response, fabricate a proxy 502, or waive unstarted ordinary resources.
Captured HTTP prefixes may reuse global formats for complete JSON/SSE values;
partial or unknown bytes stay exact, and no unobserved response EOF is added.
Capture limits and prefixes that were not flushed remain capture failures.
Replay still validates the finite recorded inventory with its configured
execution budgets; unbounded Source end observation does not remove Replay's
failure detection or execution limits.

An upstream TCP connection failure retains a semantic
`dependency_connect_failure` observation with its physical endpoint, known
protocol, duration and the connection reset actually delivered to Source.
Replay consumes that finite observation through a real Target connection and
reproduces its termination. Parser, capture-storage and protocol-corruption
errors remain recording failures; a connection-failure case does not waive them.
For an endpoint with both successful exchanges and a failed connection, Replay
first requires consumption of the completed Source predecessors. Overlapping
successful and failed connections without provable physical ownership are
rejected explicitly rather than resetting an arbitrary Target connection.

Replay keeps the Case active after the HTTP response until Target has consumed
the complete finite dependency inventory. Recorded dependency failures replay
as the same failure; completion does not permit a different Target error or
missing accesses. Older published cases without the observation artifact can
reuse their immutable inventory only when it proves a configured terminal
resource or an observed dependency failure. An unproven end requires a complete
recording rather than granting an asynchronous exemption.

Recorder accumulates observed method/path identities only after successful case
publication. At recording finalization, `recording-run.json` adds `api_methods`,
mapping each recorded HTTP path or pattern to its sorted, unique method list.
For example: `{"/api/teams":["GET","OPTIONS"],"/api/users":["POST"]}`.
This optional display metadata is fixed with the recording. Historical recordings
without it retain an empty method set; readers never scan or rewrite old cases
to populate it. It does not change Replay selection or verification gates.

</details>

Build the normal engine binary with the published `brz-http-gateway` and
`brz-redis` versions pinned in the workspace. The Recorder enables the gateway
SDK's Redis admission and route validation features. Gateway services executing
global reservations by digest require a Recorder that preloads the script.

```bash
cargo build --locked --release --bin traffic-e2e
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The supervised timeout regressions also launch a real fixed-identity Source
without installing interception rules. Run them on a host with Python 3 and root
or passwordless sudo:

```bash
cargo test --lib record_service::tests::quiescing -- --ignored --test-threads=1
cargo test --lib record_service::tests::shutdown -- --ignored --test-threads=1
```

Verify the Recorder against the full Breeze gateway's Socket.IO transport with
the opt-in SDK test. Ordinary engine builds use the admission SDK alone.

```bash
cargo test -p traffic-engine-recording --features gateway-integration-tests,tokio/test-util \
  external_sdk_socketio_large_fragmented_ack
```

Run in an isolated container network namespace, with a root controller and
`NET_ADMIN`/`NET_RAW` for fixed-identity dependency interception. The recording
container's Source must use the same business configuration as the original
service. Example environment and command (provide the Redis URL securely):

```bash
export TRAFFIC_E2E_RECORD_URL=http://recorder-host:4080
export TRAFFIC_E2E_RECORDING_PREFIX=recording:orders
export TRAFFIC_E2E_RECORDING_REDIS_URL=redis://redis-host:6379/0
traffic-e2e record --coordination redis --max-inflight-requests 8 --source-workdir /app --ready-path /health \
  -- python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

Default flow is gateway → public adapter `:4080` → Recorder `127.0.0.1:4081` →
Source `127.0.0.1:8080`. Recorder and Source listeners must use different
loopback ports. With Redis coordination, `--advertise-url` / `TRAFFIC_E2E_RECORD_URL` is required and
must be the HTTP origin reachable by gateways, including any Docker port mapping.

### Gateway API policy at startup

In Redis coordination mode, `--api-policy PATH` / `TRAFFIC_E2E_API_POLICY` reads
a gateway JSON policy before Source startup. Mount the file read-only in the
recording container. For example, `api-policy.json` can select two API paths,
each with the same admission limit:

```json
{
  "case-limit": 200,
  "includes": [
    { "path": "/api/users", "match": "exact" },
    { "path": "/api/teams/:id/skills", "match": "exact" }
  ],
  "excludes": [{ "path": "/internal", "match": "prefix" }]
}
```

```bash
traffic-e2e record --coordination redis --api-policy /etc/traffic-e2e/api-policy.json \
  --source-workdir /app --ready-path /health \
  -- python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

Use the same Redis and advertised-address environment as above. After readiness,
before opening admission and registering its address, Recorder writes the policy
to `<prefix>:api-policy` and executes `DEL <prefix>:api-counts` once. Every Redis
recording startup resets counts. When `--api-policy` is omitted, Recorder writes
`{"includes":[],"excludes":[]}` to restore all paths without a gateway limit,
replacing any previous round's selection or cap. Finish the previous
round before starting another Recorder with the same prefix. Publication or reset
failure fails startup. Heartbeats and address re-registration never rewrite the
policy or reset counts. Shutdown removes only the owned address; policy and counts
remain until the next round or an explicit operator update.

The gateway applies `excludes` first. Missing or empty `includes` permits every
path; missing or empty `excludes` excludes none. `prefix` is the default and matches whole path segments. `exact` supports
`:id` and terminal `*rest` templates; query parameters do not participate. Exact
templates share a counter across concrete paths; prefix-only matches count each
actual path separately. All HTTP methods share the path's limit. `case-limit`
is optional and bounded by Redis's signed integer range; zero pauses admission,
and omission means no limit. A missing policy key also means all paths without
a limit. Invalid files fail before Source starts. Gateways load the policy at
startup and refresh it periodically (about 10 seconds with default leases).

This JSON controls gateway admission only. It neither changes Recorder capture
rules and case grouping nor overrides local `--case-limit` / project limits.
Recorder may return 404 for a filtered or locally exhausted API; the gateway
retains its existing fallback behavior. Gateway counters measure acquired
admissions, not successfully published cases, and limits remain approximate.
There is no per-API override map or automatic shutdown when gateway counts reach
the limit. Direct recording does not use this option or contact Redis.

The standalone service uses the configured HTTP include/exclude rules, body
limits and required dependency recorders. Its concurrency setting applies across
admitted ingress, including open streams. `--max-inflight-requests` overrides
`recorder.recording.max_inflight_requests` (default 8). Source runs until the
controller receives SIGTERM/SIGINT or a recording failure stops the run.

| Parameter / environment | Default | Purpose |
| --- | --- | --- |
| `--coordination` / `TRAFFIC_E2E_RECORDING_COORDINATION` | unset | Optional `redis` discovery and reservation coordination |
| `--run-id` | generated UTC ID | One immutable recording run per process |
| `--config` / `TRAFFIC_E2E_PROJECT_CONFIG` | unset | Read-only project YAML; reuses Recorder configuration and policy, without target or rewrite orchestration |
| `--listen` / `TRAFFIC_E2E_RECORD_LISTEN` | `0.0.0.0:4080` | Public adapter |
| `--recorder-listen` / `TRAFFIC_E2E_RECORDER_LISTEN` | `127.0.0.1:4081` | Internal Recorder |
| `--source-origin` / `TRAFFIC_E2E_SOURCE_ORIGIN` | `http://127.0.0.1:8080` | Source origin |
| `--ready-path` / `TRAFFIC_E2E_SOURCE_READY_PATH` | project value or `/` | Override Source readiness path |
| `--redis-url` / `TRAFFIC_E2E_RECORDING_REDIS_URL` | required with Redis coordination | Coordination Redis; supports password/default user and DB |
| `--prefix` / `TRAFFIC_E2E_RECORDING_PREFIX` | `recording` | Shared coordination prefix |
| `--max-inflight-requests` / `TRAFFIC_E2E_RECORDING_MAX_INFLIGHT_REQUESTS` | `recorder.recording.max_inflight_requests` or `8` | Maximum concurrent ingress requests across the recording, including open streams |
| `--url-key` / `TRAFFIC_E2E_RECORDING_URL_KEY` | `<prefix>:url` | Address lease key |
| `--data-root` / `TRAFFIC_E2E_DATA_ROOT` | `/data/traffic-e2e` | Persistent evidence, encryption key and CA |
| `--artifact-owner` / `TRAFFIC_E2E_ARTIFACT_OWNER` | invoking controller owner | Numeric host UID:GID for private storage and finalized runs; explicit values require root |
| `--source-workdir` / `TRAFFIC_E2E_SOURCE_WORKDIR` | `/app` | Source working directory |
| `--policy` / `TRAFFIC_E2E_POLICY` | unset | Unified policy for standalone recording; with `--config`, must name `project.policy` |
| `--api-policy` / `TRAFFIC_E2E_API_POLICY` | all paths, no gateway limit | Redis-only gateway JSON policy; publish once at startup, independently of Recorder rules and limits |
| `--startup-timeout-seconds` | `300` | Startup/readiness deadline |
| `--request-timeout-seconds` | project value or `30` seconds | Override request forwarding/response deadline |
| `--dns-upstream` / `TRAFFIC_E2E_DNS_UPSTREAM` | project value or first system resolver | Override real DNS upstream before fake-IP projection |

An invalid explicit project configuration fails before Source startup. Mount the
project YAML read-only alongside its policy and restart after edits.

Keep project configuration and policy outside the image and bind-mount them
read-only. Preserve the `.traffic-e2e` directory and repository-relative path
inside the mount; keep the real Source work directory and business configuration
unchanged:

```bash
--mount "type=bind,src=$PWD/.traffic-e2e/policy.yaml,dst=/etc/traffic-e2e/.traffic-e2e/policy.yaml,readonly" \
--mount "type=bind,src=$PWD/.traffic-e2e/project.yaml,dst=/etc/traffic-e2e/.traffic-e2e/project.yaml,readonly" \
--env TRAFFIC_E2E_PROJECT_CONFIG=/etc/traffic-e2e/.traffic-e2e/project.yaml
```

The mounted project contains `project.policy: .traffic-e2e/policy.yaml`. For a
deployment without project YAML, mount the policy and supply
`--policy /etc/traffic-e2e/.traffic-e2e/policy.yaml`. API route labels come from
the Target catalog during regression. `--no-interception` supports local
adapter tests.

## Direct standby and run identity

Without `--coordination`, the service waits for direct HTTP requests after Source
readiness. It never connects to Redis and requests need no reservation headers.
The same ingress concurrency, body limits, recording rules and finalization apply. Source's business `REDIS_URL` does not enable recording coordination.

```bash
traffic-e2e record --data-root /data/traffic-e2e --source-workdir /app \
  -- python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Each process creates one run. `--run-id YYYYMMDDHHMMSS` is optional; the default
uses UTC and atomically retries directory collisions. An explicit existing ID
fails without overwriting its evidence. Ready logs include run ID and manifest
path. SIGTERM/SIGINT withdraws admission, drains requests and finalizes the run;
only completed runs are suitable for rewrite. Failed capture returns a nonzero
exit status. There is no separate start command; `--api-policy` only configures
gateway ingress selection in Redis mode.

The project owns its `.traffic-e2e/Dockerfile.recording`, using the example in
[`docker/record/Dockerfile.example`](../docker/record/Dockerfile.example).
Build and container lifecycle belong to the deployment caller. The controller
runs as root for interception and launches Source as 998:998; pass exit signals
to the controller. Persist the entire data root, including private keys.
Use a published engine image as a build stage and copy
`/usr/local/bin/traffic-e2e` into the Source image. For Kubernetes recording,
copy `/usr/local/bin/kubectl` from its separate versioned distribution image.
See the
[engine image build and publication](development.md#engine-binary-image)
instructions; project recording builds do not compile the engine or need SSH.
The [kubectl image builder](development.md#kubectl-distribution-image) accepts an
existing static Linux/amd64 executable, independently of the engine runtime.
Supply controller-private credentials through read-only runtime mounts or an
explicitly packaged project recording image using a private build context.
Configure [Kubernetes dependency recording](kubernetes-recording.md)
to discover Service TCP ports and prepare supervised forwards before Source starts.

Project Dockerfiles have separate roles:

| File under `.traffic-e2e/` | Role |
| --- | --- |
| `Dockerfile.recording` | Standalone Source/Recorder service running `traffic-e2e record`; owned by the deployment caller. |
| `Dockerfile.source` | Source adaptor used by diagnostic preflight; scaffolded during project initialization. |
| `Dockerfile.target` | Target application used by Replay and diagnostic preflight; scaffolded during project initialization. |

For existing projects, rename the managed Source adaptor from
`Dockerfile.recording` to `Dockerfile.source` before giving the standalone
recording image the `Dockerfile.recording` name. Rename `Dockerfile.e2e` to
`Dockerfile.target` and update `project.target.dockerfile` accordingly.

## Redis lifecycle

The external operator sets `<prefix>:max-gateways` to the participation limit N.
The app does not own that configuration or gateway leases. Gateway and app must
use the same Redis writer/database, prefix and URL key.

The app loads the global reservation Lua script with `SCRIPT LOAD` before
publishing `<prefix>:url` using `SET NX PX 30000`:

```json
{"url":"http://recorder-host:4080","owner":"<32 hex boot token>","max_inflight":8}
```

The global recording gateway reads the request limit from this value. Every
10 seconds the app renews the lease only if its complete value still
matches. A live second recorder cannot overwrite it. On shutdown the app deletes
only its own value; after a crash TTL expiry allows a replacement to register.
After a successful address renewal, the app checks the script cache with
`SCRIPT EXISTS` and reloads an absent script. Request reservation operations use
`EVALSHA`. The gateway uses its ordinary admission fallback if Redis reports a
missing script.
After readiness, the first address refresh runs immediately and later refreshes
run every 10 seconds. A missing registration is recreated with `SET NX`, without
overwriting another owner. Initial registration failure, renewal errors, expiry
and replacement never stop HTTP admission, Recorder, Source or an active request.
The service logs discovery failures and retries on the next refresh; the existing
200 ms Redis operation timeout remains unchanged. Gateways use their fallback
when discovery is unavailable. Request reservation checks and renewal retain
their independent ownership rules below.
On normal or recoverable error shutdown, token-checked unregistration is
best-effort. Failed unregistration and uncatchable exits rely on address TTL.

`<prefix>:inflight` is a sorted set shared by every gateway using that prefix.
Each token is a member scored by its expiration in Redis server time, in Unix
milliseconds. The gateway removes expired members and reserves a free slot in
one operation. At capacity it uses the normal fallback.

The adapter verifies the `x-breeze-admission-token` reservation and strips the
header before dispatch. Its local semaphore uses the same limit. The lease and
local slot stay active through the response stream. Completion or disconnect
releases that token. Expiry recovers reservations after a crash. The core
Recorder owns no Redis logic or gateway identity.

Shutdown withdraws the address, stops new adapter connections, stops Source,
drains active requests and disconnect dependencies, finalizes Recorder, then
removes interception rules.
Evidence lives under
`<data-root>/.traffic-e2e/local/artifacts/recordings/<run-id>/`. Only request
headers explicitly listed in `recorder.recording.encrypt_request_headers` are
encrypted, including headers on WebSocket upgrade actions. Other headers, URIs,
bodies and interaction messages are stored without additional encryption;
binary values retain their protocol's explicit Base64 encoding. Historical
encrypted interactions remain readable. Configured header encryption uses a persistent key in
`<data-root>/.traffic-e2e/local/secrets/traffic-e2e-enc.sec`. Persist the entire
data root across restarts. Source cannot read private evidence, the encryption
key, or CA private key.

Recorder state follows the managed project's local layout beneath `<data-root>`:
the fake DNS registry is `.traffic-e2e/local/artifacts/fake_dns_registry.json`,
and the recording CA pair is `.traffic-e2e/local/data/traffic-recorder-ca.pem`
and `traffic-recorder-ca-key.pem`. Existing files are loaded; an absent registry
or CA pair is initialized by the engine. A partially missing or invalid CA pair
fails startup. To reuse host project state, mount its `local/data`,
`local/artifacts` and `local/secrets` directories at these container locations.
Temporary Source trust and control files live in the container's `runtime/`
directory and are removed on normal shutdown.

Replay reads the sealed dependency inventory and `recording-network.json`,
creates its own DNS mapping and uses a Replay-session CA. It does not
read the recording fake DNS registry or require the recording CA private key.
Sharing Recorder state keeps subsequent recordings consistent; it is not a
prerequisite for Replay.

For a host bind mount, pass the invoking host user's numeric UID:GID as
`TRAFFIC_E2E_ARTIFACT_OWNER` when creating the container. The controller stays
root and Source stays UID/GID 998. Private storage retains restrictive permissions;
normal finalization recursively assigns the completed run to the configured host
user. The reserved Source UID cannot own recording artifacts.

## Rewrite handoff

Finalization seals the input inventory and the dependency and payload
partitions in `dependency-manifest.json`. The dependency TSVs interleave
lifecycle and data rows. Every row starts with `seq`, `offset_us`, and the row
type. The recording assigns `seq` globally and uses monotonic microsecond
offsets. The admission sequence identifies the dependency. Later rows refer to
that sequence.

[Session recordings](session-regression.md) put primary, dependency and push
events in a single `events.tsv`. Case recordings put ordinary lifecycle events
and Case dependencies in `dependencies.tsv`, process and unattributed
dependencies in `dependencies-process.tsv` and `dependencies-unattributed.tsv`,
and notifications in `dependencies-push.tsv`. Nonmatching observations use
`observations.tsv` and remain available to route discovery and evidence readers.
The dependency locator links data rows by byte position.

A `request` data row carries the dependency metadata followed by its request
cell. Its `response` row carries the dependency sequence and response cell
after the common prefix. Responses without request data, notifications, and
observations carry their metadata and payload in one data row. Lifecycle rows
record admission and actual wire output timing. A complete response or delivery
with a recorded `wire_output end` can omit its redundant `capture_terminated`
row. The admission, receipt, and manifest coverage still describe the closure.

Endpoints use `host:port`, with brackets for IPv6. Recording-local Case and
connection IDs use independent counters. Case directories use
`apis/<api>/case-<seq>/`. A Case ID shared by observation, admission and
ownership is written once. The protocol declares its positional extension
fields and the fields belonging to the request and response. The term table
stores the declarations once. It also stores shared metadata and a UTC anchor
for relative nanosecond clocks used by evidence. Portable readers can reconstruct
the existing semantic evidence model from these fields.

Request and response cells can contain encoded text, Base64, JSON, or a
segment reference. Complete body values carry their encoding and data. A
Session body is stored out of line when nonempty. Case recordings place body
values larger than 4 KiB out of line. Both formats reference them by segment
number, byte offset and byte length. Segments roll over before the next value
once they reach 32 MiB. A value that crosses the threshold stays together.
The dependency writer rejects truncated bodies.

Replay prepares event plans from the selected dependency sequences. The
ordinary Replay read path uses the persisted locations and validates their
bounds. Explicit artifact verification and protected evidence readers use the
seal and content identities.

The writer appends startup, process, shutdown, and unattributed scope locators
as binary files under `indexes/` during recording. Finalization seals these
locators. Derived Global indexes and reports are prepared when requested.

Fast Replay caps the recorded gaps before sequenced response headers, parts and
completion. Requests and actual wire receipts still advance the Source cursor.
Engine.IO replies use the live Target ping payload, with capped delays for
recorded pong bindings. Missing pongs retain their recorded behavior.

Source proof retains original central byte positions and content hashes. Derived
indexes and independent attribution overlays do not modify the sealed recording.
Legacy API-origin ownership discovery and transaction promotion cannot replace a
current-format frozen owner. A full-session reconciliation receipt retains all
mandatory Source obligations, including unsupported and unattributed observations.

Expose the finalized recording tree under the target's conventional
`.traffic-e2e/local/artifacts/recordings/<run-id>/`, with its key accessible
privately at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec` when encryption is
used. Do not expose secrets or expected responses to Target. Replay does not
need the recording CA private key.

Use `status` on the Target's configured pull-request base. After approval,
start the round with the exact recorded run ID.

```sh
be-replay --target-root /absolute/target status
be-replay --target-root /absolute/target run --user-confirm --recording-run-id 20261123161021
```

When the workload or capture configuration changes, have the recording owner
seal a new run and use its identity for a new round. Keep earlier recordings
immutable.
[Source session regression](session-regression.md)
