# Standalone Source recording

See [API-origin dependency observation](recording-api-origin-tail.md) for
immediate HTTP response forwarding and rule-scoped asynchronous recording tails.

`traffic-e2e record` is the single standalone Source recording service.
It starts a co-located Source as UID/GID 998, starts Recorder, and optionally registers a
reachable HTTP address in coordination Redis after readiness and the existing
post-ready settle window. Optional `--config PATH` / `TRAFFIC_E2E_PROJECT_CONFIG`
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
rules, readiness, streaming and timeout settings when they affect the project.
For example, `http_gateway.record_streaming: true` selects streaming capture;
`project.replay.http_stream_timing` separately selects replay timing and defaults
to `recorded`.

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

Normal SIGTERM/SIGINT shutdown first withdraws discovery and closes admission of
new cases. Source, Recorder and admitted sessions remain alive for up to **60
seconds**, waiting for primary requests, dependency tails and case publication.
Existing Socket.IO polling follow-ups may finish their admitted session. Stream
idle windows, absolute request deadlines and dependency persistence budgets
continue to apply; a failure requiring Source isolation ends the wait early.
After this wait, the supervisor stops Source and then closes retained dependency
connections as engine cleanup before finalizing the recording.

The run manifest distinguishes external SIGTERM/SIGINT (`shutdown_signal`) from
an internal safety stop (`source_isolation_required`). Source isolation can
complete a valid recording after an asynchronous dependency failure or deadline;
it does not imply that the operator stopped the container.

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
`shutdown` owner with the frozen `origin_case_id` (the `post-<case_id>`
relationship). They are stored once in the central ledger and referenced by
`indexes/shutdown-scope.json`, independently of the primary Case's result.
Declared process-task ownership and ambiguous selector failures retain priority.

If no Case was running at the first shutdown boundary, teardown requests remain
unattributed (`shutdown_without_running_case`) and still require analysis. A
previously completed Case or a reserved but unstarted input cannot supply the
association later. Associated shutdown evidence does not request repository
analysis, repair a failed Case, supply primary Replay responses, or certify a
WholeSource pass; its unexecuted mandatory dependencies remain visible separately.

HTTP request waits and HTTP streaming duration share
`recorder.http_gateway.request_timeout_ms`, default 900000 ms (900 seconds).
`--request-timeout-seconds` overrides the same budget for both. Ordinary HTTP
timeouts retain their case while Source gets the configured
`recording.case_dependency_drain_timeout_ms` recovery budget to finish. If it
cannot finish within that budget, admission closure wakes the supervisor to stop
Source and finalize the failed recording. Source exit is confirmed before the
supervisor closes any remaining dependency connections as engine-owned cleanup.

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

Standalone recording can load the Source effects of a `traffic-policy/v3`
document with `--policy PATH` / `TRAFFIC_E2E_POLICY`. With `--config`, an explicit
policy must resolve to the same file as `project.policy`; it cannot override the
project authority. Without project configuration or policy, cases use literal
URI paths. Capture, HTTP response acquisition and process ownership effects are
applied once at startup. Comparison rules in the same file do not enable Replay
or change Source business behavior. HTTP include/exclude rules still apply.

An API that returns before its work finishes can retain the ordinary Case with
`async_api` in the same policy:

```yaml
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

These are illustrative terminal resources; choose the actual final dependency
from Source behavior. An initialization access that uses the same key or SQL
cannot also identify completion. MySQL matches the full SQL structure and fixed
literals, ignoring whitespace and keyword case. Each `?` matches one scalar;
prepared parameters are decoded before matching. Redis matches the operation
and physical key, with at most one `*`. An optional `occurrence: 2` waits for the
second successful access to the same physical key, database and endpoint when
Source uses the same operation during initialization and final cleanup. Distinct
keys and mirrored evidence cannot be combined to reach that count.
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

Dependencies remain in
the ordinary Case after the primary response is sent. Any declared terminal
resource, any ordinary dependency failure, or the existing common request
deadline completes observation. There is no policy timeout or failure toggle.
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
unsafe exchanges, and business-command errors retain their failure behavior.

`async-api-observation.json` records `end_reason` as `resource`,
`dependency_failure`, or `timeout`, together with the zero-based selected
`scenario_index`. The latter two end reasons stop Source through normal
recording supervision so its detached worker cannot leak into another Case.
Admitted I/O retains its original ownership until the real termination and queued
evidence have drained. The ordinary Case and recording finish normally; this is
not a recording invalidation. Capture corruption or incomplete primary HTTP
traffic still follows the existing failure behavior.

The observation stores the precise Source-stop offset and exact `cleanup_refs`
for admitted requests still unfinished at that boundary. Original outcomes,
errors and partial bytes remain in the semantic trace. Replay retains those
requests through an engine-controlled Target stop and consumes them only after
real Target transport termination. It does not turn Recorder cleanup into a
business response, fabricate a proxy 502, or waive unstarted ordinary resources.
Captured HTTP prefixes may reuse global formats for complete JSON/SSE values;
partial or unknown bytes stay exact, and no unobserved response EOF is added.
Capture limits and prefixes that were not flushed remain capture failures.

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

Build the normal engine binary. The gateway SDK uses published
`brz-http-gateway = 0.2.12` with `redis-recording` enabled; Redis uses published
`brz-redis = 0.0.16`. Its recorder-side registration, reservation renewal and
completion protocol is compatible with gateway services using `0.2.14` and the
API policy below. The Recorder SDK stays on `0.2.12` to avoid newer SDKs' transitive
`serde_json/preserve_order` feature changing engine JSON serialization and Replay
identities. No sibling gateway checkout is required.

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

Run in an isolated container network namespace, with a root controller and
`NET_ADMIN`/`NET_RAW` for fixed-identity dependency interception. The recording
container's Source must use the same business configuration as the original
service. Example environment and command (provide the Redis URL securely):

```bash
export TRAFFIC_E2E_RECORD_URL=http://recorder-host:4080
export TRAFFIC_E2E_RECORDING_PREFIX=recording:orders
export TRAFFIC_E2E_RECORDING_SCOPE=all-apis
export TRAFFIC_E2E_RECORDING_REDIS_URL=redis://redis-host:6379/0
traffic-e2e record --coordination redis --source-workdir /app --ready-path /health \
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

The existing per-API case limit remains enabled. With project configuration,
Recorder settings, including limits, redaction, dependency timing, DNS strategies,
and post-ready observation, are reused. HTTP include/exclude rules are retained exactly as configured. The standalone service still supplies its
internal listener, Source origin, fixed 404 fallback and persistent mount paths;
explicit readiness, request-timeout and case-limit options override project values.
The project setting `recorder.http_gateway.record_streaming` is also retained;
there is no separate CLI override. Its default is `false`. With `false`, any
request whose `Accept` includes `text/event-stream` returns the fixed
404 before Source dispatch, including mixed JSON/SSE MCP requests. The adapter
releases the reservation on this response, allowing the gateway to use its
original path. See [SSE recording selection](http-sse.md).
Without project configuration the per-API default is `usize::MAX`
(`u64::MAX` on the supported 64-bit deployment). `--case-limit N` or
`TRAFFIC_E2E_CASE_LIMIT=N` applies a smaller positive limit. After an API hits
its limit, Recorder returns the configured 404 so the gateway can use its
original path. There is no duration limit; SIGTERM/SIGINT ends the session.

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
| `--scope` / `TRAFFIC_E2E_RECORDING_SCOPE` | `all-apis` | One shared request slot |
| `--url-key` / `TRAFFIC_E2E_RECORDING_URL_KEY` | `<prefix>:url` | Address lease key |
| `--data-root` / `TRAFFIC_E2E_DATA_ROOT` | `/data/traffic-e2e` | Persistent evidence, encryption key and CA |
| `--artifact-owner` / `TRAFFIC_E2E_ARTIFACT_OWNER` | invoking controller owner | Numeric host UID:GID for private storage and finalized runs; explicit values require root |
| `--source-workdir` / `TRAFFIC_E2E_SOURCE_WORKDIR` | `/app` | Source working directory |
| `--policy` / `TRAFFIC_E2E_POLICY` | unset | Unified policy for standalone recording; with `--config`, must name `project.policy` |
| `--api-policy` / `TRAFFIC_E2E_API_POLICY` | all paths, no gateway limit | Redis-only gateway JSON policy; publish once at startup, independently of Recorder rules and limits |
| `--startup-timeout-seconds` | `300` | Startup/readiness deadline |
| `--request-timeout-seconds` | project value or `30` seconds | Override request forwarding/response deadline |
| `--dns-upstream` / `TRAFFIC_E2E_DNS_UPSTREAM` | project value or first system resolver | Override real DNS upstream before fake-IP projection |

The post-ready cap is separate from the startup failure deadline. For example,
`recorder.recording.post_ready_max_wait_ms: 30000` allows case admission after at most
30 seconds of post-ready observation even when periodic Redis snapshot requests
prevent a quiet period. Source startup and bootstrap dependency sealing are
separate phases. `recorder.recording.post_ready_settle_ms` controls the quiet
period, with a 15-second minimum for nonzero values. A missing or invalid
explicit project configuration fails before Source startup and registration.
Mount project YAML read-only alongside its policy and restart after edits.

Keep project configuration and policy outside the image and bind-mount them
read-only. Preserve the `.traffic-e2e` directory and repository-relative path
inside the mount; keep the real Source work directory and business configuration
unchanged:

```bash
--mount "type=bind,src=$PWD/.traffic-e2e/policy.yaml,dst=/etc/traffic-e2e/.traffic-e2e/policy.yaml,readonly" \
--mount "type=bind,src=$PWD/.traffic-e2e/project.yaml,dst=/etc/traffic-e2e/.traffic-e2e/project.yaml,readonly" \
--env TRAFFIC_E2E_PROJECT_CONFIG=/etc/traffic-e2e/.traffic-e2e/project.yaml
```

The mounted project contains `project.policy: .traffic-e2e/policy.yaml`.
For a deployment without project YAML, mount that same policy and supply
`--policy /etc/traffic-e2e/.traffic-e2e/policy.yaml` instead.

An explicitly configured missing, non-regular or invalid policy fails startup;
there is no fallback to literal-path grouping on errors. Policy overlays must
also be compatible with the standalone Recorder configuration; for example,
Breeze capture entries require a matching DNS bypass strategy. Restart the
container after changing policy; files are not watched or reloaded during a run.
With `/api/teams/*/skills`, requests for different team IDs share the
`apis/api-teams-wildcard-skills/` group and its case limit. Previously published
recordings retain their existing groups.

`--no-interception` is for local adapter tests only. Ordinary HTTP bodies remain
buffered. With `recorder.http_gateway.record_streaming: true`, SSE, NDJSON
and Socket.IO EIO4 sessions are forwarded incrementally. Raw binary response
streams additionally require `recorder.http_gateway.record_raw_streaming: true`.
Socket.IO supports polling, direct WebSocket and polling upgrade. One connection
owns one case and one recording slot across authentication and multiple events.
The default business idle is 10 seconds and the activity limit is 10 minutes.
Normal closure keeps Source running. Primary HTTP streams retain their case for
the [dependency tail](recording-stream-dependency-tail.md), including when the
client cancels before business completion. The default idle window is 60 seconds,
bounded by the original request budget. The 5-second writer drain begins after
live dependency requests finish. Socket.IO retains its existing dependency window
and transport cleanup policy.
Protocol heartbeats do not reset business idle. An unfinished request times out
explicitly and an activity-limit capture is incomplete.

See [streaming and Socket.IO](interaction-recording.md) for completion profiles,
input timing, dependency streaming and background-work policy. The former SSE 50 ms
contract is retired; its recordings require re-recording. Request body limits
still apply before Source dispatch.

## Direct standby and run identity

Without `--coordination`, the service waits for direct HTTP requests after Source
readiness. It never connects to Redis and requests need no reservation headers.
The same local single-request slot, body limits, recording rules and finalization
apply. Source's business `REDIS_URL` does not enable recording coordination.

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
use the same Redis writer/database, prefix, URL key and request scope.

The app publishes `<prefix>:url` using `SET NX PX 30000`:

```json
{"url":"http://recorder-host:4080","owner":"<32 hex boot token>"}
```

The gateway SDK accepts this lease value as well as an externally managed plain
URL. Every 10 seconds the app renews the lease only if its complete value still
matches. A live second recorder cannot overwrite it. On shutdown the app deletes
only its own value; after a crash TTL expiry allows a replacement to register.
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

For an incoming request the adapter validates the reserved scope/token headers
and checks token ownership with Redis GET. It removes both headers before
Recorder/Source dispatch. A local semaphore retains exclusive admission, and
token-checked renewal keeps the Redis reservation alive through dispatch and
case cleanup. Lost ownership closes admission and fails an active interaction.
Ordinary HTTP busy admission returns 404 without deleting the active token;
new streaming connections return 503. Missing/stale ordinary HTTP admission
also returns 404 without Source dispatch.

After the full Recorder response, including its case/dependency finalization,
the adapter calls `RedisAdmissionProvider::complete` to compare the token and
delete `<prefix>:inflight:<scope>`. Closed admission, oversized input, or an
upstream connection failure before dispatch releases that token and returns 404.
Errors/disconnects after dispatch return 502/504 and retain the reservation for
TTL recovery. A downstream disconnect does not cancel the upstream operation.
The core Recorder owns no Redis logic or gateway identity.

Shutdown withdraws the address, stops new adapter connections, stops Source,
drains active requests and disconnect dependencies, finalizes Recorder, then
removes interception rules.
Evidence lives under
`<data-root>/.traffic-e2e/local/artifacts/recordings/<run-id>/`; authorization and
cookie request headers are encrypted using a persistent key in
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

Replay reads `dependencies.jsonl` and the finalized `recording-network.json`
manifest, creates its own DNS mapping and uses a Replay-session CA. It does not
read the recording fake DNS registry or require the recording CA private key.
Sharing Recorder state keeps subsequent recordings consistent; it is not a
prerequisite for Replay.

For a host bind mount, pass the invoking host user's numeric UID:GID as
`TRAFFIC_E2E_ARTIFACT_OWNER` when creating the container. The controller stays
root and Source stays UID/GID 998. Private storage retains restrictive permissions;
normal finalization recursively assigns the completed run to the configured host
user. The reserved Source UID cannot own recording artifacts.

## Rewrite handoff

Finalization seals `dependency-manifest.json`, the central `dependencies.jsonl`
and lifecycle ledger, the complete input inventory and reference-only Case,
startup, process and unattributed scopes. Replay authenticates the sealed inventory
and prepares bounded native indexes and reusable read caches. There are no separate
Case or Global payload files in current recordings.

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

`backend-rewrite next` consumes existing completed batches directly; it does not
start recording, allocate recording IDs, restart Source, or recover recording
containers. The selected batch stays fixed across failed Replay attempts.
For deterministic selection, set `recording_run_id` in the existing local
`.traffic-e2e/regression.yaml`. Without a pin, initial discovery selects an
available completed batch with a usable scope; subsequent runs keep that identity.
A new capture contract requires an externally produced newer batch; batches
already present when refresh begins cannot satisfy it. Never edit
old recordings to satisfy the new contract.
