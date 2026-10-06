# Standalone online recording

`recording-online` is an optional, independent application over `traffic_e2e`.
It starts a co-located Source as UID/GID 998, starts Recorder, and registers a
reachable HTTP address in coordination Redis after readiness and the existing
post-ready settle window. It does not load `project.yaml`, inspect Git, apply
API selectors, or start the rewrite coordinator. Gateway route configuration
selects traffic; all methods and paths arriving with valid admission are eligible.

Build with the opt-in feature. The gateway SDK uses published
`brz-http-gateway = 0.1.6`; Redis uses published `brz-redis`.

```bash
cargo build --locked --release --features online-recording --bin recording-online
cargo test --locked --features online-recording
cargo clippy --locked --all-targets --features online-recording -- -D warnings
```

Run in an isolated container network namespace, with a root controller and
`NET_ADMIN`/`NET_RAW` for fixed-identity dependency interception. The online
container's Source must use the same business configuration as the original
service. Example environment and command (provide the Redis URL securely):

```bash
export TRAFFIC_E2E_ONLINE_URL=http://recorder-host:4080
export TRAFFIC_E2E_RECORDING_PREFIX=recording:orders
export TRAFFIC_E2E_RECORDING_SCOPE=all-apis
export TRAFFIC_E2E_RECORDING_REDIS_URL=redis://redis-host:6379/0
recording-online --source-workdir /app --ready-path /health \
  -- python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

Default flow is gateway → public adapter `:4080` → Recorder `127.0.0.1:4081` →
Source `127.0.0.1:8080`. Recorder and Source listeners must use different
loopback ports. `--advertise-url` / `TRAFFIC_E2E_ONLINE_URL` is required and
must be the HTTP origin reachable by gateways, including any Docker port mapping.

The existing per-API case limit remains enabled. Its default is `usize::MAX`
(`u64::MAX` on the supported 64-bit deployment). `--case-limit N` or
`TRAFFIC_E2E_CASE_LIMIT=N` applies a smaller positive limit. After an API hits
its limit, Recorder returns the configured 404 so the gateway can use its
original path. There is no duration limit; SIGTERM/SIGINT ends the session.

| Parameter / environment | Default | Purpose |
| --- | --- | --- |
| `--listen` / `TRAFFIC_E2E_ONLINE_LISTEN` | `0.0.0.0:4080` | Public adapter |
| `--recorder-listen` / `TRAFFIC_E2E_RECORDER_LISTEN` | `127.0.0.1:4081` | Internal Recorder |
| `--source-origin` / `TRAFFIC_E2E_SOURCE_ORIGIN` | `http://127.0.0.1:8080` | Source origin |
| `--ready-path` / `TRAFFIC_E2E_SOURCE_READY_PATH` | `/` | Source readiness, expects 200 |
| `--redis-url` / `TRAFFIC_E2E_RECORDING_REDIS_URL` | exported `REDIS_URL` | Coordination Redis; supports password/default user and DB |
| `--prefix` / `TRAFFIC_E2E_RECORDING_PREFIX` | `recording` | Shared coordination prefix |
| `--scope` / `TRAFFIC_E2E_RECORDING_SCOPE` | `all-apis` | One shared request slot |
| `--url-key` / `TRAFFIC_E2E_RECORDING_URL_KEY` | `<prefix>:url` | Address lease key |
| `--data-root` / `TRAFFIC_E2E_DATA_ROOT` | `/data/traffic-e2e` | Persistent evidence, encryption key and CA |
| `--artifact-owner` / `TRAFFIC_E2E_ARTIFACT_OWNER` | invoking controller owner | Numeric host UID:GID for private storage and finalized runs; explicit values require root |
| `--source-workdir` / `TRAFFIC_E2E_SOURCE_WORKDIR` | `/app` | Source working directory |
| `--startup-timeout-seconds` | `300` | Startup/readiness deadline |
| `--request-timeout-seconds` | `30` | Request forwarding/response deadline |
| `--dns-upstream` / `TRAFFIC_E2E_DNS_UPSTREAM` | first system resolver | Real DNS upstream before fake-IP projection |

`--no-interception` is for local adapter tests only. HTTP request and response
bodies are buffered. Primary `text/event-stream` responses use a bounded 50 ms
observation after receiving Source headers, then Recorder ends the upstream
response and finalizes the case. The adapter forwards this finite response and
releases admission after finalization. See [bounded SSE support](http-sse.md)
for the recording/replay contract. HTTP upgrade and indefinite streaming sessions
are not supported. The existing body capture limit bounds request buffering;
oversized input is rejected before Source dispatch.

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
Loss of registration stops admission and initiates graceful shutdown.

For an incoming request the adapter validates the reserved scope/token headers
and checks token ownership with Redis GET. It removes both headers before
Recorder/Source dispatch. A local semaphore keeps one request active even after
the 60-second Redis slot expires. Busy returns 404 without deleting the active
token. Missing/stale admission also returns 404 without Source dispatch.

After the full Recorder response, including its case/dependency finalization,
the adapter calls `RedisAdmissionProvider::complete` to compare the token and
delete `<prefix>:inflight:<scope>`. Closed admission, oversized input, or an
upstream connection failure before dispatch releases that token and returns 404.
Errors/disconnects after dispatch return 502/504 and retain the reservation for
TTL recovery. A downstream disconnect does not cancel the upstream operation.
The core Recorder owns no Redis logic or gateway identity.

Shutdown withdraws the address, stops new adapter connections, drains an active
request, finalizes Recorder, stops Source, then removes interception rules.
Evidence lives under
`<data-root>/.traffic-e2e/local/artifacts/recordings/<run-id>/`; authorization and
cookie request headers are encrypted using a persistent key in
`<data-root>/.traffic-e2e/local/secrets/traffic-e2e-enc.sec`. Persist the entire
data root across restarts. Source cannot read private evidence, the encryption
key, or CA private key.

For a host bind mount, pass the invoking host user's numeric UID:GID as
`TRAFFIC_E2E_ARTIFACT_OWNER` when creating the container. The controller stays
root and Source stays UID/GID 998. Private storage retains restrictive permissions;
normal finalization recursively assigns the completed run to the configured host
user. The reserved Source UID cannot own recording artifacts.
