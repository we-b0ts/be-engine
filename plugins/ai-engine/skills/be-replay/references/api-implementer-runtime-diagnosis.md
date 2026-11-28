# Runtime and Replay Diagnosis

Use the failed Source sequence, Target attempt, and reported setup or Replay
error. See [Source Session evidence](session-regression.md#diagnose-the-first-failure).

## Session progress

For setup errors, check the sealed input, Replay readiness, Target image build,
and managed startup inputs at the reported boundary. For an event failure,
follow the expected event and returned protected evidence queries. For primary
HTTP, use `exchange` to correlate the request with its response or cancellation.
Use `events --payload` when the diagnostic needs protected primary HTTP data.

Use `source_start`, `ready`, `stop`, and `source_exit` to locate launch, readiness,
and shutdown issues. Startup, background work, and concurrent requests can
interleave. Trace the application condition enabling the expected event and the
preceding recorded input or delivery that establishes it. Preserve normal
runtime deadlines and cancellation behavior.

## Rejected egress

Treat reported packet-count deltas and sampled time windows as leads. Counts can
include retries and background traffic. Trace the dependency call and the
endpoint from Source configuration or an earlier dependency response. Check
equivalent recorded endpoints. Return the relevant sequence, literal IP and
port if available, Source citation, and precise missing observation.

## Local cache and runtime state

Trace the response through the cache key, hit or miss branch, loader,
population or refresh, and startup or request lifecycle. Preserve Source key
construction, negative-cache behavior, warmup and readiness, expiry and stale
behavior, bounds, coalescing, and dependency failure behavior. Use recorded
startup and background events to confirm the relevant loader or refresh.

If a generated time affects the runtime branch, establish the Source clock,
time value, and delivery. Check [rule diagnosis](api-implementer-rule-diagnosis.md)
and preserve the application expiry and refresh semantics.

## Target runtime inputs

Check the build and entrypoint, application environment, source-compatible
mounts, port and readiness endpoint, Replay CA trust, dependency client wiring,
foreground identity, and graceful shutdown. Trace permission failures to the
actual mount or writable directory. For input changes, use
[startup input requirements](api-implementer-startup-inputs.md).

If Replay cannot reproduce a recorded mandatory exchange, return its evidence
reference, Source citation, and exact limitation to the coordinator. When
capture is incomplete, follow [dependency diagnosis](api-implementer-dependency-diagnosis.md).
