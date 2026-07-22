# Resilience And Observability

Resilience comes from bounded failure domains and explicit recovery semantics,
not from indiscriminate retries or catch-all fallbacks.

## Failure And Overload

Define behavior for dependency timeout, connection exhaustion, malformed data,
partial batch failure, overload, shutdown, and stale configuration. Preserve
root causes while mapping them to stable external errors.

Use bulkheads, rate limits, load shedding, circuit breakers, or degradation only
when the failure mode justifies their operational cost. Bound every recovery
mechanism. A fallback must have its own capacity and correctness analysis; cache
failure followed by unrestricted database fallback is not resilient.

Protect idempotency and ordering across retries and partial completion. Required
side effects must not silently disappear because the primary response was
already written.

## Lifecycle

Startup should validate configuration and initialize owned resources before
readiness. Readiness and liveness must represent distinct contracts when the
platform uses both. Do not make transient dependency failure permanently wedge
startup unless the dependency is required by contract.

Graceful shutdown must stop admission, signal cancellation, drain bounded work,
flush required buffers, close clients, and terminate within a deadline. Report
which work was abandoned when the deadline expires.

## Observability

Make these questions answerable without exposing sensitive data:

- Did startup load the intended configuration and reach readiness?
- Is the service saturated at admission, workers, queues, memory, or a
  dependency pool?
- Which dependency and operation consumed the latency budget or failed?
- Did retry, fallback, degradation, or shedding occur?
- Did shutdown drain successfully?

Prefer existing structured logs, metrics, traces, and platform collection.
Avoid a parallel observability stack. Use bounded-cardinality dimensions;
never put user IDs, raw URLs, cache keys, SQL, message payloads, or unbounded
error text into metric labels.

Record latency distributions, counts, errors, saturation, and relevant queue or
pool wait. Correlation IDs should cross dependency boundaries when supported.
Sample high-volume successes while preserving errors and rare state changes.

Logs MUST redact credentials, authorization data, cookies, tokens, private
keys, full DSNs, SQL binds, and sensitive bodies. Diagnostic value does not
justify secret exposure.
