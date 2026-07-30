# Dependency Client Engineering

Apply this contract to databases, caches, HTTP/RPC services, queues, discovery,
configuration services, and storage systems. Use genuine production clients in
normal runtime and integration paths.

When source or repository evidence shows that Breeze manages a remote
resource's identity, discovery, listener, or connection lifecycle, read the
[`breeze-sdk` skill](../../breeze-sdk/SKILL.md) and use it for the reusable
resource layer. Apply that routing explicitly to Memcached, Redis, MySQL,
Kafka, queues such as MCQ or QueueService, Motan, Vintage service discovery,
and future Breeze-managed remote-resource types. Treat this list as trigger
examples, not a closed protocol allowlist.

Keep business SQL, keys, messages, remote service contracts, provider DTO
mapping, fallback decisions, and orchestration in a capability-owned adapter.
Only the business-independent Breeze resource client belongs in the SDK.

## Shared Contract

- Construct long-lived clients and pools at startup or through an explicitly
  owned lazy initializer. Never create a client or pool per request.
- Set separate connect, acquisition, request/read/write, and total deadlines
  when the client exposes them. All must fit the caller's remaining budget.
- Bound pool size, waiter count, in-flight requests, per-target concurrency,
  response size, and retry work.
- Classify timeout, overload, protocol, authentication, validation, and remote
  application errors without erasing their root causes.
- Retry only operations proven safe or protected by idempotency. Bound attempts
  and elapsed time, add jitter where synchronization is possible, and expose
  retry counts.
- Prevent retry multiplication across SDK, proxy, service, and job layers.
- Make discovery, routing, sharding, and failover changes observable. Do not
  bypass an established proxy or SDK without reproducing its semantics.
- Redact credentials, tokens, keys, values, SQL binds, and message bodies from
  ordinary logs and metrics.

## MySQL And SQL

Keep transactions short and never hold them across unrelated remote calls.
Bound result sizes or stream rows when a result can be large. Preserve schema
types, nullability, signedness, precision, temporal semantics, and transaction
isolation from authoritative schema evidence rather than guesses.

Pool capacity must account for application concurrency, transaction duration,
database limits, and the number of application instances. A large pool can
reduce database availability. Instrument acquisition wait, active/idle
connections, query latency, timeouts, errors, and transaction duration.

## Redis And Memcached

Treat multi-key operations, pipelines, scripts, and large values as bounded
work. Preserve binary data and protocol semantics. Distinguish miss, error,
timeout, and decode failure. Define cache stampede protection and fallback
behavior for hot or missing keys; a cache failure must not create an unbounded
database surge.

Respect the existing sharding/proxy SDK when it owns routing, failover, or
degradation policy. Do not replace it with direct node access merely to simplify
tests or recording.

## Kafka And Queues

Bound producer buffering, batch size, delivery wait, consumer concurrency, and
in-flight processing. Define acknowledgement, idempotency, ordering, duplicate,
retry, dead-letter, and commit semantics before implementation. Do not commit a
message before required side effects are durable. Rebalance and shutdown must
stop admission and settle owned work without silently losing it.

## HTTP And RPC

Reuse connection pools, bound response bodies, and close or drain responses as
required by the client. Preserve end-to-end deadlines and idempotency metadata.
Limit fan-out and hedge only with measured justification. Validate remote data
at the boundary and keep protocol models out of core business logic where a
stable internal contract exists.
