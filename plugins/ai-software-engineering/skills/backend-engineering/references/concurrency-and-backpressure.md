# Concurrency And Backpressure

Concurrency is a resource allocation decision. Define what limits admission,
work in progress, queued work, memory, downstream concurrency, and shutdown
time before increasing parallelism.

## Required Design

- Bound task creation, queues, batches, buffers, fan-out, and in-flight calls.
- Propagate the caller deadline and cancellation signal through child work.
- Stop admission before draining during shutdown.
- Choose overload behavior explicitly: wait within a deadline, shed, degrade,
  coalesce, or reject. Never default to unbounded buffering.
- Keep fairness requirements explicit when one tenant, shard, key, or job type
  can monopolize workers or connections.

Use structured concurrency when the language supports it. A parent operation
should own and await, cancel, or deliberately detach every child. Detached
tasks need a bounded supervisor, error reporting, and shutdown ownership.

## Async And Blocking Work

Do not block an async executor with filesystem calls, synchronous DNS, process
waits, CPU-heavy JSON work, compression, cryptography, or blocking client
libraries. Move unavoidable blocking or CPU-heavy work to a bounded dedicated
pool and include its queue in capacity analysis.

Do not hold a lock across remote I/O, sleep, user callbacks, or other
unbounded-duration work. Keep critical sections small and define lock ordering
when more than one lock can be acquired. Prefer ownership transfer, sharding,
or message passing when shared mutation dominates the hot path.

## Throughput And Batching

Batch only when the downstream protocol and latency budget benefit. Bound both
batch size and maximum wait time. Define partial-failure, ordering, duplicate,
and retry behavior. Flush required batches during shutdown within a deadline.

Parallel fan-out can reduce median latency while increasing tail latency,
downstream load, and failure amplification. Cap concurrency per request and
globally. Avoid nested concurrency limits that deadlock or reserve capacity
while waiting for another saturated pool.

## Evidence

Measure queue wait, active work, saturation, rejections, task duration, and
shutdown drain time when the path is operationally significant. A higher task
or thread count is not evidence of greater throughput.
