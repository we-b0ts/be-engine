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

Use structured concurrency. A parent future should own and await or cancel
every child task. With Tokio, use the repository's established task-set,
cancellation, or supervisor pattern; dropping a `JoinHandle` only detaches its
task and is not lifecycle ownership. Deliberately detached tasks need a bounded
supervisor, error reporting, and shutdown ownership.

## Async And Blocking Work

Do not block Tokio executor threads with filesystem calls, synchronous DNS,
process waits, CPU-heavy JSON work, compression, cryptography, or blocking
client libraries. Put bounded admission in front of `spawn_blocking`, or move
the work to a bounded dedicated pool, and include its queue and shutdown in
capacity analysis.

Do not hold a `std::sync` or async lock guard across remote I/O, sleep, user
callbacks, or other unbounded-duration work. Holding a guard across `.await`
requires an explicit resource reason and a contention and cancellation review.
Keep critical sections small and define lock ordering when more than one lock
can be acquired. Prefer ownership transfer, sharding, or message passing when
shared mutation dominates the hot path.

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
