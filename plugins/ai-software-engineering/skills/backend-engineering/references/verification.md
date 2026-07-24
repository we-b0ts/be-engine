# Correctness And Performance Verification

Select evidence according to the claim and risk. Tests prove only the behavior
they exercise; code inspection alone does not prove runtime performance,
capacity, or stability.

## Correctness Evidence

- Unit tests cover pure logic, parsing, validation, state transitions, error
  mapping, and serialization boundaries.
- Component tests cover real framework and adapter integration where local
  execution is deterministic.
- Integration tests use genuine client and protocol paths for external
  dependency behavior when practical.
- Recorded or real-traffic E2E evidence verifies observable compatibility when
  supplied. Follow the supplied traffic tool's canonical workflow.
- Failure tests cover timeout, cancellation, overload, partial failure, retry,
  and shutdown when those paths are material.

Mocks can isolate local logic but cannot prove wire compatibility, connection
management, dependency semantics, or system capacity. Avoid tests that
reimplement the production algorithm or construct actual results from expected
fixtures.

## Performance Evidence

Define the claim before measuring: latency percentile, throughput, CPU,
allocation, memory, queueing, dependency load, or recovery time. Use
representative payload sizes, concurrency, connection reuse, warmup, and
dependency behavior. Compare a baseline when changing an existing path.

Microbenchmarks are appropriate for parsers, codecs, allocators, and local hot
loops. End-to-end benchmarks or load tests are required for service throughput,
tail latency, queueing, pool saturation, overload, and stability claims.

Observe at least:

- request or job rate and latency distribution;
- error, timeout, retry, fallback, and rejection rates;
- queue depth and wait, active tasks, and pool acquisition wait;
- CPU, allocation or GC pressure, and resident memory;
- downstream request rate and saturation;
- recovery and shutdown behavior.

Do not tune to one average-rate happy-path run. Include bursts, slow
dependencies, large payloads, and sustained duration when the risk requires it.

## Completion Language

Use precise conclusions:

- `verified` only for the exercised contract and environment;
- `analytically bounded` for a design property established without runtime load;
- `not measured` for unsupported performance assumptions;
- `remaining risk` for untested failure or capacity behavior.

Never translate a passing functional test into a high-performance,
high-throughput, scalable, or highly available claim.
