---
name: backend-engineering
description: "Guide AI whenever designing, implementing, modifying, migrating, or reviewing backend APIs, workers, scheduled jobs, consumers, gateways, or shared runtime components. Apply production engineering standards and context-dependent guidance for architecture, dependency clients, bounded concurrency, timeouts, retries, backpressure, data and memory efficiency, throughput, resilience, observability, and evidence-based verification. Use regardless of current traffic scale; do not invoke for UI-only or documentation-only work."
---

# Backend Engineering

Build backend software that remains correct and operable under concurrency,
dependency failures, large payloads, and sustained load. Treat performance,
throughput, and stability as measurable system properties, not adjectives that
can be claimed from code inspection alone.

## Normative Language

Interpret `MUST`, `MUST NOT`, and `REQUIRED` as hard engineering constraints.
Interpret `SHOULD` as the default unless repository evidence or measured
tradeoffs justify another choice. Record important workload assumptions and
tradeoffs rather than silently inventing production requirements.

Repository instructions and established runtime contracts remain authoritative.
Apply stricter local rules when they exist. Do not preserve a demonstrably unsafe
legacy pattern merely because it already exists, but keep unrelated cleanup out
of the current change.

## Working Method

1. Inspect the repository instructions, architecture, normal startup, config,
   tests, observability, and the exact path being changed. Identify whether the
   path is latency-sensitive, throughput-sensitive, memory-sensitive,
   stateful, or failure-critical.
2. State the observable contract, expected workload when known, external
   dependencies, side effects, and failure semantics. Mark unknown capacity
   inputs as assumptions; do not fabricate exact traffic or latency targets.
3. Establish resource budgets before adding concurrency: request and job
   deadlines, maximum in-flight work, queue bounds, connection ownership,
   payload limits, and shutdown behavior.
4. Choose the smallest design that preserves clear ownership and dependency
   direction. Reuse established repository frameworks and clients unless
   evidence justifies a change.
5. Implement success, overload, timeout, cancellation, and dependency-failure
   paths together. Do not postpone failure behavior until after the happy path.
6. Verify correctness and operational properties in proportion to risk. Use
   targeted tests for local behavior and measured evidence for material
   performance or capacity claims.
7. Review the final implementation again for unbounded work, retry
   multiplication, avoidable allocation, hidden blocking, resource leaks,
   missing observability, and accidental behavior changes.

## Non-Negotiable Baseline

- Every queue, buffer, cache, batch, fan-out, task set, and in-flight request
  population MUST have an explicit bound or an evidenced external bound.
- Every remote operation MUST have a deadline consistent with the caller's
  end-to-end budget. Cancellation and shutdown MUST stop or safely detach work.
- Retries MUST be limited, idempotency-aware, budget-aware, and observable.
  Layered clients MUST NOT multiply retries invisibly.
- Long-lived dependency clients and pools MUST have explicit ownership,
  reuse, health behavior, capacity, and shutdown. Do not create a new client or
  connection pool per request.
- Overload MUST produce bounded degradation, backpressure, shedding, or a clear
  failure. It MUST NOT grow memory or work queues without limit.
- Large or attacker-controlled inputs MUST be bounded before allocation.
  Avoid unnecessary full-object copies and repeated serialization on hot paths.
- Partial failure MUST remain isolated. A slow or failing dependency MUST NOT
  consume all workers, connections, memory, or retry budget.
- Logs, metrics, and traces MUST make startup, saturation, dependency latency,
  errors, and shutdown diagnosable without exposing secrets or unbounded data.
- Production behavior MUST NOT depend on tests, recordings, fixtures, debug
  branches, or developer-only defaults.

## Risk-Scaled Decisions

Do not add caches, pools, batching, lock-free structures, circuit breakers, or
parallelism only because they sound scalable. Each mechanism adds failure modes
and operational cost. Prefer the simplest bounded design that satisfies known
requirements and leaves an observable path for later tuning.

Conversely, low current traffic is not permission to introduce unbounded
resources, per-request client construction, hidden retries, whole-response
duplication, or irreversible coupling. These are correctness and operability
defects before they become scale defects.

## Reference Routing

- Read [architecture.md](references/architecture.md) when choosing modules,
  ownership, configuration, APIs, or runtime boundaries.
- Read [concurrency-and-backpressure.md](references/concurrency-and-backpressure.md)
  when adding async work, threads, queues, batching, fan-out, or background work.
- Read [dependency-clients.md](references/dependency-clients.md) whenever the
  change touches databases, caches, HTTP/RPC, queues, discovery, or another
  remote system.
- Read [data-and-memory.md](references/data-and-memory.md) for JSON, large
  payloads, serialization, buffering, compression, or allocation-sensitive paths.
- Read [resilience-and-observability.md](references/resilience-and-observability.md)
  for readiness, overload, degradation, shutdown, logging, metrics, or tracing.
- Read [verification.md](references/verification.md) before making correctness,
  performance, throughput, capacity, or stability claims.
- Read [migration.md](references/migration.md) when rewriting or migrating an
  existing capability, including cross-language work.
- Read [rust.md](references/rust.md) only when Rust is the implementation language.

When recorded traffic is supplied or `traffic-e2e` is requested, load the
companion `traffic-e2e` skill. It exclusively owns recording, case artifacts,
dependency replay, replay policy, and canonical E2E evidence. Do not duplicate
those contracts here.

## Completion Review

Before claiming completion, confirm that:

1. repository-required format, lint, static analysis, and tests pass;
2. normal startup and shutdown remain valid for runnable components;
3. resource bounds, deadlines, retries, cancellation, and dependency ownership
   are explicit on every changed runtime path;
4. large data and hot paths do not introduce avoidable copies, unbounded
   buffering, high-cardinality telemetry, or blocking work on async executors;
5. failure and overload behavior are tested or otherwise evidenced where they
   can affect correctness or availability;
6. performance claims include a benchmark, load test, production-equivalent
   observation, or an explicitly limited analytical claim;
7. the final structure owns the responsibilities introduced by the change and
   leaves unrelated legacy cleanup untouched.

If required evidence is unavailable, report the assumption or remaining risk.
Do not describe the implementation as high-performance, high-throughput,
scalable, or highly available without corresponding evidence.

## Change Delivery Gate

When the work produces deliverable source, config, test, script, or
documentation changes, commit the intended changes on the feature branch, push
it, and create a draft PR against the confirmed base before the final response.
An incomplete or blocked verification result does not waive this requirement;
preserve the exact status and blockers in the PR.

Skip PR creation only when the user explicitly requests no PR or when no
deliverable change exists. Keep unrelated pre-existing worktree changes out of
the commit and PR.
