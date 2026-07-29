---
name: backend-engineering
description: "Design, implement, modify, or review production backend code using coding, code-organization, module-ownership, architecture, runtime-safety, and verification standards. Use for backend APIs, workers, scheduled jobs, consumers, gateways, dependency clients, shared runtime components, and target-code work delegated by an orchestration workflow; this skill owns engineering quality, not task sequencing, external evidence gates, or delivery orchestration."
---

# Backend Service Engineering

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

Read-only inspection of an available authorized runtime is allowed when
repository files do not establish effective configuration or startup behavior.
Inspect only necessary configuration, environment variable names and
provenance, startup arguments, deployment metadata, and dependency wiring.
Never print, persist, or hard-code secret values, and do not replace a genuine
runtime dependency with an environment variable inferred from traffic.

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

- Read [code-organization.md](references/code-organization.md) before modifying
  or reviewing product code. For Rust changes, run its bundled organization
  checker after the final product-code edit and before commit, then again at
  the prescribed MR boundary.
- Read [architecture.md](references/architecture.md) when choosing modules,
  ownership, configuration, APIs, or runtime boundaries.
- Read [large-rust-backend-architecture.md](references/large-rust-backend-architecture.md)
  before structuring or extending a Rust backend with multiple deployable
  roles, product capabilities, service dependencies, remote clients, API
  adapters, or complex configuration.
- Read [concurrency-and-backpressure.md](references/concurrency-and-backpressure.md)
  when adding async work, threads, queues, batching, fan-out, or background work.
- Read [dependency-clients.md](references/dependency-clients.md) whenever the
  change touches databases, caches, HTTP/RPC, queues, discovery, or another
  remote system.
- When a remote resource is managed through Breeze, also read and use the
  [`breeze-sdk` skill](../breeze-sdk/SKILL.md) for its business-independent
  resource client; keep business behavior under this skill in the owning
  capability.
- Read [data-and-memory.md](references/data-and-memory.md) for JSON, large
  payloads, serialization, buffering, compression, or allocation-sensitive paths.
- Read [resilience-and-observability.md](references/resilience-and-observability.md)
  for readiness, overload, degradation, shutdown, logging, metrics, or tracing.
- Read [verification.md](references/verification.md) before making correctness,
  performance, throughput, capacity, or stability claims.
- Read [rust.md](references/rust.md) only when Rust is the implementation language.

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
