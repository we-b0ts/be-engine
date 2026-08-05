---
name: backend-engineering
description: "Design, implement, modify, or review large production Rust backend systems using coding, code-organization, module-ownership, architecture, runtime-safety, and verification standards. Use only when Rust is the target implementation language and the backend has or is expected to have substantial architecture such as multiple capabilities, deployable roles, dependency clients, API or data contracts, background runtimes, or complex configuration. Apply to focused target-code work within those systems as well as cross-cutting architecture work; do not use for non-Rust target code. This skill owns engineering quality, not task sequencing, external evidence gates, or delivery orchestration."
---

# Large Rust Backend Engineering

Build large Rust backend systems that remain correct and operable under
concurrency, dependency failures, large payloads, sustained load, and evolving
capability boundaries. Treat performance, throughput, and stability as
measurable system properties, not adjectives that can be claimed from code
inspection alone.

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

1. Inspect the repository instructions, Cargo workspace, crate and module
   ownership, normal startup, configuration, async runtime, tests,
   observability, and the exact path being changed. Identify whether the path
   is latency-sensitive, throughput-sensitive, memory-sensitive, stateful, or
   failure-critical.
2. State the observable contract, expected workload when known, external
   dependencies, side effects, and failure semantics. Mark unknown capacity
   inputs as assumptions; do not fabricate exact traffic or latency targets.
3. Establish resource budgets before adding concurrency: request and job
   deadlines, maximum in-flight work, queue bounds, connection ownership,
   payload limits, and shutdown behavior.
4. Choose the smallest design that preserves clear ownership and dependency
   direction. Reuse the repository's established runtime, frameworks, crates,
   and clients unless evidence justifies a change.
5. Implement success, overload, timeout, cancellation, and dependency-failure
   paths together. Do not postpone failure behavior until after the happy path.
6. Verify correctness and operational properties in proportion to risk. Use
   targeted tests for local behavior and measured evidence for material
   performance or capacity claims.
7. Review the final implementation again for unbounded work, detached tasks,
   retry multiplication, avoidable cloning or allocation, blocking on async
   executor threads, resource leaks, missing observability, and accidental
   behavior changes.

Read-only inspection of an available authorized runtime is allowed when
repository files do not establish effective configuration or startup behavior.
Inspect only necessary configuration, environment variable names and
provenance, startup arguments, deployment metadata, and dependency wiring.
Never print or persist secret values observed in source-process memory. Never
manually dump or persist values obtained from a remote system. Configuration
or discovery-service snapshots MUST NOT be read, copied, or used as application
startup input, including snapshots managed by the source SDK. Keep runtime
state in memory and use its genuine retrieval and refresh path. Never hard-code
externally supplied secrets. A constant present in the source repository or
pinned compiled artifact may be migrated directly into target source code as
source behavior. Do not replace a genuine runtime dependency with an
environment variable inferred from traffic.

## Non-Negotiable Baseline

- Every newly created backend repository MUST be a Cargo workspace with the
  primary product as the root package, reusable libraries under `crates/`, and
  additional deployable roles under `apps/<role>/`. Every third-party
  dependency version and source and every internal path dependency MUST be
  declared in root `[workspace.dependencies]` and inherited by root and member
  packages. Existing non-workspace repositories require an explicitly scoped
  migration rather than a silent conversion during focused work.
- Access to MySQL, Redis, Memcached, Kafka, Queue, TAuth2, Vintage, and Motan,
  plus shared logging and runtime switches, MUST go through the canonical
  `crates/breeze/<package>` library named `brz-<package>`. Product packages MUST
  NOT depend directly on the corresponding raw driver or SDK.
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

## Rust Runtime Baseline

- Keep async code on the repository's established runtime. With Tokio, move
  blocking filesystem, process, compression, cryptographic, or CPU-heavy work
  behind bounded admission to `spawn_blocking` or a dedicated pool.
- Give every spawned task an owner through its parent future, a task set,
  cancellation mechanism, or supervisor. Detached tasks still require bounded
  admission, error reporting, and shutdown behavior.
- Do not hold synchronous or asynchronous lock guards across `.await` unless
  the protected resource requires it and the resulting contention and
  cancellation behavior are understood.
- Do not add `clone()`, `Arc`, boxing, or owned conversion merely to satisfy the
  compiler. Review retained memory, aliasing, synchronization, and hot-path
  allocation before widening ownership.
- Preserve error sources and operational categories with typed errors or
  contextual chains. Keep timeouts, overload, protocol failures, and remote
  application failures distinguishable until retry, observability, and
  external error mapping decisions are complete.
- Keep `unsafe` isolated behind a narrow safe interface, document its safety
  invariants, and test the boundary. Do not introduce it for speculative
  performance gains.

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
  or reviewing product code. Run its bundled organization checker after the
  final product-code edit and before commit, then again at the prescribed MR
  boundary.
- Read [architecture.md](references/architecture.md) before modifying or
  reviewing product code to map workspace shape, deployable roles, capability
  ownership, dependency direction, contracts, configuration, and runtime
  composition.
- Read [concurrency-and-backpressure.md](references/concurrency-and-backpressure.md)
  when adding async work, threads, queues, batching, fan-out, or background work.
- Read [breeze-platform.md](references/breeze-platform.md) whenever a change
  touches shared logging, runtime switches, MySQL, Redis, Memcached, Kafka,
  Queue, TAuth2, Vintage, Motan, or another Breeze-owned platform foundation or
  remote-resource, runtime-configuration, or discovery lifecycle.
- Read [data-and-memory.md](references/data-and-memory.md) for JSON, large
  payloads, serialization, buffering, compression, or allocation-sensitive paths.
- Read [resilience-and-observability.md](references/resilience-and-observability.md)
  for readiness, overload, degradation, shutdown, logging, metrics, or tracing.
- Read [verification.md](references/verification.md) before making correctness,
  performance, throughput, capacity, or stability claims.

## Completion Review

Before claiming completion, confirm that:

1. a newly created backend satisfies the mandatory Cargo workspace shape and
   workspace-owned dependency rules;
2. every touched common service and runtime switch uses its canonical
   `crates/breeze/<package>` boundary without a product-level raw driver or SDK
   dependency;
3. repository-required `cargo fmt`, build or check, test, Clippy, and other
   static-analysis gates pass for the affected workspace scope;
4. normal startup and shutdown remain valid for runnable components;
5. resource bounds, deadlines, retries, cancellation, and dependency ownership
   are explicit on every changed runtime path;
6. large data and hot paths do not introduce avoidable copies, unbounded
   buffering, high-cardinality telemetry, or blocking work on async executors;
7. failure and overload behavior are tested or otherwise evidenced where they
   can affect correctness or availability;
8. performance claims include a benchmark, load test, production-equivalent
   observation, or an explicitly limited analytical claim;
9. the final structure owns the responsibilities introduced by the change and
   leaves unrelated legacy cleanup untouched.

If required evidence is unavailable, report the assumption or remaining risk.
Do not describe the implementation as high-performance, high-throughput,
scalable, or highly available without corresponding evidence.
