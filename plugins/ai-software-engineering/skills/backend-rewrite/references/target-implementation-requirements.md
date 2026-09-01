# Target Implementation Requirements

Read this reference only in these situations:

- an assigned API or process-output worker is about to change target product
  code, target startup, or target configuration; or
- the main orchestrator is about to integrate a worker change, resolve an
  integration conflict, or make a shared target refactor.

These requirements apply to an existing initialized target repository. Use
[project-init.md](project-init.md) only for explicit one-time initialization.

## Scope And Compatibility

- Repository instructions and established build, runtime, and module contracts
  are authoritative.
- Preserve the source service's observable API, error, side-effect, ordering,
  configuration, dependency, startup, and shutdown behavior unless the current
  work item proves a narrower intentional difference.
- Change only the current work scope's proven cause and the smallest shared
  boundary required by that repair. Keep unrelated cleanup and repository-wide
  restructuring out of the change.
- Do not silently convert an existing repository to another Cargo workspace or
  package shape. Initialization and explicitly scoped architecture migrations
  own those changes.
- Product behavior must not depend on tests, fixtures, debug branches, or
  developer-only defaults.

## Evidence And Runtime Inputs

- Target product code and configuration MUST NOT read traffic cases, recorded
  responses, Replay sessions, reports, coordinator state, or files below
  `.traffic-e2e/local/`.
- Recorded artifacts are read-only diagnostic evidence. Do not copy their
  values into fixtures, generated startup input, hardcoded responses, or local
  dependency replacements.
- Do not modify source behavior or coordinator evidence to manufacture a
  passing result.
- Never print, persist, or hard-code credentials, private keys, tokens, remote
  configuration values, source-process memory, or generated SDK snapshots.
  A constant proven in source code or a pinned compiled artifact may remain
  source-compatible behavior.
- Keep genuine runtime configuration and dependency retrieval on their normal
  source-compatible loading and refresh paths. Do not replace them with values
  inferred from traffic.

## Runtime Requirements

- Keep async target code on the repository's established runtime. With Tokio,
  blocking filesystem, process, compression, cryptographic, or CPU-heavy work
  requires bounded admission to `spawn_blocking` or a bounded dedicated pool.
- Every queue, buffer, cache, batch, fan-out, task set, and in-flight work
  population MUST have an explicit bound or a proven external bound.
- Every remote operation MUST have a deadline consistent with its caller.
  Retries MUST be limited, idempotency-aware, budget-aware, and observable;
  layered clients MUST NOT multiply retries invisibly.
- Every spawned or background task MUST have an owner, bounded admission, error
  reporting, cancellation behavior, and shutdown behavior.
- Long-lived dependency clients and pools MUST have explicit ownership,
  capacity, reuse, health behavior, and shutdown. Do not construct them per
  request.
- Do not hold a lock guard across remote I/O or another unbounded wait. Any
  guard held across `.await` requires an explicit resource invariant and known
  cancellation behavior.
- Large or externally controlled inputs MUST be bounded before allocation.
  Caches and retained collections MUST define capacity and eviction.
- Preserve operational error categories until retry, observability, and
  external error mapping decisions are complete. Logs and telemetry MUST NOT
  expose secrets, full sensitive payloads, or unbounded-cardinality values.
- Keep `unsafe` behind a narrow safe interface with documented invariants and
  boundary tests. Do not introduce it for an unmeasured performance claim.

### Source Executor And Thread-Pool Submissions

When source code submits fire-and-forget work to an executor or thread pool,
implement the target equivalent with a long-lived worker backed by a bounded
`tokio::sync::mpsc` queue. Complete queue admission before returning from the
request. Do not translate each submitted job into a detached per-job
`tokio::spawn`.

Use `tokio::spawn` only to start the long-lived queue worker during service
startup. Define the queue capacity, full and closed behavior, worker
concurrency, error reporting, cancellation, and shutdown or drain behavior,
and keep each choice compatible with the source submission contract.

## Repository Structure

- A changed product unit and its parent MUST continue to have one clear owner
  and primary reason to change. Do not add catch-all `common`, `utils`,
  `helpers`, `manager`, or equivalent ownership for unrelated behavior.
- Production modules MUST NOT depend on test, fixture, recording, or Replay
  modules.
- Rust product source files under `src/`, `crates/**/src/`, or `apps/**/src/`
  MUST remain at or below 1000 lines. If a touched file already exceeds the
  limit, extract the touched responsibility before adding behavior.
- Run the bundled
  [`check-code-organization`](../scripts/check-code-organization) after the
  final product-code edit when the target repository does not enforce an
  equivalent source-size gate.

Every used Breeze or platform SDK capability MUST be its own workspace package
at `crates/breeze/<capability>` and be exposed through the corresponding
`brz-<capability>` library. Use the canonical capability names `http`,
`memcache`, `redis`, `mysql`, `vintage`, `motan`, `auth`, `mcq`, `kafka`, and
`logs`. `brz-auth` owns authentication SDK implementations, including TAuth
and TAuth2; Memcache-backed MCQ belongs in `brz-mcq`. Product code MUST use the
`brz-*` library rather than a raw SDK or driver. Create only packages the
product uses.

## Verification Ownership

- A worker runs focused local tests for its changed work scope and returns the
  exact work scope and issue ID, proven cause, changed files and shared impact,
  patch or commit, test results, unchanged acceptance command, coordinator
  inputs, and unresolved risks.
- A worker MUST NOT execute coordinator acceptance, advance workflow state, or
  claim that the work item or workflow is complete.
- The main orchestrator integrates the change in the canonical target worktree
  and executes the coordinator-issued target quality and acceptance actions.
  Worker-local checks do not replace those integrated-revision gates.
- Performance, throughput, capacity, scalability, and availability claims
  require measured evidence for the stated workload and environment. Otherwise
  report the property as not measured or as a remaining risk.
