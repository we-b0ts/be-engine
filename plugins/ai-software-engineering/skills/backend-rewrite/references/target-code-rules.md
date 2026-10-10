# Target Code Rules

Read before changing assigned target product code, startup, configuration, or
integration code. These rules apply to the code author and integrator.

These rules apply only to an existing initialized target repository.

## SDK Contracts

Read the relevant reference before defining, changing, or reviewing a client,
listener, lifecycle, startup, or configuration contract. Load only affected SDKs:

- Inbound HTTP or an `http-server` listener: [http-server.md](sdk/http-server.md).
- Outbound HTTP through `brz-http`: [http-client.md](sdk/http-client.md).
- Motan service export: [motan-exporter.md](sdk/motan-exporter.md).
- Motan dependency calls: [motan-referer.md](sdk/motan-referer.md).
- Memcache `CacheService`: [memcache.md](sdk/memcache.md).
- `brz-redis`: [redis.md](sdk/redis.md).
- `brz-mysql`: [mysql.md](sdk/mysql.md).
- Application logging through `brz-logs`: [logs.md](sdk/logs.md).

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
- `.traffic-e2e/Dockerfile.source` and `.traffic-e2e/Dockerfile.target` remain
  target-owned build contracts. Change either when the current work scope
  requires source-adaptor integration for diagnostic preflight or
  target-runtime integration; the assigned code author owns their contents.
  Standalone standard capture uses the separate project-owned `.traffic-e2e/Dockerfile.recording`.
- A `project.delivery.managed_paths` object with `build_context` exposes its
  declared directory as a BuildKit named context. Use that exact name through
  `COPY --from` or `RUN --mount=from`; never use `COPY ../...` or assume that an
  undeclared sibling is visible to the target build.
- Product behavior must not depend on tests, fixtures, debug branches, or
  developer-only defaults.

## Evidence And Runtime Inputs

- Target product code and configuration MUST NOT read traffic cases, recorded
  responses, Replay sessions, reports, engine state, or files below
  `.traffic-e2e/local/`.
- Recorded artifacts are read-only diagnostic evidence. Do not copy their
  values into fixtures, generated startup input, hardcoded responses, or local
  dependency replacements.
- Do not modify source behavior or engine evidence to manufacture a
  passing result.
- When source behavior proves that implemented target logic requires an
  application-owned environment variable, preserve the runtime lookup and
  include the source-proven startup requirement in the result. Do not wait for
  a connection or startup failure or hardcode the effective value.
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
- Changed `tokio::spawn` calls require evidence of initialization ownership.
  Trace the startup entry, call chain and all callers; registering a request
  callback in `main` does not make its execution initialization-owned.
  Request-triggered spawning is prohibited even when its handle is immediately
  awaited. Unknown ownership cannot pass review. Submit startup evidence through
  the [source review contract](source-review-rules.md), not a prose assertion alone.
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

### Rust Data Representation And Allocation

- Prefer dedicated `Serialize` and `Deserialize` structs and typed maps where
  practical.
- Avoid unnecessary allocations and copies. Do not introduce intermediate
  `String`, `Vec`, owned collections, `clone`, `to_owned`, `format!`, or
  serialize-then-deserialize steps when direct construction, streaming, buffer
  reuse, or borrowing is sufficient.
- Prefer borrowed values and explicit lifetimes, such as `&str` and `&[u8]`,
  when data does not need independent ownership. Use owned values at genuine
  ownership boundaries such as spawned tasks, queues, caches, or persistence,
  or when borrowing would make the interface less safe or substantially more
  complex.

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
  MUST remain at or below 1000 complete physical lines, including comments,
  blank lines and the last line without a trailing newline. This is the whole
  changed file's size, not the diff size. If a touched file already exceeds the
  limit, extract the touched responsibility before adding behavior.

Every used Breeze or platform SDK capability MUST be added as a Git dependency
pinned to its documented release tag and exposed through the corresponding
`brz-<capability>` dependency name. Use the canonical capability names `http`,
`memcache`, `redis`, `mysql`, `vintage`, `motan`, `auth`, `mcq`, `kafka`, and
`logs`. `brz-auth` owns authentication SDK implementations, including TAuth
and TAuth2; Memcache-backed MCQ belongs in `brz-mcq`. Product code MUST use the
`brz-*` dependency rather than a raw SDK or driver. Add only dependencies the
product uses.

## Validation

Validate changed behavior with focused local checks. Preserve the exact checked
code and evidence identity in your result. Follow your role's delivery protocol
for its required reports; local success does not establish formal acceptance.

- Performance, throughput, capacity, scalability, and availability claims
  require measured evidence for the stated workload and environment. Otherwise
  report the property as not measured or as a remaining risk.
