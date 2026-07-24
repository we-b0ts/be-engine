# Backend Architecture And Ownership

Use the repository's architecture as evidence, not as an unquestioned
precedent. Change the smallest coherent boundary that can own the requested
behavior without extending a catch-all module or leaking infrastructure into
business logic.

## Boundaries

Keep these responsibilities separable even when a small service initially puts
them in one package:

- transport and protocol adaptation;
- application orchestration and policy;
- domain or wire models;
- dependency adapters and persistence;
- configuration and startup wiring;
- diagnostics and operational lifecycle;
- test and E2E orchestration.

Dependency direction should point from volatile boundaries toward stable
business contracts. Product code MUST NOT import fixture, recording, replay, or
test-only support. Entrypoints should wire components rather than accumulate
business behavior.

Do not create an abstraction before it has a real consumer or variation, but do
not hide unrelated responsibilities behind a generic `util`, `common`,
`manager`, or `service` module. Prefer names derived from the product domain and
runtime responsibility.

## Runtime Ownership

Every long-lived object needs one clear owner and lifecycle:

- listeners and background tasks;
- database, cache, HTTP, RPC, and queue clients;
- executors, worker pools, queues, and semaphores;
- caches, registries, refreshers, and watchers;
- temporary files and local subprocesses.

Startup must construct them in dependency order. Readiness must mean required
listeners and critical dependencies are usable according to the product
contract. Shutdown must stop admission, drain or cancel bounded work, flush
required state, and release owned resources within a deadline.

Avoid process-wide mutable globals and hidden singletons. If shared state is
required, make ownership, synchronization, mutation, and reset semantics
explicit.

## Configuration And Compatibility

Use the repository's typed configuration path and precedence rules. Keep
secrets outside committed defaults. Reject invalid combinations at startup
rather than failing later on a hot path.

Preserve externally observable API, error, side-effect, ordering, and
compatibility behavior unless the user approves a contract change. Version a
contract when old and new consumers must coexist. Do not use internal cleanup
as justification for an accidental wire-format or error-semantics change.

## Scope Control

Refactor a relevant legacy boundary when the requested behavior would otherwise
make ownership or failure handling materially worse. Do not combine that with
unrelated repository-wide cleanup. Follow local file-size rules; absent such a
rule, split by responsibility and reviewability rather than an arbitrary line
count.
