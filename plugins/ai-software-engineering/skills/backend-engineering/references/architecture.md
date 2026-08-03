# Large Rust Backend Architecture

Use the repository's observable behavior and current architecture as evidence,
not as an unquestioned target. Design crates, modules, and runtime ownership
from deployable roles, product capabilities, contracts, and lifecycles. Change
the smallest coherent boundary that can own the requested behavior without
extending a catch-all module or leaking infrastructure into business logic.

## Contents

- [Architecture Discovery](#architecture-discovery)
- [Workspace And Deployment Shape](#workspace-and-deployment-shape)
- [Capability Ownership](#capability-ownership)
- [Dependency Direction](#dependency-direction)
- [Application Services](#application-services)
- [Serialization And Contract Boundaries](#serialization-and-contract-boundaries)
- [Runtime Ownership](#runtime-ownership)
- [HTTP, Routing, And Middleware](#http-routing-and-middleware)
- [Configuration Ownership](#configuration-ownership)
- [Composition Root](#composition-root)
- [Compatibility And Scope Control](#compatibility-and-scope-control)
- [Completion Review](#completion-review)

## Architecture Discovery

Before writing product code, inspect and record the relevant architecture:

1. independently deployed HTTP or RPC servers, workers, schedulers, and
   consumers;
2. product capabilities and the routes, methods, jobs, or events they own;
3. data resources, remote services, and third-party systems used by each
   capability;
4. API, RPC, event, and storage serialization contracts;
5. static and dynamic configuration sources and their current owners;
6. startup, readiness, background work, and shutdown responsibilities; and
7. the Cargo workspace, feature selection, crate graph, and binary targets that
   enforce or blur those boundaries.

Map the complete changed capability, its entrypoint, and its direct
dependencies before implementation. For a focused change, do not turn this
mapping into an unrelated repository-wide redesign.

Treat a large source service, application state, dependency list, or legacy
dependency-injection graph as evidence of behavior and coupling, not as a
boundary to reproduce.

## Workspace And Deployment Shape

- Give each independently deployed runtime role a clear binary package. Do not
  combine roles behind a mode flag merely because they share source code; move
  cohesive shared behavior into library crates.
- Keep binary entrypoints focused on configuration loading, dependency
  construction, runtime startup, readiness, and shutdown. Keep business
  behavior in capability-owned library modules or crates.
- Build each binary with only the capabilities and adapters it actually runs.
- Treat test harnesses, benchmarks, migrations, administrative commands, and
  recording or replay targets as tooling unless they are independently
  deployed production roles.
- Prefer one library crate for a cohesive capability and modules for its
  internal roles. Split it into more crates only for independent consumers, a
  distinct lifecycle, or dependency enforcement that cannot remain clear at a
  module boundary.
- Do not create one crate for every source file or type. Crate boundaries add
  build, feature, versioning, and public-API cost.
- Keep crate dependencies acyclic and prevent libraries from depending on
  application packages.

When a repository adopts the Platform workspace standard, keep the primary
product as the root package with both `[package]` and `[workspace]` in the root
`Cargo.toml`, keep its source under root `src/`, put reusable libraries under
`crates/`, and put additional deployable roles under `apps/<role>/`. Do not
silently impose this layout on a repository governed by a different explicit
standard.

In a workspace with a root package, root-level Cargo commands may select only
that package. Repository-wide checks MUST use the repository's canonical
workspace commands or select `--workspace` explicitly.

## Capability Ownership

Organize business behavior by product capability rather than repository-wide
technical layers. A capability may contain:

```text
capability/
├── application/
├── domain/
├── ports/
└── adapters/
```

Use names that match the repository's domain; these role names are examples,
not mandatory directories.

- Let `application` own use-case orchestration.
- Let `domain` own business state, rules, and invariants.
- Let `ports` describe dependencies required by the capability.
- Let `adapters` translate between ports and databases, caches, remote
  services, queues, or wire protocols.

Expose a narrow public facade when other capabilities need the behavior. Do
not let them reach into private repositories, adapters, or internal modules.
Do not create repository-wide `service`, `model`, `common`, `manager`,
`processor`, `helper`, or `utils` crates or modules that collect unrelated
capabilities. Give shared code one precise owner and one cohesive reason to
change.

## Dependency Direction

Keep the logical direction explicit:

```text
transport adapter -> application -> domain and ports
infrastructure adapter -> domain and ports
composition root -> transports, applications, and adapters
```

- Domain code MUST NOT depend on HTTP frameworks, generated wire types,
  resource drivers, remote clients, configuration loaders, or application
  startup.
- Application code MAY depend on domain types and dependency contracts, but
  MUST NOT construct infrastructure clients or read global configuration.
- Infrastructure adapters MAY use approved resource or remote-client crates to
  implement capability dependencies.
- Only the composition root may select concrete implementations and assemble
  the complete runtime graph.
- Capability dependencies MUST remain acyclic. Introduce a higher-level
  orchestrator or extract a lower-level cohesive capability instead of adding
  mutual service dependencies.

Product code MUST NOT import fixtures, recordings, replay logic, or test-only
support. Keep production startup separate from test and E2E orchestration.

## Application Services

Model an application service around one use case or one cohesive use-case
family, not an entire product domain.

- Give it only the collaborators required by that use case and inject them
  explicitly through constructors.
- Keep request parsing, response rendering, wire serialization, configuration
  reads, and client construction outside the service.
- Do not pass a catch-all application context, dependency map, or service
  registry into business code.
- Do not expose another capability's repository as a shortcut around its
  public behavior.
- When one operation coordinates several capabilities, create an application
  orchestrator that owns that workflow instead of making peer services call
  each other in a cycle.

Treat a growing constructor, many unrelated methods, or dependencies used by
only a subset of methods as a boundary-review signal. Split by use case or
sub-capability before extending the service further.

## Serialization And Contract Boundaries

Keep transport, storage, and business representations distinct:

```text
HTTP JSON DTO
    <-> HTTP adapter
application and domain types
    <-> resource or remote-service adapter
Protobuf, RPC, event, or storage types
```

- Keep JSON request and response DTOs in the HTTP adapter.
- Keep generated Protobuf, RPC, event, and storage types in their contract or
  adapter boundary.
- Use transport-independent business types in application and domain
  interfaces.
- Perform explicit conversion at the boundary that owns the external contract.
- Keep business-specific SQL, cache keys, messages, and serialization policy
  with the owning capability adapter, not a generic resource client.
- Do not use a generated contract crate as a repository-wide business model.

When multiple crates consume one stable wire contract, place its source and
generated types in a dedicated contract crate owned by that protocol or
capability. Keep business orchestration and infrastructure lifecycle out of
contract crates.

## Runtime Ownership

Give every long-lived object one clear owner and lifecycle:

- listeners and background tasks;
- database, cache, HTTP, RPC, and queue clients;
- executors, worker pools, queues, and semaphores;
- caches, registries, refreshers, and watchers; and
- temporary files and local subprocesses.

Construct them in dependency order. Reach readiness only when required
listeners and critical dependencies satisfy the product contract. During
shutdown, stop admission, drain or cancel bounded work, flush required state,
and release owned resources within a deadline and in reverse dependency order.

Avoid process-wide mutable globals, hidden singletons, and service locators. If
shared state is required, make ownership, synchronization, mutation, and reset
semantics explicit.

## HTTP, Routing, And Middleware

Register routes explicitly by API version and product capability. Keep route
ownership and middleware ordering visible in code.

Let an HTTP handler own only extraction, transport-level validation, conversion
between DTOs and application inputs, invocation of one application use case,
and conversion of results and errors to HTTP responses. Keep business policy,
data access, remote orchestration, and resource lifecycles out of handlers.

Let middleware own transport-wide context, deadline propagation, tracing,
logging, compression, or admission behavior. It MUST NOT hide business
workflows, direct repository access, or undeclared remote calls. Expose only
handler-facing use-case facades through HTTP state; do not put every service,
client, configuration object, and runtime handle into one catch-all state.

## Configuration Ownership

Centralize configuration source loading while distributing typed ownership:

- Let each component define and validate the configuration for behavior it
  owns.
- Let each binary composition root aggregate the configuration required by
  that deployable.
- Let only the configuration or bootstrap boundary read files, environment
  variables, command-line values, or configuration services.
- Pass each component only its validated configuration or runtime snapshot.
- Keep static startup configuration separate from dynamic configuration.
- Give every dynamic configuration stream one owner, typed snapshots, and
  explicit update behavior.
- Use configuration to select implementations and behavior, not to describe an
  arbitrary object graph equivalent to a dependency-injection container.

Reject invalid or incomplete combinations before readiness. Keep secrets out
of committed defaults. Avoid stringly typed names, implicit defaults scattered
across consumers, and multiple components independently parsing the same
source.

## Composition Root

Construct dependencies explicitly in each binary:

1. load and validate configuration;
2. create shared runtime resources;
3. create data-resource and remote-service clients;
4. create repositories and infrastructure adapters;
5. create application services and orchestrators;
6. create transport handlers, routers, workers, and schedulers;
7. start admission only after required dependencies are ready; and
8. stop admission and shut down owned resources in reverse dependency order.

Split large wiring code into capability-focused builder modules while keeping
the final graph visible from the binary. Return typed components from builders;
do not register them in a global container. Use explicit enums or optional
dependencies for configuration-selected implementations and validate the
selection before construction. Avoid hidden lazy initialization unless the
component contract explicitly requires and owns it.

## Compatibility And Scope Control

Preserve externally observable API, error, side-effect, ordering, and
compatibility behavior unless the user approves a contract change. Version a
contract when old and new consumers must coexist. Do not use internal cleanup
as justification for an accidental wire-format or error-semantics change.

Refactor a relevant legacy boundary when the requested behavior would otherwise
make ownership or failure handling materially worse. Do not combine that with
unrelated repository-wide cleanup. Apply code-organization and size gates as
backstops while splitting by responsibility rather than line count alone.

## Completion Review

Before accepting an architecture or implementation, confirm that:

1. every independently deployed role has a clear binary owner;
2. product code is organized by capability rather than catch-all technical
   crates;
3. binary entrypoints contain wiring and lifecycle but no business behavior;
4. crate and module dependencies follow the declared acyclic direction;
5. application services have narrow, explicit collaborators;
6. transport and generated wire or storage types do not leak into application
   or domain interfaces;
7. resource and remote clients are constructed once by an explicit owner;
8. routes and middleware ordering are visible;
9. configuration loading is centralized and component configuration is typed;
10. startup, readiness, background work, and shutdown have explicit owners;
11. workspace-wide checks include every relevant member package; and
12. no global service locator, dependency registry, or catch-all application
    context bypasses the intended boundaries.

Report each deliberate exception with its owner, reason, and affected
dependency direction. Do not claim that an architecture is suitable merely
because it compiles or reproduces one source route.
