# Large Rust Backend Architecture

Use this reference for platform backends whose complexity spans multiple
deployable roles, product capabilities, dependency clients, API surfaces, data
contracts, or configuration domains. Preserve observable behavior during a
rewrite, but do not reproduce legacy package structure, dependency injection,
or catch-all service boundaries without validating their ownership.

## Contents

- [Architecture Discovery](#architecture-discovery)
- [Workspace And Deployment Shape](#workspace-and-deployment-shape)
- [Capability Ownership](#capability-ownership)
- [Dependency Direction](#dependency-direction)
- [Application Services](#application-services)
- [Serialization And Contract Boundaries](#serialization-and-contract-boundaries)
- [Infrastructure Resources And Remote Services](#infrastructure-resources-and-remote-services)
- [HTTP, Routing, And Middleware](#http-routing-and-middleware)
- [Configuration Ownership](#configuration-ownership)
- [Composition Root](#composition-root)
- [Completion Review](#completion-review)

## Architecture Discovery

Before writing product code, inspect and record the relevant architecture:

1. independently deployed HTTP servers, RPC servers, workers, schedulers, and
   consumers;
2. product capabilities and the routes, RPC methods, jobs, or events they own;
3. data resources, remote services, and third-party systems used by each
   capability;
4. API, RPC, event, and storage serialization contracts;
5. static and dynamic configuration sources and their current owners;
6. startup, readiness, background work, and shutdown responsibilities.

Propose the target workspace packages and their dependency direction from this
evidence before implementing a capability. For a focused change, map the
complete changed capability, its entrypoint, and its direct dependencies rather
than attempting an unrelated repository-wide redesign.

Treat the source layout as behavior evidence, not as the target architecture.
A large source service, XML context, application state, or dependency list does
not justify recreating the same boundary.

## Workspace And Deployment Shape

- Every platform backend repository has one primary product package. Keep that
  package at the repository root: use both `[package]` and `[workspace]` in the
  root `Cargo.toml`, keep the primary product under root `src/`, and place its
  library dependencies under `crates/`.
- Do not create a virtual workspace or move the primary package under `apps/`.
- Put each additional independently deployed runtime role in a separate binary
  package, conventionally under `apps/<role>/`.
- Test harnesses, benchmarks, migrations, administrative commands, and local
  recording or replay targets are not additional runtime roles merely because
  they are separate binary targets.
- Keep binary targets and their entrypoint modules limited to configuration
  loading, dependency construction, runtime startup, readiness, and shutdown.
  Put business behavior in capability-owned library modules or packages.
- Put reusable product and platform libraries under `crates/`, organized from
  stable owner or product capability to implementation role.
- Do not make a library depend on an application package.
- Do not combine independently deployed roles in one binary behind a mode flag
  merely because they share source code. Move shared behavior into libraries.
- Build each binary with only the capabilities and adapters it actually runs.

In a workspace with a root package, Cargo commands at the repository root
select that root package by default. Repository-wide checks MUST explicitly
select the workspace, for example with `cargo test --workspace` and
`cargo clippy --workspace --all-targets`, unless the repository provides
stricter equivalent commands.

Prefer one library package for a cohesive capability and modules for its
internal roles. Split a capability into additional packages only when it has
independent consumers, a distinct lifecycle, or a boundary that materially
improves dependency enforcement. Do not create one package for every source
file or type.

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

Use the names that accurately describe the repository's domain; the example
roles are not mandatory directory names.

- `application` owns use-case orchestration.
- `domain` owns business state, rules, and invariants.
- `ports` describe dependencies required by the capability.
- `adapters` translate between ports and databases, caches, remote services,
  queues, or wire protocols.

Do not create repository-wide `service`, `model`, `common`, `manager`,
`processor`, `helper`, or `utils` packages that collect unrelated
capabilities. Shared code needs one precise owner and one cohesive reason to
change.

A capability may expose a narrow public facade. Other capabilities MUST NOT
reach into its private repositories, adapters, or internal modules.

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
- Infrastructure adapters implement capability dependencies and MAY use the
  approved resource or remote-client packages.
- Only the composition root may select concrete implementations and assemble
  the complete runtime graph.
- Capability dependencies MUST remain acyclic. Introduce a higher-level
  orchestrator or extract a lower-level cohesive capability instead of adding
  mutual service dependencies.

## Application Services

Model an application service around one use case or one cohesive use-case
family, not an entire product domain.

- Give the service only the collaborators required by that use case.
- Inject collaborators explicitly through constructors.
- Keep request parsing, response rendering, wire serialization, and client
  construction outside the service.
- Do not pass a catch-all application context, dependency map, or service
  registry into business code.
- Do not expose another capability's repository as a shortcut around its
  public behavior.
- When one operation coordinates several capabilities, create an application
  orchestrator that owns that workflow instead of making peer services call
  each other in a cycle.

A growing constructor, many unrelated methods, or dependencies used by only a
small subset of methods are boundary-review signals. Split by use case or
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
- Application and domain interfaces MUST use transport-independent business
  types.
- Perform explicit conversion at the boundary that owns the external
  contract.
- Keep business-specific SQL, cache keys, Protobuf messages, and serialization
  policy with the owning business adapter, not a generic resource client.
- Do not use a generated contract package as a repository-wide business model
  package.

When multiple packages consume one stable wire contract, place its source and
generated types in a dedicated contract package owned by that protocol or
capability. Keep business orchestration and infrastructure lifecycle out of
contract packages.

## Infrastructure Resources And Remote Services

Use repository-approved packages for shared database, cache, and messaging
infrastructure. Business repositories and adapters depend on those packages
without constructing another client, pool, resolver, producer, or retry layer.

Represent every internal or third-party remote system through a named client
or adapter boundary:

- Name the boundary after the remote capability or provider, not merely
  `http`, `rpc`, or `client`.
- Group multiple remote interfaces only when they share one provider,
  configuration, lifecycle, and compatibility contract.
- Keep discovery, protocol types, connection lifecycle, request policy, and
  remote error classification inside the remote-client boundary.
- Expose a typed capability interface to application code.
- Do not pass raw HTTP, RPC, or generated client objects into application
  services.

If a remote client is reused by multiple deployables, make it a library
package. If it is local to one capability, it may remain an adapter module
while preserving the same dependency boundary.

## HTTP, Routing, And Middleware

Register routes explicitly by API version and product capability. Keep route
ownership visible from code.

An HTTP handler owns only:

- path, query, header, and body extraction;
- transport-level validation;
- conversion from JSON DTOs to application inputs;
- invocation of one application use case;
- conversion of results and errors to HTTP responses.

Keep business decisions, data access, remote orchestration, and resource
lifecycles out of handlers.

Define the middleware or filter stack in one visible composition location and
make ordering explicit. Middleware may own transport-wide request context,
deadline propagation, tracing, logging, compression, or admission behavior.
It MUST NOT hide business workflows, direct repository access, or undeclared
remote calls.

Expose only handler-facing use-case facades through HTTP state. Do not put every
service, resource client, configuration object, and runtime handle into one
catch-all application state.

## Configuration Ownership

Centralize configuration source loading while distributing typed ownership:

- Each component defines the typed configuration and validation for the
  behavior it owns.
- Each binary composition root aggregates the configuration required by that
  deployable.
- Only the configuration/bootstrap boundary reads files, environment
  variables, command-line values, or configuration services.
- Pass each component only its validated configuration or runtime snapshot.
- Business code MUST NOT read global property maps or configuration sources.
- Keep static startup configuration separate from dynamic configuration.
- Give every dynamic configuration stream one owner, typed snapshots, and
  explicit update behavior.
- Configuration selects implementations and behavior; it MUST NOT describe an
  arbitrary object graph equivalent to a dependency-injection container.

Reject invalid or incomplete combinations before readiness. Avoid stringly
typed bean names, implicit defaults scattered across consumers, and multiple
components independently parsing the same source.

## Composition Root

Construct dependencies explicitly in each binary:

1. load and validate the binary's configuration;
2. create shared runtime resources;
3. create data-resource and remote-service clients;
4. create repositories and infrastructure adapters;
5. create application services and orchestrators;
6. create transport handlers, routers, workers, and schedulers;
7. start admission only after required dependencies are ready;
8. stop admission and shut down owned resources in reverse dependency order.

Split large wiring code into capability-focused builder modules while keeping
the final graph visible from the binary. Builders return typed components; they
MUST NOT register objects in a global container.

Use explicit enums or optional dependencies for configuration-selected
implementations. Validate the selection before construction. Avoid hidden lazy
initialization unless the component contract explicitly requires and owns it.

## Completion Review

Before accepting an architecture or implementation, confirm that:

1. the primary product is the root package and the root `Cargo.toml` contains
   both `[package]` and `[workspace]`;
2. every independently deployed role has a clear binary owner;
3. product code is organized by capability rather than catch-all technical
   packages;
4. binary entrypoints contain wiring and lifecycle but no business behavior;
5. crate and module dependencies follow the declared acyclic direction;
6. application services have narrow, explicit collaborators;
7. HTTP JSON and generated wire or storage types do not leak into application
   or domain interfaces;
8. resource and remote clients are constructed once by an explicit owner;
9. routes and middleware ordering are visible;
10. configuration loading is centralized and component configuration is typed;
11. workspace-wide checks include every member package;
12. no global service locator, dependency registry, or catch-all application
    context bypasses the intended boundaries.

Report any deliberate exception with its owner, reason, and affected
dependency direction. Do not claim that a target architecture is suitable
merely because it compiles or reproduces one source route.
