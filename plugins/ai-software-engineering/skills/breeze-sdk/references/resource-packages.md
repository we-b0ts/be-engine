# Breeze Remote-Resource Packages

Use this reference for business-independent remote-resource package ownership
and application integration.

## Contents

- Package scope
- Package responsibility
- Application integration

## Package Scope

Define packages by reusable remote-resource ownership, not a closed protocol
allowlist. Current and expected examples include:

- `mysql` (`brz-mysql`);
- `redis` (`brz-redis`);
- `memcached` (`brz-memcached`);
- `kafka` (`brz-kafka`);
- `mcq` (`brz-mcq`);
- `queueservice` (`brz-queueservice`);
- `motan` (`brz-motan`) or another reusable RPC/service transport whose
  resource identity or connection lifecycle is managed through Breeze;
- `vintage`, the reusable discovery library used by Motan and other
  infrastructure clients; and
- future database, cache, queue, messaging, storage, and remote-service
  resources with the same business-independent ownership.

Do not use `brz-*` merely because a class is called an SDK or is reusable.
Include it when Breeze owns the business-independent resource lifecycle. Motan
is an explicit platform resource: its reusable SDK, protocol, discovery,
routing, transport, codec, and connection lifecycle belong in the Breeze
package. Keep only the invoked business service contract and capability
adapter outside.

## Package Responsibility

Each descriptor-backed remote-resource package owns:

- typed logical resource identity;
- shared descriptor resolution and permitted registration;
- client, pool, producer, or consumer construction and reuse;
- generic discovery, routing, channel, transport, and protocol lifecycle when
  applicable;
- bounded connection and operation timeouts;
- resource-specific retry and health behavior;
- enablement and configuration validation; and
- orderly shutdown.

The shared descriptor layer owns filename parsing, identity matching, locking,
port selection, atomic creation, and listener readiness. Resource packages
must not implement divergent copies.

Use the shared descriptor layer as a library dependency of each resource
package. Do not expose it as a production startup executable that a project
CLI must call before constructing resource clients.

Business SQL and table selection, cache keys and cache policy, message topics
and schemas, RPC service interfaces and method semantics, provider DTO
mapping, fallback policy, and cross-resource orchestration stay outside the SDK
in a capability-owned adapter.

For Motan, the Breeze package owns descriptor and node resolution, connection
reuse, framing and generic codec integration, deadline propagation, transport
errors, retries, health, and shutdown. The business capability owns only the
remote business service interface, method inputs and outputs, application
errors, and the decision about when or why to call it.

Keep Motan and Vintage as separate sibling libraries under the Breeze package
root, and let Motan depend on Vintage. Read
[motan-vintage.md](motan-vintage.md) before implementing either library.

Do not move a complete business client into Breeze and then hide its domain
coupling behind a generic name. Expose the smallest reusable resource client;
let the business adapter translate it into a capability-facing port.

## Application Integration

For descriptor-backed remote resources, expose logical identity and bounded
operation settings in the composition root; do not expose arbitrary
caller-selected Breeze ports as application configuration.

Use this shape for descriptor-backed resources:

```text
composition root declares ResourceIdentity
  -> brz-<resource> receives identity, DescriptorPolicy, and client options
  -> brz-<resource> resolves or registers through the descriptor library
  -> brz-<resource> constructs and returns the long-lived client
```

The consuming application owns which logical resources it needs. The resource
SDK owns how each identity becomes a Breeze endpoint and client. Adding a
resource may change the application composition root and capability adapter;
it must not require a new project-CLI branch, resolver invocation, or
descriptor-derived address variable.

Construct long-lived clients once, inject narrow interfaces into capabilities,
reuse connections appropriately, and make startup failure explicit. Keep
health and shutdown behavior observable without leaking descriptor-derived
credentials or committed secret values.

For migration work, preserve source-side identity and dependency semantics
first. A language or framework change is not evidence for changing group,
namespace, topic, protocol, retry, fallback, or lifecycle behavior.
