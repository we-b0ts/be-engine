# Breeze Resource Clients

Use this reference for SDK package ownership and application integration.

## Package Scope

Define packages by reusable remote-resource ownership, not a closed protocol
allowlist. Current and expected examples include:

- `mysql` (`brz-mysql`);
- `redis` (`brz-redis`);
- `memcached` (`brz-memcached`);
- `kafka` (`brz-kafka`);
- `mcq` (`brz-mcq`); and
- `queueservice` (`brz-queueservice`);
- `motan` (`brz-motan`) or another reusable RPC/service transport whose
  resource identity or connection lifecycle is managed through Breeze; and
- future database, cache, queue, messaging, storage, or remote-service
  resources with the same business-independent ownership.

Do not use `brz-*` merely because a class is called an SDK or its traffic
crosses Breeze infrastructure. Logging, serialization, authentication,
metrics, and ordinary provider clients remain with their actual platform or
capability owner. Motan is an explicit business-independent platform resource:
its reusable SDK, protocol, discovery, routing, transport, codec, and
connection lifecycle belong in the Breeze package. Keep only the invoked
business service contract and capability adapter outside. For ordinary HTTP or
provider-specific RPC clients, do not infer Breeze ownership without the same
reusable resource boundary.

Prefer a standalone, versioned Breeze SDK project as the permanent owner. When
an application must carry a transitional local implementation, keep
`crates/breeze/` closed to the same package set and do not duplicate the SDK
across services after a shared dependency exists.

## Package Responsibility

Each resource package owns:

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

Business SQL and table selection, cache keys and cache policy, message topics
and schemas, RPC service interfaces and method semantics, provider DTO
mapping, fallback policy, and cross-resource orchestration stay outside the SDK
in a capability-owned adapter.

For Motan, the Breeze package owns descriptor and node resolution, connection
reuse, framing and generic codec integration, deadline propagation, transport
errors, retries, health, and shutdown. The business capability owns only the
remote business service interface, method inputs and outputs, application
errors, and the decision about when or why to call it.

Do not move a complete business client into Breeze and then hide its domain
coupling behind a generic name. Expose the smallest reusable resource client;
let the business adapter translate it into a capability-facing port.

## Application Integration

Expose logical identity and bounded operation settings to the composition
root. Do not expose arbitrary caller-selected Breeze ports as application
configuration.

Construct long-lived clients once, inject narrow interfaces into capabilities,
reuse connections appropriately, and make startup failure explicit. Keep
health and shutdown behavior observable without leaking descriptor-derived
credentials or committed secret values.

For migration work, preserve source-side identity and dependency semantics
first. A language or framework change is not evidence for changing group,
namespace, topic, protocol, retry, fallback, or lifecycle behavior.
