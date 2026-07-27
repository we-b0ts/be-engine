# Breeze Resource Clients

Use this reference for SDK package ownership and application integration.

## Package Scope

The supported resource package set is:

- `mysql` (`brz-mysql`);
- `redis` (`brz-redis`);
- `memcached` (`brz-memcached`);
- `kafka` (`brz-kafka`);
- `mcq` (`brz-mcq`); and
- `queueservice` (`brz-queueservice`).

Do not use `brz-*` for Motan, HTTP, or other RPC and service clients merely
because their traffic crosses Breeze infrastructure. Those clients remain
provider- or capability-owned.

Prefer a standalone, versioned Breeze SDK project as the permanent owner. When
an application must carry a transitional local implementation, keep
`crates/breeze/` closed to the same package set and do not duplicate the SDK
across services after a shared dependency exists.

## Package Responsibility

Each resource package owns:

- typed logical resource identity;
- shared descriptor resolution and permitted registration;
- client, pool, producer, or consumer construction and reuse;
- bounded connection and operation timeouts;
- resource-specific retry and health behavior;
- enablement and configuration validation; and
- orderly shutdown.

The shared descriptor layer owns filename parsing, identity matching, locking,
port selection, atomic creation, and listener readiness. Resource packages
must not implement divergent copies.

Business SQL, cache keys, messages, serialization, fallback policy, and
capability behavior stay outside the SDK in the owning application module.

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
