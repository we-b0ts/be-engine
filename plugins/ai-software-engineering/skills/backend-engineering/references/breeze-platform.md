# Breeze Platform Libraries

Use this reference whenever a backend uses shared logging, runtime switches,
MySQL, Redis, Memcached, Kafka, Queue, TAuth2, Vintage, Motan, or another
Breeze-owned foundation or business-independent remote-resource lifecycle.

## Ownership And Layout

Whenever the backend uses a Breeze-owned common capability, it MUST create one
independent library package at `crates/breeze/<capability>` named
`brz-<capability>`. This applies equally to logging, MySQL, Redis, Memcached,
Kafka, Queue, TAuth2, Vintage, Motan, and runtime switches; use `log`, `mysql`,
`redis`, `memcache`, `kafka`, `queue`, `tauth2`, `vintage`, `motan`, and
`switch` as their respective capability names. Create only packages used by
the product, and classify additional packages by platform ownership rather
than merely by protocol name or whether source code calls something an SDK.

Breeze owns shared logging and authentication foundations and reusable resource
identity, discovery, descriptor, protocol, connection, pool, producer,
consumer, and transport lifecycles. The owning capability retains SQL and
tables, cache keys and cache policy, topics and message schemas, RPC service
interfaces and method semantics, provider mapping, authorization policy,
business fallback, and cross-resource orchestration.

Only the corresponding `brz-*` package may depend on the raw driver, protocol
crate, or source-compatible SDK for a capability covered by this policy.
Product applications and capability adapters MUST depend on the `brz-*`
package instead. Domain and application interfaces remain platform-independent;
inject a narrow capability port rather than leaking a Breeze or driver type
into business logic.

Construct long-lived Breeze clients in the application composition root and
inject a narrow interface into the capability. Apply the resilience,
observability, and verification rules for deadlines, bounds, retries, health,
shutdown, and operational evidence.

When Redis or Memcached is accessed through Data Mesh or Breeze at
`127.0.0.1`, the local proxy port MUST be resolved from `/data1/breeze/socks`
before establishing the connection; it is not a fixed business configuration
value. Business configuration provides the logical resource identity, which
may include registry or domain, group, namespace, optional topic, and resource
type. `brz-redis` and `brz-memcache` use this identity to select the
corresponding descriptor, read the port from its `<socket-type>:<port>` field,
and connect to `127.0.0.1:<port>`. Descriptor filenames use these forms:

```text
<domain>+3+config+v1+<group>+all:<namespace>@<socket-type>:<port>@<protocol>
<domain>+3+config+cloud+<type-code>+<group>+<namespace>[#<topic>]@<socket-type>:<port>@<protocol>
```

For example:

```text
static.config.api.demo.test+3+config+cloud+redis+user+alchemy_userdata@redis:9302@rs
```

Business code does not read the descriptor directory, configure the resolved
port directly, or hard-code a previously observed local proxy port.

Configuration returned by Vintage or another runtime configuration service
MUST NOT be hard-coded into source code or committed configuration. A Vintage
or other configuration-service snapshot MUST NOT be read or copied as
application startup input; startup uses the genuine runtime configuration
path.

## Logging

Place the shared logging foundation at `crates/breeze/log` as `brz-log`.
Expose the platform `trace`, `debug`, `info`, `warn`, `error`, and `access`
facade over `tracing`. Treat `access` as a separately routed structured
channel, not an alias for `info`.

The application composition root initializes the global subscriber once.
Libraries never install or replace it. `brz-log` owns common context,
transport, and redaction defaults; capabilities own their event fields,
metrics, sampling, and alert policy unless a source-proven platform contract
says otherwise.

## TAuth2

Place the shared authentication foundation at `crates/breeze/tauth2` as
`brz-tauth2`. Preserve the pinned source implementation's token acquisition,
parsing, claims, signature verification, expiry, refresh, and failure
semantics.

Keep remotely fetched tokens and derived verification state in memory. Do not
create an SDK-owned token snapshot or derive startup configuration from process
memory, remote responses, logs, or diagnostics. An authoritative supplied
authentication or seed configuration root remains configuration and must use
the source-compatible loader.

Keep endpoint authorization policy, whitelists, and capability-specific error
mapping outside `brz-tauth2`. Verify initialization, refresh, expiry and
failure behavior, and that no derived token state is persisted.

## Acceptance

Confirm that every used Breeze capability has exactly one workspace package at
its required path and package name, only that package depends on its raw driver
or SDK, and product behavior reaches it through a narrow owned boundary.
