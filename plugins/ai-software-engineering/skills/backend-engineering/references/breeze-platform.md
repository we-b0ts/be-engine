# Breeze Platform Libraries

Use this reference when source or repository evidence assigns a shared
foundation or business-independent remote-resource lifecycle to Breeze.

## Ownership And Layout

Keep Breeze-owned Rust packages under one `breeze/<package>` or
`crates/breeze/<package>` root and name published packages `brz-*`. Classify by
platform ownership, not by protocol name or whether source code calls something
an SDK.

Breeze owns shared logging and authentication foundations and reusable resource
identity, discovery, descriptor, protocol, connection, pool, producer,
consumer, and transport lifecycles. The owning capability retains SQL and
tables, cache keys and cache policy, topics and message schemas, RPC service
interfaces and method semantics, provider mapping, authorization policy,
business fallback, and cross-resource orchestration.

Construct long-lived Breeze clients in the application composition root and
inject a narrow interface into the capability. Apply the normal dependency
client, resilience, observability, and verification references for deadlines,
bounds, retries, health, shutdown, and operational evidence.

For descriptor-backed resources, use one shared descriptor package rather
than resource-specific parsers or launcher-generated addresses; read
[breeze-descriptors.md](breeze-descriptors.md). Keep Motan and Vintage as
sibling packages, let Motan depend on Vintage, and read
[breeze-motan-vintage.md](breeze-motan-vintage.md) before changing either.

## Logging

Place the shared logging foundation at `breeze/log` as `brz-log`. Expose the
platform `trace`, `debug`, `info`, `warn`, `error`, and `access` facade over
`tracing`. Treat `access` as a separately routed structured channel, not an
alias for `info`.

The application composition root initializes the global subscriber once.
Libraries never install or replace it. `brz-log` owns common context,
transport, and redaction defaults; capabilities own their event fields,
metrics, sampling, and alert policy unless a source-proven platform contract
says otherwise.

## TAuth2

Place the shared authentication foundation at `breeze/tauth2` as
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
