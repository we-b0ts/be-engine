<!-- BEGIN PLATFORM BREEZE RESOURCE DEVELOPMENT -->
## Platform Breeze Resource Development

Before creating or modifying a `brz-*` package, any code under
`crates/breeze/`, or runtime wiring for a Platform database, cache, or
messaging resource, read
[docs/breeze-resource-development.md](docs/breeze-resource-development.md)
completely and follow it as a repository contract.

Do not add non-allowlisted packages under `crates/breeze/`. During independent
service startup, reuse the exact resource descriptor when present; only when it
is absent may the service allocate a random eligible port and create a
format-compatible descriptor for Breeze to load. During replay, require the
recording-created descriptor, read its exact port, and never allocate a port or
create, rewrite, rename, or delete a descriptor.
<!-- END PLATFORM BREEZE RESOURCE DEVELOPMENT -->
