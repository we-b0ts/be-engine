# Configuration Compatibility

Use this reference before implementing target configuration loading or
accepting target startup as migration-compatible.

## Contract

Treat the source service's configuration as an external runtime contract.
Rewrite code and internal configuration structures when useful, but make the
target consume the same authoritative configuration artifacts and compatible
formats.

Preserve every configuration behavior that can affect the migrated capability
or service startup:

- externally supplied formats and configuration keys;
- parsing, interpolation, defaulting, required-value, and validation semantics;
- source-defined selection, layering, override, and precedence behavior;
- behavior-relevant startup, refresh, and dynamic-reload semantics.

## Discover The Source Loader

Trace configuration from the source startup path to its consumers:

```text
entrypoint and runtime inputs -> loader and source artifacts -> selection and
merge behavior -> parsed key or structure -> behavior-driving consumer
```

Search source build and deployment files, entrypoints, framework wiring,
configuration-access call sites, and exact packaged dependencies. When the
repository does not contain the effective configuration or loader, inspect the
authorized source image or runtime read-only. Reading source configuration for
rewrite diagnosis and implementation is allowed and expected; do not print,
copy into reports, or commit credentials and other sensitive values.

Determine only the behavior relevant to startup and the active rewrite scope.
Record configuration provenance and key names, not secret values. If startup
materializes or updates effective configuration, recreate or restart the
source through its authoritative entrypoint without changing its business
behavior, and treat traffic from that diagnostic lifecycle as non-evidence.

## Materialize Local Runtime Inputs

Use the Git-ignored `.traffic-e2e/runtime/` directory only when source-proven
runtime inputs must be materialized locally. Initialization creates only this
root directory; do not precreate an environment file or configuration
subdirectory.

Create `.traffic-e2e/runtime/.env` only when process-environment values must be
materialized. Source configuration artifacts required for local target startup
may be placed under `.traffic-e2e/runtime/`; create a `config/` subtree only
when the discovered artifacts benefit from one, and preserve their supplied
format and any filename or directory relationships required by the source
loader. Copy only inputs needed by startup or the active capability, keep
sensitive values out of commands and reports, and never commit this directory.

Treat this directory as local staging, not as a new product configuration
contract. Pass its paths through the target's normal startup boundary; do not
hard-code `.traffic-e2e` into product configuration loading or translate the
source artifacts into a parallel target-only format.

## Implement Compatible Loading

Make the target read the same supplied configuration rather than requiring an
operator to transform it first. A cross-language target may parse the source
format into typed internal structures, but it must preserve the source
configuration contract at the external boundary.

## Verify

Before accepting target startup or configuration-dependent behavior:

1. Identify the source loader, authoritative configuration artifact, and
   behavior-driving consumer.
2. Identify the target compatibility loader and corresponding consumer.
3. Start the target with the same unmodified authoritative configuration
   supplied to the source environment.
4. Verify relevant defaults, overrides, validation, and refresh behavior when
   they affect startup or the active capability.
5. Record the artifact provenance, loader path, consumed keys or structures,
   and startup result without recording sensitive values.

If the target cannot start from the source configuration contract, keep the
rewrite `action_required`; configuration compatibility is not complete.
