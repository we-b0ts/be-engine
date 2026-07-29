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

When source-proven runtime inputs must be materialized locally, use the
repository's Git-ignored runtime-input location. It is permitted to copy the
necessary authoritative configuration artifacts out of an authorized source
image or runtime without modifying that source. Preserve their supplied format
and any filename or directory relationships required by the source loader.

Materialize only environment values and configuration artifacts needed by
startup or the active capability. Keep sensitive values out of commands and
reports, and never commit local runtime inputs. Treat the local location as
staging, not as a new product configuration contract: pass its paths through
the target's normal startup boundary and do not translate the source artifacts
into a parallel target-only format.

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
