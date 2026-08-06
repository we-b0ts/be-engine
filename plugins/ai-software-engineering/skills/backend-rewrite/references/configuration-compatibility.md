# Configuration Compatibility

Use this reference before implementing target configuration loading or
accepting target startup as migration-compatible.

## Contents

- Contract
- Mandatory loader boundary
- Discover the source loader
- Materialize local boot inputs
- Implement compatible loading
- Verify

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

## Mandatory Loader Boundary

Configuration files or directories used by source startup trigger this
requirement. Inspect the authoritative source runtime loading path before
constructing target configuration or dependency clients. When the target lacks
a compatible loader, implement it in product code and initialize it once from
the composition root before constructing its consumers.

The active rewrite scope may limit which typed configuration and consumers are
implemented now. It does not permit narrowing the source loader's external
input unit, file selection, layering, merge, override, validation, or refresh
contract.

The target container entrypoint receives the mounted configuration root through
`TRAFFIC_E2E_CONFIG_DIR`. It MUST NOT open configuration files, extract selected
keys, translate them into target-only environment variables, hard-code their
values, or implement parsing, merge, defaulting, or validation on behalf of
product code. The normal target process owns all configuration loading.

Only a literal proven to be consumed as a constant or default by the same
source runtime code path may become a target code constant or default. Keep
every value obtained through configuration loading or references, including
`${a.b.c.d}`, properties, XML or YAML keys, environment variables, and startup
arguments, configuration-driven with its environment-specific resolution.
Never copy one environment's resolved value into target code as a constant,
default, or fallback.

Preserve each source configuration directory as a complete subtree below the
mounted configuration root and keep loading in product code. For example, a
source root `/data1/authconfs` transported for local E2E may be placed at
`.traffic-e2e/local/boot/data1/authconfs` and is visible to the container at
`/traffic-e2e/config/data1/authconfs`. The target loader resolves the path from
`TRAFFIC_E2E_CONFIG_DIR`; the OCI entrypoint does not translate its contents.

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

Trace the complete external loader boundary even when the active rewrite scope
uses only part of the resulting configuration. Record configuration provenance
and key names, not secret values. If startup materializes or updates effective
configuration, recreate or restart the source through its authoritative
entrypoint without changing its business behavior, and treat traffic from that
diagnostic lifecycle as non-evidence.

## Materialize Local Boot Inputs

Use the repository's Git-ignored `.traffic-e2e/local/boot/` only to transport
source-proven startup inputs. The directory name, existence, and Git-ignore
status do not establish provenance or authorize creating content. Only an
authoritative startup configuration that is supplied directly to the source
loader may be copied. SDK- or loader-generated snapshots, caches, and other
derived runtime state MUST NOT be read, copied, or used as startup input, even
when the source SDK created them during its normal lifecycle. Copy the smallest
complete authoritative configuration root; never copy one selected file, a
selected file set, or extracted keys. When that complete root exists only
inside the source container, copy it verbatim to
`.traffic-e2e/local/boot/<root-name>/` as the standard transport path and
continue the workflow. Preserve its supplied format and directory
relationships; do not treat the transport mechanism as an operator-selected
design choice.

Never create a boot input by dumping, decrypting, extracting, or translating
source-process memory, remote responses, logs, or debug output. A constant
present in the source repository or pinned compiled artifact may be inspected,
decompiled when necessary, and migrated directly into target source code; such
a source-owned hard-coded constant is code behavior, not a snapshot. For
remote-backed configuration, discovery, registry, or secrets, implement the
source SDK's genuine initialization, retrieval, refresh, and fallback path
without reading or copying its snapshots or inventing a target-local cache.
Keep sensitive values out of commands and reports, never commit local boot
inputs, and pass an allowed configuration root through the target's normal
startup boundary without translating it into a target-only format.

## Implement Compatible Loading

Make the target read the same supplied configuration rather than requiring an
operator or launcher to transform it first. Implement source-compatible
selection, parsing, layering, merge, precedence, validation, and applicable
refresh behavior behind one target-owned configuration boundary. Initialize
that boundary once during application composition and supply typed
configuration to dependency clients and capability modules.

A cross-language target may parse the complete source format into a generic
property or document model and expose typed structures only for current
consumers. It need not model every unused key immediately, but it must preserve
the complete source loading contract at the external boundary.

## Verify

Before accepting target startup or configuration-dependent behavior:

1. Identify the source loader, authoritative configuration artifact, and
   behavior-driving consumer.
2. Identify the target compatibility loader and corresponding consumer.
3. For every behavior-driving source placeholder or configuration key, confirm
   that the target loader supplies it to the corresponding consumer; reject a
   resolved environment value used as a target constant, default, or fallback.
4. Confirm the OCI entrypoint transports only the configuration root and
   source-defined selectors; reject entrypoint-owned key extraction or
   translation.
5. Start the target with the same unmodified authoritative configuration
   supplied to the source environment.
6. Verify relevant selection, layering, precedence, defaults, validation, and
   refresh behavior when they affect startup or the active capability.
7. Record the artifact provenance, loader path, consumed keys or structures,
   and startup result without recording sensitive values.

If the target cannot start from the source configuration contract, keep the
assigned API incomplete and return the unresolved configuration risk;
configuration compatibility is not complete.
