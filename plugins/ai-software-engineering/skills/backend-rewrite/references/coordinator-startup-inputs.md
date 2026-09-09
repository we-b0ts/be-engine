# Coordinator Startup Inputs

Audience: the coordinator applying returned, source-proven startup inputs.
Read after receiving a required environment override, source-compatible mount,
or image-local writable directory. Missing source reasoning returns to the
implementation owner; do not inspect source to invent startup requirements.

## Environment

Initialization snapshots the selected source process's effective environment.
Every target start, restart, preflight, Replay, and Comparison automatically
loads the application-owned portion of that snapshot. Runtime identity,
Kubernetes service-link variables, field-derived Pod identity, and
`TRAFFIC_E2E_*` variables are not projected to the target. An explicitly
declared application `PORT` has no special behavior and is handled like any
other application variable.

The single target override file is:

```text
.traffic-e2e/local/target.env
```

It is Git-ignored, mode `0600`, and may be empty. traffic-e2e recreates it when
missing. Values in this file override source-snapshot values by name and may
add target-only variables. There is no per-case environment file.

When target behavior proves that a variable must differ from the captured
baseline, use the API instead of displaying or editing values manually:

```bash
backend-rewrite --target-root <target> startup env list
backend-rewrite --target-root <target> startup env exists <NAME>
backend-rewrite --target-root <target> startup env equals <NAME> \
  [--value <VALUE> | --from-env <CALLER_NAME> | --from-source]
backend-rewrite --target-root <target> startup env ensure <NAME> \
  [--value <VALUE> | --from-env <CALLER_NAME> | --from-source]
backend-rewrite --target-root <target> startup env remove <NAME>
backend-rewrite --target-root <target> startup env import <PATH>
backend-rewrite --target-root <target> startup env validate
```

`--from-source` uses the exact effective value saved during initialization
without returning it. It verifies or converges a source-proven
requirement; `ensure` returns `unchanged` without creating a redundant override
when the source baseline already matches. With no value option, `equals` and `ensure` read the
same-named caller variable; `--from-env` selects another caller name.

These APIs return names and state only, never values or hashes. Equality is
exact after dotenv parsing. There is no substring, prefix, regex, or
partial-value oracle. `list`, `exists`, `equals`, and `validate` observe the
effective source-plus-override target environment; `list` separately identifies
override names. `remove` removes only a `target.env` override, so the source
baseline may become effective again.

Consume the returned `startup_environment` input. Use `--from-source` for
`from_source: true`; otherwise use its explicit caller-owned value source and
evidence. Apply inputs accompanying a code handoff after its publication;
apply an input-only result while its original dispatch is still confirmed.
Both paths require the engine's normal acceptance afterward.
Do not substitute a worker-local file for the canonical override.

```yaml
startup_environment:
- name: APPLICATION_VARIABLE
  from_source: true
  source_evidence: target behavior requires the captured source runtime value
```

Conflicting requirements for one name must be reconciled rather than applied
last-writer-wins. Do not convert file-backed configuration into environment
variables or hardcode runtime configuration in target code.

## Source-Compatible Mounts

Use a startup mount only when the target needs existing source file or
directory content at the same absolute path:

```bash
backend-rewrite --target-root <target> startup mount list
backend-rewrite --target-root <target> startup mount exists <ABSOLUTE_PATH>
backend-rewrite --target-root <target> startup mount ensure <ABSOLUTE_PATH>
```

`ensure` reads only `.traffic-e2e/local/source/`; it never reconnects to the
initialization Pod. A captured ConfigMap/Secret path is copied from the source
snapshot. An image-local path is copied from the immutable local source image
through a temporary, never-started Docker container. Supported source mount
access is preserved; image-local paths default to read-only.

The API validates absolute paths and overlap, adds only a missing declaration,
preserves existing startup content, and converges `project.yaml` with the
ignored `.traffic-e2e/local/startup/` snapshot. It returns path, access mode,
status, and snapshot ID, never file contents. Missing, damaged, ignored PVC, or
unsupported projected-volume content is an error. Do not edit either snapshot
or `project.yaml` manually. Replacement remains an explicitly authorized
administrator repair.

## Image-Local Writable Directories

An empty writable directory is a target/source-adaptor image requirement, not
source content to mount. Require the responsible worker's Dockerfile change and
local check result; do not inspect or rewrite Dockerfiles here. Route missing
implementation or source proof back to that owner.

If the returned requirement includes retained output, apply the supported
`target.runtime_outputs` configuration through the existing workflow. Runtime
outputs are separate from startup inputs and do not enter the startup snapshot.
