# API Implementer Startup Inputs

Read only when assigned source analysis proves that the target needs an
environment override, source-compatible mount, or image-local writable directory.
Return input requirements; do not mutate canonical startup configuration.

## Environment

Initialization already captures the source process's effective environment.
Every target start receives its application-owned portion. Runtime identity,
Kubernetes service-link and field-derived Pod values, and `TRAFFIC_E2E_*` are
excluded. An application `PORT` is ordinary application configuration.

Keep normal runtime lookup in target code. Return an addition or override only
when source behavior proves it is necessary; do not wait for a target failure
or scan unrelated source to enumerate speculative variables.

```yaml
startup_environment:
- name: APPLICATION_VARIABLE
  from_source: true
  source_evidence: target behavior requires the captured source runtime value
```

Prefer `from_source: true` for the captured source value. Otherwise identify the
caller-owned value source and narrow source proof without exposing secrets.
Flag conflicting requirements for the same name. Do not create a worker-local
environment file, read canonical secret values, or hardcode runtime values.

## Mounts

For existing source file/directory content, return its exact absolute mount path
and source proof that the target reads it there. The source snapshot supplies
captured ConfigMap/Secret content or immutable image-local content. Do not edit
snapshots, reconnect to the source Pod, or replace a file with invented env vars.

## Writable Directories

When the application only needs an empty writable directory for logs, caches,
PID files, or temporary state, do not propose a startup mount. Inspect the
actual build and update `.traffic-e2e/Dockerfile.source` for source-adaptor
needs in diagnostic preflight, `.traffic-e2e/Dockerfile.target` for target
needs, or both when proven. Independent standard capture uses `.traffic-e2e/Dockerfile.recording`
owned by its deployment caller.

The final image must let UID/GID `998:998` read, write, and enter the directory.
Use commands available in the actual final stage; do not assume `install`,
`chown`, or a shell exists. Do not recursively change ownership of configuration
or credential trees. Return `target.runtime_outputs` requirements when content
must survive container shutdown; these are outputs, not startup snapshots.

Return startup inputs with the Session finding and Source sequences or the
Case issue and dispatch identity. Include the code handoff when code changed.
The coordinator applies the inputs and runs verification.
