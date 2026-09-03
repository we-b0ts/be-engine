# Target Startup Inputs

Read this reference only when implementation or startup diagnosis proves that
the target needs an environment variable, dotenv import, source-compatible
mount, or image-local writable directory. Initialization deliberately does not
scan source code to enumerate possible inputs.

## Environment

The single project-level environment file is:

```text
.traffic-e2e/local/target.env
```

It is Git-ignored, mode `0600`, and may be empty. traffic-e2e creates it during
initialization and recreates it empty if it is missing later. Every target
start, restart, preflight, Replay run, and Comparison run loads this same file;
there is no case-level environment file.

`target.env` is target-only: traffic-e2e never loads it into the retained
source container or the recording adaptor. Preserve source environment and
dotenv behavior unchanged. Do not copy source dotenv contents into
`target.env` merely to make initialization preflight pass; add a target value
later only when target implementation or startup proves it is required.

### Implementation-time environment discovery

This workflow is triggered by behavior evidence, not only by a failed start or
dependency connection. Whenever source-code or source-runtime evidence proves
that logic being implemented in the target reads an application-owned runtime
environment variable, determine whether the target needs the same input. If it
does, preserve that runtime configurability in target code and manage the
source-proven effective value through this API. Do not hardcode the value or
wait for target execution to fail first.

An implementation worker does not mutate the project-level ignored file from
its isolated worktree. It returns a `startup_environment` coordinator input for
each required value, containing the exact variable `name`, effective `value`,
and `source_evidence`. After integrating the worker change, the main
orchestrator applies those inputs against the canonical target root before
target quality or acceptance. When one Agent owns both implementation and the
canonical target root, it may apply the value immediately.

Use this handoff shape:

```yaml
startup_environment:
- name: APPLICATION_VARIABLE
  value: source-proven-effective-value
  source_evidence: path and lookup behavior proving the runtime input
```

The orchestrator coalesces identical entries for the same name. Conflicting
values for one name are not last-writer-wins: stop and reconcile the source
configuration scope before updating the canonical environment.

```text
source behavior reads NAME
  -> target implementation needs NAME
  -> prove the effective source value
  -> startup env ensure NAME --value VALUE
  -> next target start automatically loads target.env
  -> run target quality and acceptance with the updated startup fingerprint
```

Do not convert every source setting into an environment variable. If target
behavior should read an existing file at its original absolute path, use a
source-compatible startup mount. If the value is a target implementation
default and no runtime input is required, keep the source-compatible default in
target code instead.

Use the coordinator API instead of displaying or hand-editing sensitive
values:

```bash
backend-rewrite --target-root <target> startup env list
backend-rewrite --target-root <target> startup env exists <NAME>
backend-rewrite --target-root <target> startup env equals <NAME> \
  [--value <VALUE> | --from-env <CALLER_NAME>]
backend-rewrite --target-root <target> startup env ensure <NAME> \
  [--value <VALUE> | --from-env <CALLER_NAME>]
backend-rewrite --target-root <target> startup env remove <NAME>
backend-rewrite --target-root <target> startup env import <PATH>
backend-rewrite --target-root <target> startup env validate
```

`equals` and `ensure` accept an exact `--value`, or read the candidate from the
same-named caller environment variable by default. `--from-env` selects another
caller variable.
`list`, `exists`, `equals`, `ensure`, `remove`, `import`, and `validate` return
variable names and state only; they never return stored values or hashes.
Equality is exact after dotenv parsing.
There is no substring, prefix, regular-expression, or partial-value oracle.

`ensure` returns `created`, `updated`, or `unchanged`. `import` merges the
parsed dotenv values and reports names and counts only. API mutations may
normalize ordering and remove comments, so keep documentation outside the
runtime env file.

traffic-e2e does not define a `PORT` convention and has no application-specific
port mapping. Derive any required native variable name from the actual
container, runtime, and target implementation, then manage it like any other
environment variable. Replay mounts its public CA at the fixed path
`/traffic-e2e/trust/replay-ca.pem`; when a runtime needs an application-owned
variable for that path, add it through `startup env ensure`. Initialization has
no port or Replay-CA environment selector.

## Source-Compatible Mounts

Use mounts only for a source file or directory whose existing content must be
available to the target at the same absolute path:

```bash
backend-rewrite --target-root <target> startup mount list
backend-rewrite --target-root <target> startup mount exists <ABSOLUTE_PATH>
backend-rewrite --target-root <target> startup mount ensure <ABSOLUTE_PATH>
```

`ensure` adds only a missing path. It requires the configured source container
to remain present and stopped with the initialization-time container and image
identity. It validates the absolute path and overlap rules, captures only the
new path, preserves existing snapshot content, and converges
`target.startup.mounts` with `.traffic-e2e/local/startup/` as one managed
operation. It returns only the
path, access mode, change status, and snapshot ID; it never returns file
contents.

An exact source Docker-mount destination inherits its `rw` or `ro` access.
Image-local source paths default to read-only. A partial parent/child overlap
with a source Docker mount is rejected. Do not hand-edit `project.yaml` or the
local snapshot. Replacing, refreshing, or removing existing captured content
is not an ordinary implementation operation; use administrator startup repair
when explicitly authorized.

A declared mount whose snapshot is missing or damaged is an error. Never
replace missing source content with an empty file or directory.

## Image-Local Writable Directories

Do not use a startup mount when the application only needs an empty writable
directory for logs, caches, PID files, or temporary state. There is no API that
rewrites Dockerfiles because their stages, base images, tools, and final users
are not structurally uniform.

Update the applicable build contract after inspecting its actual structure:

- update `.traffic-e2e/Dockerfile.recording` when the source recording process
  requires the directory;
- update `.traffic-e2e/Dockerfile.e2e` when the target process requires it; and
- update both when both processes use the same path.

The applicable final image must allow UID/GID `998:998` to read, write, and
enter the directory. Choose commands appropriate to the real base image,
build stage, and final `USER`; do not assume `install`, `chown`, or a shell is
available. Do not recursively change ownership of existing configuration or
credential trees. Build and preflight must verify the resulting access as
`998:998`.

When directory contents must be retained after the container stops, use the
separate `target.runtime_outputs` contract. A runtime output is not a startup
input and never enters the startup snapshot.
