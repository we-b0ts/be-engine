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

Use the coordinator API instead of displaying or hand-editing sensitive
values:

```bash
backend-rewrite --target-root <target> startup env list
backend-rewrite --target-root <target> startup env exists <NAME>
backend-rewrite --target-root <target> startup env equals <NAME> [--from-env <CALLER_NAME>]
backend-rewrite --target-root <target> startup env ensure <NAME> [--from-env <CALLER_NAME>]
backend-rewrite --target-root <target> startup env remove <NAME>
backend-rewrite --target-root <target> startup env import <PATH>
backend-rewrite --target-root <target> startup env validate
```

`equals` and `ensure` read the candidate value from the same-named caller
environment variable by default. `--from-env` selects another caller variable.
Do not place secret values in argv. `list`, `exists`, `equals`, `ensure`,
`remove`, `import`, and `validate` return variable names and state only; they
never return stored values or hashes. Equality is exact after dotenv parsing.
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
