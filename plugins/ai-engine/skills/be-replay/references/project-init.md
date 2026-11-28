# One-Time Project Initialization

Read this reference only when the caller explicitly asks to initialize an
uninitialized target repository. Initialization is manual and one-time. Normal
rewrite work and resumed sessions must not rerun it.

## Initialize

Choose one source provider: a running, ready Kubernetes Pod or a local Docker
container (running, exited, or created). Run from the Target repository or put
`--target-root` before the subcommand.

```bash
be-replay init \
  --source-pod <pod> \
  --namespace <namespace> \
  [--pod-container <regular-container>] \
  [--kubeconfig /path/to/kubeconfig] \
  [--context <context>] \
  [--env-file /path/to/initial.env] \
  [--readiness-path /healthz] \
  [--http-backend-port 8080] \
  [--http-gateway-port 4080]
```

Omit `--pod-container` only when the Pod has exactly one regular container.
The command pins the selected container's exact immutable image in local
Docker and snapshots its image identity, effective environment, command and
arguments, supported security settings, and supported ConfigMap/Secret mounts
into the ignored `.traffic-e2e/local/source/` directory. It may pull the exact
registry digest. The Pod is an initialization input only: later diagnostic
preflight, Replay, and startup-input APIs use the local snapshot
and do not require access to the original Pod.

For a local Docker container, use:

```bash
be-replay init --source-container <container-name-or-id>
```

The container and Kubernetes inputs are mutually exclusive. Container capture
reads Docker configuration without `exec`, snapshots bind/volume contents, and
commits its writable layer and effective launch configuration without starting,
stopping, or pausing the input. It saves a private, checksummed image archive
under `.traffic-e2e/local/source/`; no registry digest is required. The original
container is not needed afterward. Running capture is an online snapshot; use
a stopped, quiescent source for consistent application files. The existing
Linux/amd64 and managed runtime user `998:998` contracts still apply. Writable
mount snapshots are copied for each managed run, tmpfs starts empty, and ignored
mounts are listed in the result. Do not copy the source container's host ports
or network into the engine's isolated runtime.

Run `be-replay` as the current user; do not add `sudo`. The current user
needs access to Docker. The Kubernetes provider additionally requires get and
exec access to the named Pod.
Initialization captures the effective container environment directly, so later
target starts automatically receive source application variables even when a
referenced ConfigMap or Secret is no longer API-readable.

`--env-file` is optional and may name an empty dotenv file. It initializes the
ignored mode-0600 `.traffic-e2e/local/target.env`. That file contains only
target overrides or additions; source application environment is injected from
the source snapshot first, then `target.env` wins by name. There is one project
environment file, never one per case.

`--readiness-path` defaults to `/healthz`. The generated configuration records
status `200`; there is no readiness-status argument. The backend port defaults
to `8080`, the Recorder HTTP gateway defaults to `4080`, and the two ports must
differ. traffic-e2e does not infer or special-case an application `PORT`
variable.

Initialization creates local `dev-migration` from the current `HEAD` when it is
missing without switching branches. It writes version 18
`.traffic-e2e/project.yaml` with verification settings, the unified
`traffic-policy/v3` document at `.traffic-e2e/policy.yaml` and an empty
`.traffic-e2e/apis.yaml` catalog. It creates an empty startup mount snapshot,
missing Dockerfile scaffolds, a target bootstrap when target files are absent,
and required ignore rules. Existing complete target files and Dockerfiles are
preserved.
Partial or conflicting initialization state is rejected.

Do not scan source or target code before this command merely to enumerate
environment variables, dotenv files, mounts, or writable directories. Do not
add framework-specific port or trust mappings during initialization.

## Complete The Build Contracts

`.traffic-e2e/Dockerfile.source` and `.traffic-e2e/Dockerfile.target` are
target-owned build contracts. During initialization, complete either file as
required by the source adaptor for diagnostic preflight or
the target runtime contract. Independent standard recording uses a separate
project-owned `.traffic-e2e/Dockerfile.recording`, built and started by its deployment caller.
Both managed final processes must run in the
foreground as UID/GID `998:998`; neither image may contain credentials,
recordings, generated trust, build cache, or `.traffic-e2e/local/` content.

Before completing `Dockerfile.target`, inspect `project.delivery.managed_paths`.
An object entry with `path` and `build_context` makes that managed directory
available as a BuildKit named context. Consume only the required files with
`COPY --from=<build_context>` or `RUN --mount=from=<build_context>` and preserve
the target as the default context. A string entry expands delivery and review
scope only and is not a Docker build input. Do not use `COPY ../...`, change the
default context to the outer Git repository, or infer sibling paths that the
project configuration does not declare.

Document the Target repository's validation commands in `AGENTS.md` or
`CLAUDE.md`. Managed integration follows the
[code integrator guide](code-integrator.md), and the coordinator runs full
Session verification.

The generated target exposes a readiness GET endpoint. The readiness path
must be literal, with no captures, query, fragment, whitespace, or trailing
slash except `/`. Keep the readiness endpoint and SIGTERM/SIGINT shutdown
behavior when adding business APIs.

The generated bootstrap target temporarily contains `src/startup_probe.rs`,
and `src/main.rs` calls it during startup. Keep it through initialization
preflight. Delete the module, declaration, and call when real target
implementation begins, as marked by generated comments.

If an image needs an image-local writable directory, follow
[api-implementer-startup-inputs.md](api-implementer-startup-inputs.md#writable-directories) and update the applicable Dockerfile after inspecting
its real structure. Do not assume a fixed base image or available shell tool.

## Verify Initialization

Run:

```bash
traffic-e2e diagnose preflight --target-root <canonical-root> --duration-seconds 60
```

Only overall `status = "passed"` completes the check. On failure, adjust the
reported build/startup contract or managed input and rerun the same command.
This traffic-e2e diagnostic checks initialization plumbing, including one
readiness recording and Replay probes. For business verification, use a
separate sealed Source recording from the deployment caller as described in
[external recording evidence](coordinator-recording.md).

For business verification, start with `be-replay status` on the configured
pull-request base, then start the approved round with the exact sealed
recording ID. The API catalog in `.traffic-e2e/apis.yaml` labels per-method
counts. See [Source session regression](session-regression.md).

For a missing managed startup input during preflight, use
[coordinator-startup-inputs.md](coordinator-startup-inputs.md). Use `startup env`
and `startup mount` APIs rather than editing `project.yaml` or snapshot files.
Later rewrite sessions follow their assigned role's startup-input procedure.

Initialization is complete when init succeeded, both Dockerfiles are ready,
`.traffic-e2e/local/target.env` exists with mode `0600`, preflight passed, and
no local snapshot or credential entered source control. Report that result,
then explicitly ask the caller whether to create an initialization merge
request. Do not commit, push, or create the merge request without the caller's
confirmation.

When the caller confirms, keep `dev-migration` as the unchanged merge-request
target branch and put the initialization changes on a separate source branch.
Never commit the initialization changes directly to `dev-migration`, even when
that is the currently checked-out branch. Commit only the tracked
initialization deliverables, verify that `.traffic-e2e/local/`, source
snapshots, `target.env`, credentials, and generated trust remain excluded,
push the source branch, and create the merge request with `dev-migration` as
its target/base. If the caller declines, stop without creating Git delivery.
Beginning the rewrite workflow remains a separate request.
