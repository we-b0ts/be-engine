# One-Time Project Initialization

Read this reference only when the caller explicitly asks to initialize an
uninitialized target repository. Initialization is manual and one-time. Normal
rewrite work and resumed sessions must not rerun it.

## Initialize

The first provider version accepts one running, ready Kubernetes Pod. Run from
the target repository, or bind it with global `--target-root`:

```bash
backend-rewrite init \
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
registry digest. The Pod is an initialization input only: later preflight,
recording, Comparison, Replay, and startup-input APIs use the local snapshot
and do not require access to the original Pod.

Run `backend-rewrite` as the current user; do not add `sudo`. The current user
needs access to Docker and must be able to get and exec the named Pod.
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
missing without switching branches. It writes schema-version-17 project,
source-traffic-policy, and verification configuration; an empty startup mount
snapshot; missing Dockerfile scaffolds; a target bootstrap when target files
are absent; and required ignore rules. Existing complete target files and
Dockerfiles are preserved. Partial or conflicting initialization state is
rejected.

Do not scan source or target code before this command merely to enumerate
environment variables, dotenv files, mounts, or writable directories. Do not
add framework-specific port or trust mappings during initialization.

## Complete The Build Contracts

`.traffic-e2e/Dockerfile.recording` and `.traffic-e2e/Dockerfile.e2e` are
target-owned build contracts. During initialization, complete either file as
required by the source adaptor or target runtime contract. Both final processes must run in the
foreground as UID/GID `998:998`; neither image may contain credentials,
recordings, generated trust, build cache, or `.traffic-e2e/local/` content.

The generated target uses `http-server` with its `macros` feature and exports
the readiness GET route with `#[api(auth = none)]` and
`#[http_server::get(...)]`. The readiness path must be literal: no captures,
query, fragment, whitespace, or trailing slash except `/`. Keep the readiness
endpoint when adding business APIs. Follow [http-server.md](sdk/http-server.md)
to export methods in their owning modules and combine them through
`http_server::Router::new(ReadinessApi).merge(business_api)`; retain
`Server::serve_until` and the SIGTERM/SIGINT shutdown handling.

The generated bootstrap target temporarily contains `src/startup_probe.rs`,
and `src/main.rs` calls it during startup. Keep it through initialization
preflight. Delete the module, declaration, and call when real target
implementation begins, as marked by generated comments.

If an image needs an image-local writable directory, follow
[worker-startup-inputs.md](worker-startup-inputs.md#writable-directories) and update the applicable Dockerfile after inspecting
its real structure. Do not assume a fixed base image or available shell tool.

## Verify Initialization

Run:

```bash
backend-rewrite init preflight --duration-seconds 60
```

Only overall `status = "passed"` completes the check. On failure, adjust the
reported build/startup contract or managed input and rerun the same command.
Preflight checks initialization plumbing; it is not business API evidence and
must not advance `backend-rewrite next`.

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
