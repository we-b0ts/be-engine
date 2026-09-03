# One-Time Project Initialization

Read this reference only when the caller explicitly asks to initialize an
uninitialized target repository. Initialization is manual and one-time. Normal
rewrite work and resumed sessions must not rerun it.

## 1. Initialize The Repository Contract

At command time, `--source-container` must name a present, inspectable, stopped
local source container. Run from the target repository, or bind it with global
`--target-root`:

```bash
backend-rewrite init \
  --source-container <existing-source-container> \
  [--env-file /path/to/initial.env] \
  [--readiness-path /healthz] \
  [--readiness-status 404] \
  [--http-gateway-port 4080]
```

`--env-file` is optional and may name an empty dotenv file. Initialization
imports it into the ignored, mode-0600 project file
`.traffic-e2e/local/target.env`; without the option, that file starts empty.
The same file is loaded for every target start and is recreated empty if it is
missing.

Initialization creates schema-version-16 repository configuration, an empty
startup mount snapshot, a minimal `.traffic-e2e/Dockerfile.recording` scaffold,
the target bootstrap when target files are absent, and the required ignore
rules. It preserves existing Dockerfiles and an existing complete target, and
refuses partial or conflicting initialization state.

Do not scan source or target code before this command merely to enumerate
environment variables, dotenv files, mounts, or writable directories. Do not
add framework-specific port or trust variable mappings during initialization.

## 2. Complete The Two Build Contracts

Review and finish the generated `.traffic-e2e/Dockerfile.recording` scaffold
against the inspected source image and its real launch contract. Preserve the
real entrypoint, arguments, working directory, and required runtime files. The
adapted application must run as UID/GID `998:998`. Do not embed credentials,
generated trust, recordings, probe tooling, or machine-local state.

Preserve the generated or existing `.traffic-e2e/Dockerfile.e2e`. Its final
image must run the target entrypoint in the foreground as UID/GID `998:998`,
remain buildable through the managed command, and contain no credentials,
recordings, generated trust, build cache, or `.traffic-e2e/local/` content.

The generated bootstrap target contains the temporary module
`src/startup_probe.rs`, and `src/main.rs` calls it during startup. Keep both in
place through initialization preflight. As soon as real target implementation
work begins, delete that module, its `mod startup_probe;` declaration, and its
`startup_probe::run()` call. The generated comments mark all three locations.
This temporary initialization code must never become product behavior.

If either image needs an image-local writable directory, follow
[startup.md](startup.md) and update the applicable Dockerfile for UID/GID
`998:998`. Do not assume a fixed Dockerfile structure or mutate configuration
and credential trees recursively.

## 3. Run The Managed Initialization Check

After both Dockerfiles are ready, run:

```bash
backend-rewrite init preflight --duration-seconds 60
```

Provide any required named caller environment without printing its value.
Treat only the returned overall `status = "passed"` as success. On failure,
change the repository build/startup contract or managed startup inputs named by
the result, then rerun the same command. Additional local checks may help
diagnosis, but only the managed preflight result completes initialization.

Initialization preflight validates only the initialized build, recording,
network, target startup, and cleanup contracts. It is not business API
compatibility evidence and must not run or advance `backend-rewrite next`.

## 4. Add Omitted Startup Inputs Only When Proven Necessary

During later implementation, read [startup.md](startup.md) only when actual
target behavior proves that an input is missing. Use the managed API rather
than hand-editing `project.yaml` or local snapshot state:

```bash
backend-rewrite --target-root <target> startup env list
backend-rewrite --target-root <target> startup env equals <NAME> \
  [--from-env <CALLER_NAME>]
backend-rewrite --target-root <target> startup env ensure <NAME> \
  [--from-env <CALLER_NAME>]
backend-rewrite --target-root <target> startup env import <PATH>

backend-rewrite --target-root <target> startup mount list
backend-rewrite --target-root <target> startup mount exists <ABSOLUTE_PATH>
backend-rewrite --target-root <target> startup mount ensure <ABSOLUTE_PATH>
```

Environment APIs never return stored values. Mount `ensure` captures only a
missing absolute source-compatible path from the retained stopped source
container and preserves existing snapshot content. Replacing or refreshing
captured content remains an explicitly authorized administrator operation.

## 5. Finish Initialization

Initialization is complete only when:

- `backend-rewrite init` succeeded;
- both Dockerfiles are present and contain the reviewed launch contracts;
- `.traffic-e2e/local/target.env` exists with mode `0600`;
- `backend-rewrite init preflight` returned overall `passed`; and
- no credential, recording, generated trust, or `.traffic-e2e/local/` content
  is included in source-controlled changes.

Stop there. Do not begin the rewrite workflow as part of initialization.

If the caller asks for Git delivery, confirm the intended baseline and target
branch before creating a feature branch, commit, push, or pull request. Keep
runtime-local files out of the commit. Otherwise leave delivery to the caller.
