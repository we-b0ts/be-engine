---
name: platform-recording-init
description: "Initialize Platform Java/Tomcat repositories for managed standard and comparison traffic recording from an existing source application container. Use for the recording-initialization phase of a Platform backend rewrite, not generic repository setup, recording or replay execution, or target SDK implementation."
---

# Platform Recording Init

Build a ready-to-record environment around the genuine Platform source
application. Keep Recorder policy and Breeze dependency interception
standardized; adapt only the source container's proven startup facts. Treat
the source repository, business classes, and observable application behavior
as immutable.

## Input Contract

Require only the source application container name or ID. Use `breeze` as the
default supporting container. Accept stopped containers and recover their
configuration with `docker inspect`. Accept a complete `docker run` command
only when the corresponding container is unavailable.

Generated standard and comparison recording entrypoints require
`TRAFFIC_E2E_ENCRYPTION_KEY_B64`, containing the Base64 encoding of exactly 32
bytes. Treat only the variable name as configuration: never ask for, print,
persist, or commit its value.

Use these fixed Platform defaults unless the user explicitly overrides them:

```text
source HTTP port: 8080
readiness path: /healthz
readiness success status: 404
```

Do not ask the user for the source image, command, environment, mounts, or
working directory when Docker already provides them.

## Required Procedure

Read [platform-runtime.md](references/platform-runtime.md) completely before
writing shared runtime files or starting containers. Read
[standard-recording.md](references/standard-recording.md) before generating or
validating `scripts/start-recording`. Read
[comparison-recording.md](references/comparison-recording.md) before generating
or validating the candidate facade or `scripts/start-recording-comparison`.

1. Inspect repository instructions and both containers. Preserve the source
   image, root bootstrap, environment, command, working directory, limits, and
   container mount destinations.
2. Ensure `dev-migration` exists locally and on `origin` before rendering
   `project.yaml`. Track `origin/dev-migration` when it exists; otherwise
   create `dev-migration` from the repository's confirmed default-branch
   baseline and publish it. Treat it as the fixed initialization PR base.
3. Create or reuse a named initialization branch based on `dev-migration` and
   switch to it before writing files. Never write initialization outputs on
   the default branch or directly on `dev-migration`.
4. Copy and render the recording files under
   [assets/recording](assets/recording). Replace only the documented
   `__PROJECT_SCOPE__` and `__PROJECT_CLI__` placeholders in configuration
   templates. Copy `brz-no-fallback.sh` unchanged to
   `scripts/brz-no-fallback.sh`. Keep the template's fixed 10-second post-ready
   settle interval and encrypted `authorization` request-header policy;
   `recording wait-ready` owns the wait. Keep `authorization` in
   `redact_headers` for response-side protection; request encryption takes
   precedence. Create only the private `.traffic-e2e/boot/` root; init must not
   populate it. `boot/` is input-only transport, not authorization to derive
   content from a source process, remote response, recording, log, or
   diagnostic.
5. Merge the exact managed block from
   [boot-boundary.md](assets/agents/boot-boundary.md) into the repository-root
   `AGENTS.md` according to the runtime reference. Preserve all unmanaged
   content and reject unmatched or duplicate managed markers.
6. Copy the fixed Breeze Mesh patch assets unchanged into
   `.traffic-e2e/adapters/source/`. This bundled patch is the only permitted
   source-class patch and is a closed recording-infrastructure exception, not
   a pattern for new adapters. Generate only the remaining source adapter
   Dockerfile and launchers from inspected evidence; invoke the bundled patch
   applicator and recursively assign `/data1/weibo` to numeric `998:998`
   during the image build. Never add another Java override or JAR patch.
7. Generate `scripts/start-recording` for the inspected startup parameters and
   follow the exact wrapper, lifecycle, ownership, encryption, and validation
   contract in the standard-recording reference. Do not reconstruct it from
   another repository.
8. Before target implementation exists, generate an extensible
   `scripts/<project>-cli` whose initialization-time minimum is a
   fixed-response candidate mock behind `start`, `status`, and `stop`, then
   generate `scripts/start-recording-comparison` against that stable lifecycle
   subset. Follow the exact facade, wrapper, shared-Breeze, encryption,
   isolation, and validation contract in the comparison-recording reference.
9. Create empty recording bind sources by translating each private source
   mount from `/data1/<project>/<path>` to
   `/data1/<project>-recording/<path>`. Keep container destinations unchanged,
   copy no original content, and recursively assign the new writable sources
   to numeric `998:998`. Before every start, also normalize the fixed shared
   Breeze directories as specified by the runtime reference.
10. Complete the shared runtime, standard recording, and comparison recording
   validation sections. Do not generate target Breeze SDK packages or other
   repository development rules beyond the managed boot-input block; those
   belong to the
   [`breeze-sdk` skill](../breeze-sdk/SKILL.md).
11. Commit only the initialization outputs, push the initialization branch, and
   create or update its draft PR targeting `dev-migration`.

## Source-Controlled Output

Limit initialization changes to:

```text
.traffic-e2e/project.yaml
.traffic-e2e/recorder.toml
.traffic-e2e/verification.yaml
.traffic-e2e/adapters/source/*
AGENTS.md
scripts/start-recording
scripts/start-recording-comparison
scripts/<project>-cli
scripts/brz-no-fallback.sh
.gitignore
```

Append only missing ignore entries for:

```text
/.traffic-e2e/local/
/.traffic-e2e/boot/
/.traffic-e2e/data/
/.traffic-e2e/artifacts/
```

Do not modify business source, build files, deployment files, CI, README, or
repository instructions beyond the exact managed `AGENTS.md` block. The
adapter output allowance does not authorize copying or replacing business
classes, changing caches or feature switches, or otherwise changing source
behavior.

## Completion

Run:

```bash
bash -n scripts/brz-no-fallback.sh
bash -n scripts/start-recording
bash -n scripts/start-recording-comparison
bash -n scripts/<project>-cli
./scripts/start-recording --duration-seconds 1 --case-limit 1
./scripts/start-recording-comparison --duration-seconds 1 --case-limit 1
```

Run the two bounded recording commands with a valid, unlogged
`TRAFFIC_E2E_ENCRYPTION_KEY_B64`; each command must fail before runtime changes
when the variable is absent or invalid.

Also verify that `.traffic-e2e/boot/` is ignored and empty after init, and that
the root `AGENTS.md` contains exactly one current managed boot-input block.

Report completion only after every validation gate in the three selected
references passes, `dev-migration` and the initialization branch are
published, and the initialization draft PR targets `dev-migration`. Do not
send a business request, implement target Breeze clients, or require a
recorded case during initialization.
