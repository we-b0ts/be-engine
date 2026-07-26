---
name: platform-recording-init
description: "Initialize a Platform department Java/Tomcat repository for managed traffic recording from an existing source application container, using the standard Breeze and Vintage topology, fixed Recorder configuration, and bundled Breeze SDK source-image patch. Use when invoked directly or when a Platform backend rewrite asks to initialize the current repo for traffic recording from a container such as friendship. Do not use for generic repositories, recording cases, replay, or implementation work."
---

# Platform Recording Init

Build a ready-to-record environment around the genuine Platform source
application. Keep Recorder policy and Breeze dependency interception
standardized; adapt only the source container's proven startup facts.

## Input Contract

Require only the source application container name or ID. Use `breeze` as the
default supporting container. Accept stopped containers and recover their
configuration with `docker inspect`. Accept a complete `docker run` command
only when the corresponding container is unavailable.

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
writing files or starting containers.

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
4. Copy and render the files under [assets/recording](assets/recording).
   Replace only the documented `__PROJECT_SCOPE__` and `__PROJECT_CLI__`
   placeholders in configuration templates. Copy `brz-no-fallback.sh`
   unchanged to `scripts/brz-no-fallback.sh`. Keep the template's fixed
   10-second post-ready settle interval; `recording wait-ready` owns that wait.
5. Copy the Breeze patch assets unchanged into
   `.traffic-e2e/adapters/source/`. Generate the remaining source adapter
   Dockerfile and launchers from inspected evidence; invoke the bundled patch
   applicator and recursively assign `/data1/weibo` to numeric `998:998`
   during the image build.
6. Generate `scripts/start-recording` for the inspected startup parameters.
   Support optional `--run-id YYYYMMDDHHMMSS` and
   `--duration-seconds <positive-integer>`, plus repeatable
   `--api 'METHOD /path-or-pattern'` and
   `--brz-no-fallback <true|false>`. Default the duration to 60 seconds and
   Breeze no-fallback to `true`, pass API selectors through unchanged to
   `traffic-e2e record`, and require AI or automated calls to pass the duration
   explicitly. Follow
   the fixed lifecycle in the runtime reference; do not reconstruct it from
   another repository.
7. Before target implementation exists, generate an extensible
   `scripts/<project>-cli` whose initialization-time minimum is a
   fixed-response candidate mock behind `start`, `status`, and `stop`, then
   generate `scripts/start-recording-comparison` against that stable lifecycle
   subset. These three commands are not the complete or exclusive command set;
   later implementation may add the standard `e2e`, `test`, and `check`
   commands while preserving lifecycle semantics. The candidate listens on the
   configured comparison recording port.
   `start-recording-comparison` must support optional
   `--run-id YYYYMMDDHHMMSS`, `--duration-seconds`, and the enable-only
   `--baseline-recheck` flag, plus repeatable
   `--api 'METHOD /path-or-pattern'` and
   `--brz-no-fallback <true|false>`. Default the duration to 60 seconds and
   Breeze no-fallback to `true`. Start exactly one shared Breeze for the
   genuine source and candidate containers; consume the Breeze option in the
   wrapper and pass only traffic-e2e options through. Require AI or automated
   calls to pass the duration explicitly. Follow the fixed lifecycle in the
   runtime reference.
8. Create empty recording bind sources by translating each private source
   mount from `/data1/<project>/<path>` to
   `/data1/<project>-recording/<path>`. Keep container destinations unchanged,
   copy no original content, and recursively assign the new writable sources
   to numeric `998:998`. Before every start, also normalize the fixed shared
   Breeze directories as specified by the runtime reference.
9. Validate configuration, adapter construction, shell syntax, bounded
   standard and comparison recording startup, readiness, identity, dependency
   routing, and clean finalization.
10. Commit only the initialization outputs, push the initialization branch, and
   create or update its draft PR targeting `dev-migration`.

## Source-Controlled Output

Limit initialization changes to:

```text
.traffic-e2e/project.yaml
.traffic-e2e/recorder.toml
.traffic-e2e/verification.yaml
.traffic-e2e/adapters/source/*
scripts/start-recording
scripts/start-recording-comparison
scripts/<project>-cli
scripts/brz-no-fallback.sh
.gitignore
```

Append only missing ignore entries for:

```text
/.traffic-e2e/local/
/.traffic-e2e/.env/
/.traffic-e2e/data/
/.traffic-e2e/artifacts/
```

Do not modify business source, build files, deployment files, CI, README, or
repository instructions.

## Completion

Run:

```bash
bash -n scripts/brz-no-fallback.sh
bash -n scripts/start-recording
bash -n scripts/start-recording-comparison
bash -n scripts/<project>-cli
./scripts/start-recording --duration-seconds 1
./scripts/start-recording-comparison --duration-seconds 1
```

Report completion only after Recorder listeners, Breeze, and the genuine
source are ready; the genuine source Java process runs as numeric `998:998`;
`breeze.recording` resolves through fake DNS for that identity; and Recorder
finalizes cleanly. The bounded comparison recording validation must prove the
baseline and fixed-response candidate both became ready and
`comparison-recording-run.json` finalized; it does not require frontend
traffic or a published comparison recording case. Also require published
`dev-migration` and initialization branches plus the draft PR from the
initialization branch to `dev-migration`. Do not send a business request or
require a recorded case during initialization.
