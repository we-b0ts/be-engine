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
2. Copy and render the files under [assets/recording](assets/recording).
   Replace only the documented `__PROJECT_SCOPE__` and `__PROJECT_CLI__`
   placeholders in configuration templates. Copy `mesh_switch_task.sh`
   unchanged to `scripts/mesh_switch_task.sh`.
3. Copy the Breeze patch assets unchanged into
   `.traffic-e2e/adapters/source/`. Generate the remaining source adapter
   Dockerfile and launchers from inspected evidence; invoke the bundled patch
   applicator during the image build.
4. Generate `scripts/start-recording` for the inspected startup parameters.
   Follow the fixed lifecycle in the runtime reference; do not reconstruct it
   from another repository.
5. Create empty recording bind sources by translating each private source
   mount from `/data1/<project>/<path>` to
   `/data1/<project>-recording/<path>`. Keep container destinations unchanged,
   copy no original content, and recursively assign the new writable sources
   to numeric `998:998`.
6. Validate configuration, adapter construction, shell syntax, bounded
   startup, readiness, identity, dependency routing, and clean Recorder
   finalization.

## Source-Controlled Output

Limit initialization changes to:

```text
.traffic-e2e/project.yaml
.traffic-e2e/recorder.toml
.traffic-e2e/replay.yaml
.traffic-e2e/adapters/source/*
scripts/start-recording
scripts/mesh_switch_task.sh
.gitignore
```

Append only missing ignore entries for:

```text
/.traffic-e2e/local/
/.traffic-e2e/.env/
/.traffic-e2e/data/
/recordings/
```

Do not modify business source, build files, deployment files, CI, README, or
repository instructions. This skill creates files in the current branch; an
outer rewrite skill owns branch creation, commits, pushes, and pull requests.

## Completion

Run:

```bash
bash -n scripts/mesh_switch_task.sh
bash -n scripts/start-recording
./scripts/start-recording --duration-seconds 1
```

Report completion only after Recorder listeners, Breeze, and the genuine
source are ready; the genuine source Java process runs as numeric `998:998`;
`breeze.recording` resolves through fake DNS for that identity; and Recorder
finalizes cleanly. Do not send a business request or require a recorded case
during initialization.
