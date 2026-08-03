# Managed Platform And Breeze Runtime

Use this reference for Platform Java/Tomcat sources whose service discovery and
dependency clients are owned by Breeze.

## Repository Contract

The target repository provides only:

- one existing genuine source application container in
  `.traffic-e2e/project.yaml`;
- `scripts/<project>-cli start --e2e --start-breeze off --boot-dir
  .traffic-e2e/boot --port <port>`;
- `scripts/<project>-cli stop`;
- source-compatible startup inputs discovered under `.traffic-e2e/boot/`.

Each `start --e2e` invocation forces one normal project compile before launch.
If that compile command supports `--release`, it must compile with
`--release` and launch the release artifact. `--release` is not added to the
`start` subcommand itself.

The conventional existing Breeze container is `breeze` unless project config
explicitly names another one. The target repository provides no recording,
comparison, Docker, truststore, Mesh patch, or case-execution scripts.

The inspected Breeze container is a runtime template, not the image to launch.
traffic-e2e always launches its pinned Breeze E2E image while preserving the
container's command, environment, mounts, user, limits, capabilities, and
security settings. Managed recording owns the replacement network topology.
The system-owned images are:

- Breeze `v0.1.21-e2e@sha256:5aba065755724d43c7da3f6b79ac82890a0a0a08c6ae3f43af12558b5e52462f`;
- network anchor `0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62`;
- Recorder runtime `0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107`.

Do not build these in the target repository. `record` pulls them when needed.

## traffic-e2e Ownership

For standard recording, traffic-e2e:

1. validates the encryption key before changing runtime state;
2. inspects the source image and the Breeze container environment, working directory,
   entrypoint/command, mounts, user, limits, capabilities, and security options;
3. creates uniquely named managed containers and private diagnostics;
4. builds a fixed capture-only adapter from the inspected source image when
   Platform Mesh interception requires image rewriting;
5. applies only the embedded traffic transport patch, runs the source as its
   required fixed user, and does not alter source business code or switches;
6. pulls the fixed Breeze E2E, anchor, and Recorder images, then starts them
   with the adapted source in the required
   network topology, installs the Recorder CA/truststore, waits for readiness,
   captures the selected scope, finalizes the manifest, and cleans up.

The adapter is traffic-e2e product code. The target AI must neither generate
nor customize it. Any required business-behavior patch is invalid source
mutation, not an adapter extension.

Prepare the adapter after preflight and before starting managed containers.
The managed runtime fingerprints the inspected source image identity and every
adapter build input. It reuses the retained target-scoped cache image only when
that fingerprint matches; otherwise it rebuilds and replaces the stable cache
tag. Never prepare it during `config init`, comparison, or replay. Remove the
run-private build context during cleanup, but retain the matching cache image
for later standard recordings.

For comparison, traffic-e2e reproduces the genuine source runtime, starts one
shared genuine Breeze, starts the target with `--start-breeze off`, waits for
both applications, records source/candidate responses, finalizes the manifest,
and stops every managed process. Source and target must see the same Breeze
lifecycle; do not start a second Breeze from the target CLI.

## Commands

Initialize all repository configuration once from the target root:

```bash
traffic-e2e config init --source-container <source-container> --breeze
```

Record one API:

```bash
traffic-e2e record --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --brz-no-fallback true --api '<METHOD path>'
```

Record a comparison only after replay E2E passes:

```bash
traffic-e2e record-comparison --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --brz-no-fallback true --api '<METHOD path>'
```

The command's single JSON result identifies the exact `run_id` and finalized
manifest. Retain that path; do not discover artifacts through recency.

## Acceptance

- The source container supplied in project config is inspected successfully.
- The standard recording manifest is completed with no failed cases or errors.
- Comparison uses one shared Breeze and the target start command includes the
  configured `--port`.
- Cleanup runs on success, failure, and interruption.
- No generated Platform runtime script is committed to the target repository.
