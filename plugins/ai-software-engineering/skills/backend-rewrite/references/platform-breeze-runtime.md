# Platform And Breeze Target Contract

Use this reference for Platform Java/Tomcat sources whose service discovery and
dependency clients are owned by Breeze.

## Target Repository Contract

The initialized target repository provides:

- one genuine source application container in `.traffic-e2e/project.yaml`;
- `scripts/<project>-cli start --e2e --boot-dir
  .traffic-e2e/local/boot --port <port>`;
- an idempotent `scripts/<project>-cli stop`; and
- source-compatible startup inputs under `.traffic-e2e/local/boot/`.

Each `start --e2e` invocation performs one normal project compile before
launch. If that compile supports release mode, compile and launch the release
artifact; do not add a `--release` argument to the `start` interface itself.

The conventional existing Breeze container is `breeze` unless project config
names another one. For a Breeze-dependent target, `start --e2e` does not start
Breeze; source and target use the coordinator-managed Breeze lifecycle.

The target repository contains only product startup and shutdown behavior. It
does not own recording, comparison, container, truststore, source-adaptation,
or case-execution control flow.

## Coordinator Contract

The coordinator preserves the genuine source runtime contract, supplies the
managed Breeze and recording lifecycle, waits for readiness, records the
selected scope, finalizes evidence, and cleans up. Execute only the exact
commands returned by `backend-rewrite` actions.

During comparison, source and target use the same Breeze lifecycle. No second
Breeze instance belongs to the target startup path.

## Acceptance

- The configured source container can be inspected.
- Standard recording completes without failed cases or lifecycle errors.
- Comparison uses one shared Breeze and passes the configured target port.
- Cleanup succeeds after completion, failure, or interruption.
- No generated runtime-control script is committed to the target repository.
