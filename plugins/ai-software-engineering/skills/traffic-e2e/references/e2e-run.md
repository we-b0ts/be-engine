# Managed Replay E2E

Use `traffic-e2e` as the normal AI-facing replay runner. It owns Replay, target
lifecycle, HTTP requests, assertions, aggregation, progress, and publication.

## Project Configuration

Initialize all repository configuration once from the target root:

```bash
traffic-e2e config init --source-container <existing-source-container> [--breeze]
```

The generated version-7 configuration has separate `source`, optional `breeze`, `target`,
`replay`, `recording`, `delivery`, and `state` sections. Relevant target fields
are the conventional CLI, `.traffic-e2e/boot`, HTTP host, port, readiness,
timeouts, and response-size bound. Do not hand-write it.

Before a run, the runner requires:

- executable `scripts/<project>-cli`;
- valid recorder and replay config;
- ignored `.traffic-e2e/local/`;
- ignored `.traffic-e2e/boot/`; the directory itself may remain absent until
  target startup proves an authoritative input is required;
- a feature branch distinct from the configured PR base.

## Prepare One Canonical API

Confirm the route in source registrations, then run:

```bash
traffic-e2e prepare --target-root <target> \
  --case-source <exact-finalized-source> \
  --case-dir <canonical-case-directory> \
  --method <METHOD> --source-route '<source-route>' \
  --source-revision '<immutable-revision>'
```

Add `--pattern` only for a source-proven dynamic route. Use the returned
`group.group_id`; do not infer it from directories.

## Run One API

```bash
traffic-e2e run-api --target-root <target> \
  --case-source <exact-finalized-source> --api '<group.group_id>'
```

One attempt:

1. starts Replay and loads the selected cases;
2. invokes the target once as
   `scripts/<project>-cli start --e2e --start-breeze off --boot-dir
   .traffic-e2e/boot --port <configured-port>`;
3. waits for configured HTTP readiness;
4. decrypts request headers into a private temporary view when required;
5. sends every recorded request through the normal target HTTP endpoint;
6. asserts each response and keeps the target alive across the whole group;
7. invokes `scripts/<project>-cli stop` once and finalizes Replay.

The target CLI must force one compile during step 2. When its compile command
supports `--release`, that compile command must use `--release` and the CLI
must launch the release artifact. The option belongs to compilation; it is not
added to the `start` command shown above. Compilation occurs once per target
start, not once per case.

Keeping one target lifetime preserves observable local-cache, connection-pool,
startup, and warmup behavior. The target never reads a case or writes an actual
response artifact.

The terminal JSON is the engine result interface. Consume `status`, `passed`,
`gates`, bounded `diagnosis`, and `progress`; do not open report paths or
generated local state during normal operation. Explicit value presence
distinguishes JSON null, missing fields, and unavailable evidence. Report these
facts without choosing a migration repair.

## Full Round And Recovery

Run a full regression only when shared behavior could invalidate other groups:

```bash
traffic-e2e run --target-root <target> \
  --case-source <exact-finalized-source>
```

Use `traffic-e2e status` for interrupted state, `recover` for interrupted
publication/process recovery, and `abort` for an explicit interrupted result.
Never edit, rename, copy, or merge `.active`, `latest`, state, progress, or
report files.

Replay E2E passing proves compatibility with the selected recording. The
engine does not declare migration completion.
