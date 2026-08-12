# Managed Replay E2E

Use `traffic-e2e` as the normal AI-facing replay runner. It owns Replay, target
lifecycle, HTTP requests, assertions, aggregation, progress, and publication.

## Project Configuration

Initialize all repository configuration once from the target root:

```bash
traffic-e2e config init --source-container <existing-source-container> [--breeze] \
  [--startup-mount /data1/weibo/confs] [--startup-env WEIBO_CONF_PATH]
```

The generated Recorder HTTP gateway listens on port `17171` by default; use
`--http-gateway-port` only when that port is unavailable.

The generated version-14 project configuration has separate `source`, optional
`breeze`, `target`, `replay`, `recording`, `delivery`, and `state` settings plus
an embedded static `recorder` section. All AI-managed rules are kept in the
separate `.traffic-e2e/coordinator-rules.yaml` document.
Relevant target fields are `.traffic-e2e/Dockerfile.e2e`, explicit startup
mount paths and environment names, and optional quality gates. Native HTTP
port, readiness, and request policy come from the embedded recorder. Do not
hand-write the generated project configuration.

Before a run, the runner requires:

- a regular `.traffic-e2e/Dockerfile.e2e` and a root `.dockerignore` that
  excludes `.git/`, `.traffic-e2e/local/`, and `target/`;
- valid project, coordinator-rules, and replay config;
- ignored `.traffic-e2e/local/`, ensured by repository initialization;
- a matching `.traffic-e2e/local/startup/` snapshot captured by initialization;
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
2. builds `.traffic-e2e/Dockerfile.e2e`, validates its immutable image, and
   starts its OCI entrypoint once as `998:998` in a system-owned namespace;
3. waits for configured HTTP readiness;
4. decrypts request headers into a private temporary view when required;
5. sends every recorded request through the normal target HTTP endpoint;
6. asserts each response and keeps the target alive across the whole group;
7. sends `SIGTERM`, requires a clean target exit, removes the target namespace,
   and finalizes Replay.

BuildKit cache mounts preserve Cargo registry, git, and target artifacts across
builds. Source changes may rerun Cargo, but must not force dependency downloads
when the pinned builder and stable cache IDs are unchanged.

Keeping one target lifetime preserves observable local-cache, connection-pool,
startup, and warmup behavior. The target never reads a case or writes an actual
response artifact.

The runner executes the selected inventory through one process-wide active
case at a time, regardless of whether the primary request is HTTP or Motan.
Both replay adapters read the same `active_case_id`, so process-shared
dependencies remain attributed to that single case.

The terminal JSON is the primary engine result interface. Consume `status`,
`passed`, `gates`, bounded `diagnosis`, and `progress` first. Read-only runtime
inspection is available when those APIs are insufficient, but its paths and
layout are not stable contracts. Explicit value presence distinguishes JSON
null, missing fields, and unavailable evidence. Report these facts without
choosing a migration repair.

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
