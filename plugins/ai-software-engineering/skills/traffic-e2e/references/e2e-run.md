# Managed Replay E2E

Use `traffic-e2e` as the normal AI-facing replay runner. It owns Replay, target
lifecycle, HTTP requests, assertions, aggregation, progress, and publication.

## Project Configuration

Initialize all repository configuration once from the target root:

```bash
traffic-e2e config init --source-container <existing-source-container> \
  [--env-file /path/to/initial.env]
```

The generated Recorder HTTP gateway listens on port `4080` by default; use
`--http-gateway-port` only when that port is unavailable.

The generated version-16 project configuration has separate `source`, `target`,
`replay`, `recording`, `delivery`, and `state` settings plus an embedded static
`recorder` section. `replay.case_dependency_post_response_window_ms`
keeps the active Replay case open for dependencies admitted just after the
primary response and defaults to 10 ms. AI-managed source-traffic evidence
acquisition and classification policy is kept in the separate
`.traffic-e2e/source-traffic-policy.yaml` document.
Relevant target fields are `.traffic-e2e/Dockerfile.e2e`, startup mount paths,
`startup_timeout_seconds` (180 by default, at most 1800), and optional quality
gates. The timeout bounds the interval from
target launch until every enabled endpoint passes readiness. Native HTTP port,
readiness probes, and request policy come from the embedded recorder. Do not
hand-write the generated project configuration.

When initialization creates the Rust bootstrap target, keep its temporary
`src/startup_probe.rs` module and `src/main.rs` call through initialization
preflight. Delete the module, declaration, and call when real target
implementation begins, as directed by the generated comments.

Before a run, the runner requires:

- a regular `.traffic-e2e/Dockerfile.e2e` and a root `.dockerignore` that
  excludes `.git/`, `.traffic-e2e/local/`, and `target/`;
- a required BuildKit SSH mount in the target Dockerfile and at least one
  default OpenSSH identity loadable by the repository-local managed agent;
- valid project, source traffic policy, and replay config;
- ignored `.traffic-e2e/local/`, ensured by repository initialization;
- a matching `.traffic-e2e/local/startup/` snapshot captured by initialization;
- a mode-0600 `.traffic-e2e/local/target.env`, created empty when no optional
  initialization env file is provided;
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
traffic-e2e manages the build agent at
`.traffic-e2e/local/socks/ssh-agent.sock`, recreates it when the socket is
stale, and forwards it directly to BuildKit. Failed builds return a bounded
actionable Docker/Cargo output tail in `diagnosis.lifecycle_errors`.

Keeping one target lifetime preserves observable local-cache, connection-pool,
startup, and warmup behavior. The target never reads a case or writes an actual
response artifact.

The runner executes the selected inventory through one process-wide active
case at a time, regardless of whether the primary request is HTTP or Motan.
Both replay adapters read the same `active_case_id`, so process-shared
dependencies remain attributed to that single case.

Motan2 response assertions compare the complete response frame after removing
only the framework-generated `M_pt` process-time metadata entry from both
sides. Response status, serialization, all other metadata, and the business
body remain exact. The recorded and live wire frames are not rewritten.

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
