# Managed Replay E2E

Use `traffic-e2e` as the normal AI-facing replay runner. It owns Replay, target
lifecycle, HTTP requests, assertions, aggregation, progress, and publication.

## Project Configuration

Initialize all repository configuration once from the target root:

```bash
traffic-e2e config init --source-pod <pod> --namespace <namespace> \
  [--pod-container <regular-container>] \
  [--kubeconfig /path/to/kubeconfig] \
  [--env-file /path/to/initial.env] \
  [--http-backend-port 8080] \
  [--http-gateway-port 4080]
```

The source and target backend HTTP port defaults to `8080`; use
`--http-backend-port` when both backends listen on another port. The generated
Recorder HTTP gateway listens on port `4080` by default; use
`--http-gateway-port` only when that listener port is unavailable. The two
ports must differ.

The generated version-18 project configuration has separate `source`, `target`,
`policy`, `replay`, `verification`, `delivery`, and `state` settings plus an
embedded static `recorder` section.
`replay.case_dependency_post_response_window_ms`
keeps the active Replay case open for dependencies admitted just after the
primary response and defaults to 10 ms.
`verification.max_failed_cases_per_api` defaults to 10 and stops the current
API after that many non-passing cases; remaining cases are left unexecuted.
All acquisition, classification, input and comparison rules share the
`traffic-policy/v3` document named by `project.policy`, normally
`.traffic-e2e/policy.yaml`. Initialization creates this policy empty.
Relevant target fields are `.traffic-e2e/Dockerfile.target`, startup mount paths,
and `startup_timeout_seconds` (180 by default, at most 1800).
`project.replay.startup_timeout_seconds` controls dependency service readiness
(default 60), independently of index/case loading timeouts. HTTP requests use
the recorded Source response duration plus
`project.replay.request_timeout_allowance_seconds` (default 30, range 1..1800).
These execution budgets can be increased on slower hosts without changing assertions.
Quality gates are
an engine standard rather than project configuration. The timeout bounds the interval from
target launch until every enabled endpoint passes readiness. Native HTTP port,
readiness probes, and request policy come from the embedded recorder. Do not
hand-write the generated project configuration.

When initialization creates the Rust bootstrap target, keep its temporary
`src/startup_probe.rs` module and `src/main.rs` call through initialization
preflight. Delete the module, declaration, and call when real target
implementation begins, as directed by the generated comments.

Before a run, the runner requires:

- a regular `.traffic-e2e/Dockerfile.target` and a root `.dockerignore` that
  excludes `.git/`, `.traffic-e2e/local/`, and `target/`;
- at least one default OpenSSH identity loadable by the repository-local
  managed agent when the target Dockerfile uses a BuildKit SSH mount;
- valid project settings and one compiled unified policy;
- ignored `.traffic-e2e/local/`, ensured by repository initialization;
- a validated `.traffic-e2e/local/source/` snapshot containing the immutable
  source image identity and Kubernetes runtime inputs;
- a matching `.traffic-e2e/local/startup/` snapshot captured by initialization;
- a mode-0600 `.traffic-e2e/local/target.env`, created empty when no optional
  initialization env file is provided; source application environment is
  loaded first and this file supplies overrides or additions;
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
2. builds `.traffic-e2e/Dockerfile.target`, validates its immutable image, and
   starts its OCI entrypoint once as `998:998` in a system-owned namespace;
3. waits for configured HTTP readiness;
4. decrypts request headers into a private temporary view when required;
5. sends every recorded request through the normal target HTTP endpoint;
6. asserts each response and keeps the target alive across the whole group;
7. sends `SIGTERM`, requires a clean target exit, removes the target namespace,
   and finalizes Replay.

The project's Dockerfile selects its base images, build tools, stages, and
caches. When the Dockerfile uses a BuildKit SSH mount, traffic-e2e manages the
build agent at `.traffic-e2e/local/socks/ssh-agent.sock`, recreates it when the
socket is stale, and forwards it directly to BuildKit. Failed builds return a
bounded, actionable output tail in `diagnosis.lifecycle_errors`.

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
