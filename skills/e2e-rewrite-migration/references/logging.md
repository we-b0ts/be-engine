# Logging And Observability Contract

Use this reference when the migration target is a runnable service, worker, or
scheduled job. The goal is failure diagnosis for E2E migration, not a full
production observability platform.

## Contents

- [Required Outcomes](#required-outcomes)
- [Default Development Layout](#default-development-layout)
- [Log Files](#log-files)
- [Levels](#levels)
- [Structured Fields](#structured-fields)
- [Configuration](#configuration)
- [Rotation And Cleanup](#rotation-and-cleanup)
- [Command Facade Requirements](#command-facade-requirements)
- [Completion Rule](#completion-rule)

## Required Outcomes

The target implementation must make these questions answerable from logs:

- did the service start, which config did it read, and where are logs written?
- did the migrated request/job enter the target process?
- which route, handler, or job scope handled it?
- did recorded E2E use dependency replay, and which case/dependency records matched?
- did a real runtime dependency fail, and what was the root cause?
- is a failure due to target code, replay data, recording evidence,
  runtime config, or an external dependency?

Do not hide dependency or decode failures behind compatibility responses
without logging the root cause. It is acceptable for the HTTP response to
preserve the source system's business error code, but logs must retain the
underlying error.

## Default Development Layout

When the target repo has no convention, write development logs under:

```text
.migration/run/logs/
  app.log
  access.log
  error.log
  dependency.log
```

Use the repo's existing runtime/log directory if it already has one. Keep
`.migration/run/` ignored unless the target repo intentionally commits runtime
artifacts.

## Log Files

- `app.log`: process lifecycle, config loading, listener address, migration
  scope, selected runtime mode, graceful shutdown, and high-level workflow
  events.
- `access.log`: one entry per inbound HTTP request, route, or job trigger.
  Include method/path or job name, status, business code when present, latency,
  request id, and recorded case id when present.
- `error.log`: actionable failures such as panics, unhandled errors, config
  errors, dependency failures that affect behavior, and type/decode errors.
- `dependency.log`: DB, HTTP, Redis, Memcache, MQ, cache, filesystem, and other
  external boundary calls. Use it to distinguish real dependency failures from
  replay failures.

The implementation may write the same structured event to multiple sinks when
the logging library supports filtering. Do not require four physical files if
the target repo already has an equivalent structured logging convention, but
the four categories must remain queryable.

## Levels

- `error`: failures that require action or make a request/job incorrect, such
  as DB connection errors, SQL decode/type errors, missing config, panic, or
  third-party failures after retries.
- `warn`: compatible fallback or degraded behavior, such as returning a legacy
  business error while the store/client produced an internal error.
- `info`: startup and shutdown, selected config path, listener address,
  migration scope, request/job completion summaries, case loading summaries,
  and command facade lifecycle events.
- `debug`: SQL templates, downstream HTTP method/host/path, retry details,
  cache hit/miss, replay dependency match/miss/unused details, and E2E assertion
  diffs. Do not enable by default in production.
- `trace`: protocol frames, field-level decode details, or full internal spans.
  Keep disabled by default and never log secrets.

## Structured Fields

Prefer structured logs. Include these fields when available:

```text
timestamp
level
target/module
request_id
case_id
scope
method
uri
route_pattern
status_code
business_code
latency_ms
dependency.kind
dependency.name
error.kind
error.message
```

For dependency calls, include latency, operation name, result status, and a
redacted target such as DB name, HTTP host/path, queue name, or cache key
pattern. Do not log full SQL bind values, full request/response bodies, tokens,
cookies, passwords, secrets, app keys, authorization headers, or complete DSNs
unless the user explicitly asks for a secure diagnostic capture.

## Configuration

Keep logging config in the normal application config under `config/`, not in
`.migration/e2e.yaml`. A default shape may look like:

```yaml
logging:
  dir: ".migration/run/logs"
  level: "info"
  format: "json"
  stdout: true
  file: true
  buffer: "line"
  rotation:
    kind: "daily"
    max_size_mb: 100
    keep_days: 14
    keep_files: 30
  cleanup:
    enabled: true
```

Use equivalent names if the target repo has a convention. Development may use
pretty/text output for readability, but CI and production-like modes should
prefer JSON or another machine-readable structured format.

## Rotation And Cleanup

Default development behavior:

- line-buffer logs so failures are visible immediately
- rotate daily or when files exceed about 100 MB
- keep 7 to 14 days, or about 30 files
- clean expired files during startup or through the command facade

Default CI/E2E behavior:

- keep logs for the current run
- on E2E failure, print or point to the last relevant access, error, and
  dependency log entries
- avoid long-term retention unless the CI system collects artifacts

Default production-like behavior:

- write structured logs to stdout for platform collection
- keep local files as an optional fallback
- use environment/config overrides for level, format, directory, and retention

## Command Facade Requirements

For runnable service migrations, the command facade should:

- make `start` initialize logs with a useful default level, normally `info`
- redirect stdout/stderr to the configured log directory when running in the
  background
- make `status` report pid, port or health status, and log directory
- make `restart` preserve the same logging config path as `start`
- make `e2e` attach `case_id` or case path to replay logs when practical
- make `doctor` report missing log directory permissions or invalid logging
  config

If E2E fails, the final output should include the focused command and the
essential log path(s), not a full log dump.

## Completion Rule

Recorded E2E passing is not enough if the service cannot explain runtime
failures. For API/service scopes, completion requires at least startup logs and
enough access/dependency/error logging to diagnose why a real request or replay
failed. If the target repo already has an equivalent logging system, document
the mapping in `.migration/e2e.yaml` rather than adding a second system.
