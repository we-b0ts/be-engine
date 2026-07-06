# Target AGENTS.md Rules

Use this reference when creating or updating the target repo `AGENTS.md`.

## When To Write

If the target repo is empty, initialize the minimal target-language project
first, then create `AGENTS.md` so commands and paths are accurate.

If the target repo already has `AGENTS.md`, merge these rules into it. Preserve
existing project rules and add migration-specific sections. Do not replace the
file wholesale unless the user explicitly asks.

## Required Sections

The target `AGENTS.md` must include:

- project overview for the target rewrite
- source repo path and selected migration scope
- recorded case location, defaulting to `tests/fixtures/recordings`
- recorded case selection rule: collection directories must be filtered by
  `request.json.uri`
- E2E rule: recorded cases are the behavior contract
- compatibility rule: JSON responses use strict structural JSON comparison;
  exact bytes apply only to non-JSON or explicit exact-byte modes
- runtime dependency rule: recorded dependency data is test/mock evidence, not
  normal runtime storage
- normal lifecycle rule: API/service migrations require runnable service
  lifecycle commands before completion
- command facade rule: expose development operations through the repo's command
  facade, or `scripts/<project>-cli` when no convention exists
- service lifecycle rule: runnable services expose `start`, `stop`, `restart`,
  and `status`
- config rule: keep committed development runtime config under `config/`
- logging rule: runnable services provide diagnostic startup, access,
  dependency, and error logs with redaction
- module design rule: choose explicit module ownership before coding; do not
  require fixed module names
- schema mapping rule: DB/MySQL runtime types require explicit schema evidence
- rewrite rule: implement behavior in the target language; mechanical
  translation is not required
- source usage rule: read source code to understand behavior, not to preserve
  every source structure
- migration state rule: keep `.migration/e2e.yaml` current
- target language commands and quality checks
- failure classification: target bug, mock/replay issue, incomplete recording,
  recording workflow improvement, or setup issue

## Template Content

Write the target file in the target repo's voice, but include these obligations:

```markdown
# Repository Guidelines

## Migration Overview

This repository is a behavior-preserving rewrite of selected capabilities from
the source repository at: <source-repo-path>.

Current migration scope: <api-or-function-scope>.

This is a rewrite, not a mechanical translation. Use the source repository to
understand API contracts, data semantics, dependencies, and edge cases. Prefer
idiomatic target-language design as long as recorded E2E behavior remains
compatible.

## Recorded E2E Contract

Recorded cases under `tests/fixtures/recordings` are the compatibility contract.
Preserve original recorded case files. A migration is complete only when the
selected recorded E2E passes and the target repo quality checks pass.

If a path points at a collection such as `recordings/<rule>/<uri-group>`, treat
its child directories as candidate cases. Select the case by matching each
child `request.json.uri` to the migrated API path; do not rely on the
`uri-group` directory name alone.

JSON responses must be structurally compatible by default. Compare parsed JSON,
not serialized bytes: object key order and whitespace do not matter, but field
presence, value type, `null`, empty string, and missing field must match exactly.
Use exact-byte comparison only for non-JSON bodies or explicit exact-byte modes.
Ignore fields or headers only when explicitly configured in the recorded E2E
assertion config.

Use the recorded dependency data to build mocks. Do not invent missing
dependency rows, messages, cache values, or downstream responses.

Recorded dependency data is not runtime storage. The default service startup
must use normal configuration and real dependency boundaries. Tests may swap in
recorded mocks that implement the same boundary.

For API/service scopes, keep normal lifecycle commands documented and runnable:
`start`, `stop`, `restart`, and `status`. Do not mark a migration complete if
the only working path is a recorded E2E test harness or a fixture-backed app.

## Commands And Config

Use the repository command facade for development operations. If the repository
does not already have one, create `scripts/<project>-cli`; this is a committed
development script, not a built binary artifact. Prefer these command names
when relevant: `start`, `stop`, `restart`, `status`, `e2e`, `check`, `build`,
`release`, and `doctor`.

For runnable services, `stop` must be idempotent and avoid killing unrelated
processes. `restart` should run the same stop/start path. `status` should report
whether the local service is running and include pid, port, or health details
when available.

Keep application runtime config under `config/`. Development startup should read
a committed default config directly. Production may pass a different config file
or override values through environment variables. Keep secrets and machine-local
values in ignored files such as `config/local.yaml` or `.env.local`.

Do not use `.migration/e2e.yaml` or `.recorded-e2e.yaml` as application runtime
config. They are for migration state and recorded E2E behavior only.

## Logging And Diagnostics

Runnable services must provide logs that let an agent distinguish request
routing, target implementation bugs, dependency failures, mock/replay gaps, and
recording evidence gaps. If this repo has no existing logging convention, use
`.migration/run/logs/` for development logs with these categories: application
lifecycle, HTTP access or job trigger summaries, actionable errors, and external
dependency calls.

Access logs should include method, URI, route pattern when known, status code,
business code when present, latency, request id, and recorded case id when
present. Dependency logs should preserve DB/HTTP/cache/MQ root causes, including
decode/type errors, while redacting secrets. Do not log authorization headers,
cookies, tokens, app keys, passwords, full DSNs, or full request/response bodies
by default.

Keep logging config in `config/` with the runtime config. The command facade
should make `status` show the log directory and should point to relevant logs
when `e2e` fails.

## Architecture And Modules

Before writing a migration slice, choose the module layout that fits this repo.
Do not put the full migrated behavior into only `main` plus one large library
file. Module names are not prescribed; use names that fit the project, such as
`api`, `store`, `service`, `model`, `util`, `client`, or `adapter`.

For service/API scopes, make the design account for process startup,
routing/transport handlers, service behavior, models, dependency boundaries,
real runtime adapters, and recorded E2E mocks. Combine responsibilities only
when the scope is genuinely tiny and the module plan explains why.

Recorded mocks and case loaders are test support. They must not be wired into
the normal runtime path.

## Schema Mapping

For DB/MySQL-backed scopes, map runtime adapter types only from explicit schema
evidence: semantic column schema in `dependencies.jsonl`, or schema supplied by
the user through a schema dump, migration file, readonly/test DB, or equivalent.
Do not rely only on source-language model fields.

If explicit schema is unavailable, continue only with
`schema_validation_status: unconfirmed` or `partial`; do not mark the migration
complete until the schema gap is resolved.

## Migration State

Keep `.migration/e2e.yaml` updated with the source repo, target language,
current scope, recorded cases, status, commands, blockers, and recording
feedback. Track `command_facade`, `runtime_start_command`,
`runtime_stop_command`, `runtime_status_command`, `runtime_start_status`,
`config_files`, `logging_config`, `log_paths`, `module_plan`, `schema_sources`,
`schema_validation_status`, `runtime_dependency_status`, and
`recorded_mock_status` separately.

## Failure Handling

When E2E fails, classify the cause before changing code:

- target implementation bug
- dependency mock or replay issue
- incomplete recording
- recording workflow improvement needed
- target setup issue

If recording evidence is incomplete, stop and document what must be recorded or
improved instead of guessing behavior.
```

Add target-language sections after these rules. For Rust, include the commands
and conventions from `rust.md`.
