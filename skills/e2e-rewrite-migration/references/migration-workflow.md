# Migration Workflow

Use this reference when planning or executing one behavior-preserving rewrite
unit from a source repo into a target repo.

## Discovery

Inspect before implementation:

- source repo route definitions, scheduled jobs, workers, schemas, config, and
  relevant tests
- target repo structure, build system, `AGENTS.md`, existing test commands, and
  language conventions
- normal service startup entrypoints, runtime config, and dependency wiring
- existing command facade conventions such as Makefile, justfile, package
  scripts, or `scripts/*`
- existing config format and config directory conventions
- existing module boundaries, package layout, and test-support conventions
- recorded cases under the user-provided location or target
  `tests/fixtures/recordings`

The source repo is for understanding behavior and intent. Do not assume a
function-by-function translation is required. Preserve API/interface output
compatibility and use target-language architecture that is stable and idiomatic.

## Scope Selection

Migrate one API/function at a time. If the user does not name the scope:

1. Search the source repo and recorded cases for low-risk HTTP GET routes.
2. Prefer a route with a complete recorded case and minimal side effects.
3. Present the route, recorded case path, and reason it is low risk.
4. Ask the user to confirm before implementing.

Default migration order is GET endpoints, then scheduled jobs, then write
operations and complex side-effect flows. For scheduled jobs, require a recorded
trigger/input and recorded dependency behavior sufficient to replay the job.

## Recorded E2E Contract

Recorded cases are mandatory. Existing source E2E tests can add context but do
not replace recorded cases.

Use `recorded-e2e-cases` for:

- case loading and dependency replay
- dependency mocks from `dependencies.jsonl`
- JSON structural response compatibility, with exact-byte comparison only for
  non-JSON bodies or explicit exact-byte modes
- configured response ignores
- missing dependency diagnosis
- recording improvement feedback

Recorded dependency data is test evidence, not the target service's normal
runtime storage. The migrated implementation must have a real dependency
boundary for production-like startup, such as a database repository, external
service client, queue adapter, or scheduler input source. Recorded mocks should
implement the same boundary only for E2E replay.

Default copied case location in the target repo is `tests/fixtures/recordings`.
Preserve original case files. A user-provided recording path may be a single
case directory or a collection such as `recordings/<rule>/<uri-group>` whose
child directories are case ids. When given a collection, select by reading each
child `request.json.uri` and matching the selected API path; do not rely on the
`uri-group` directory name alone. If zero or multiple cases match, ask the user
to choose before rewriting.

If the selected scope has no recorded case, stop before rewriting and recommend
what to record, including the route/job, expected dependencies, and completeness
checks.

## Target Artifacts

Before implementing behavior:

- ensure `AGENTS.md` exists or is merged with migration rules
- create or update `.migration/e2e.yaml`
- create or reuse a repo-local development command facade
- create or reuse committed development config under `config/`
- choose the target module layout for the selected scope
- identify the focused recorded E2E command
- identify target quality check commands

`.migration/e2e.yaml` must remain small and auditable. Track:

- `source_repo`
- `target_language`
- `current_scope`
- `recorded_cases`
- `status`
- `command_facade`
- `module_plan`
- `schema_sources`
- `schema_validation_status`
- `e2e_command`
- `quality_commands`
- `runtime_start_command`
- `runtime_start_status`
- `config_files`
- `blockers`
- `recording_feedback`
- `runtime_dependency_status`
- `recorded_mock_status`

## Command And Config Contract

Prefer the target repo's existing command facade. If it already uses `make`,
`just`, package scripts, or another clear convention, wire migration commands
through that convention and record them in `.migration/e2e.yaml`.

If no convention exists, create a source-controlled development CLI facade at
`scripts/<project>-cli`. This is a development/debug/build script, not a
compiled binary artifact. Do not place it under `bin/` unless the target repo
already uses `bin/` for source-controlled scripts.

Expose the commands that are relevant to the migrated scope:

- `start`: start the service from normal runtime config
- `restart`: stop and start, when the project has a managed local process
- `e2e`: run the focused recorded E2E, or the configured recorded E2E suite
- `check`: run formatting, tests, linting, and relevant quality gates
- `build`: build the target artifact
- `release`: run the project's release/package flow when it exists
- `doctor`: print missing config, dependency, port, and toolchain problems

For the first migration slice, implement at least `start`, `e2e`, `check`, and
`doctor` when the target is a runnable service. Commands may wrap language-native
tools such as `cargo`, `go`, `npm`, Docker Compose, `make`, or `just`; the
stable interface for agents and users is the facade command.

Place application config under `config/`. Development startup should read a
committed default config directly, such as `config/default.yaml` or the target
repo's preferred format. Add `config/e2e.yaml` when recorded E2E needs a
different but still source-controlled isolation config. Production may specify a
different config path, such as with `--config` or a project-specific environment
variable, and may override individual values through environment variables.

Keep real secrets and machine-local values out of committed config. If local
overrides are needed, use ignored files such as `config/local.yaml` or
`.env.local`, and provide a committed template only when useful. Do not use
`.migration/e2e.yaml` or `.recorded-e2e.yaml` as application runtime config:
`.migration/e2e.yaml` tracks migration state, while `.recorded-e2e.yaml`
controls recorded assertion behavior and dependency isolation.

## Module Design Contract

Before writing behavior code, choose a small module plan that fits the target
repo and selected scope. Prefer the target repo's existing boundaries. If the
repo is new or empty, create enough structure for the first migrated slice to
grow safely without adding empty placeholder modules.

Do not prescribe exact module or directory names. The agent should choose names
that fit the project and source domain, such as `api`, `handler`, `store`,
`repository`, `service`, `model`, `util`, `client`, or `adapter`. The important
requirement is an explicit design with clear ownership boundaries.

For service/API migrations, account for these responsibilities in the design:

- process startup and config loading
- router/controller or transport handlers
- service/business behavior
- domain/request/response models
- persistence or external client boundaries
- real runtime adapters for DB, HTTP, cache, MQ, or scheduler dependencies
- recorded replay mocks and case loaders used only by tests

Do not put the full migrated API into `main` plus one large library file merely
because the first recorded case is small. `main` should be bootstrap-only, and
the library root should mostly wire or export modules. Test-only recorded mocks
should live in test support or clearly isolated mock modules, not in the normal
runtime path. Combine responsibilities only when the scope is genuinely tiny
and the module plan explains why.

## Schema Mapping Contract

For DB/MySQL-backed scopes, do not map target runtime adapter types from source
language model fields alone. Use explicit schema evidence:

- semantic `response.columns` schema in `dependencies.jsonl`
- a user-provided schema, schema dump, migration file, or readonly/test DB
  schema

The recorded dependency schema is query-level schema: it describes columns
returned by recorded dependency calls, not necessarily the full database. It is
still the first source of truth for runtime decode types on the migrated query.

If explicit schema is available, record it in `.migration/e2e.yaml` under
`schema_sources` and set `schema_validation_status` to `confirmed` or a more
specific passed status. If schema is missing or incomplete, the agent may still
write code and pass recorded E2E, but it must set
`schema_validation_status: unconfirmed` or `partial` and must not mark the
migration complete. The final response must call out the missing schema evidence
and ask the user for a recording with semantic column schema or an explicit
schema source.

## Implementation Loop

Use at most 3 iterations:

1. Implement the smallest target behavior needed for the selected scope.
2. Add or reuse the command facade and config files needed for normal
   development startup.
3. Choose or create the module layout before adding the handler/service code.
4. Confirm DB/MySQL schema evidence before finalizing runtime adapter field
   types. If schema is missing, record the unconfirmed status.
5. Implement or wire the real runtime dependency path separately from recorded
   mocks. The default app/server startup must not require a recorded case path.
6. For API/service scopes, ensure a normal runnable entrypoint exists before
   declaring success. A library-only test harness is not enough for a migrated
   service API.
7. Run the focused recorded E2E through recorded mocks.
8. Classify failures as target implementation bug, mock/replay issue,
   incomplete recording, recording workflow improvement, or target setup issue.
9. Fix target implementation only when recorded replay evidence is complete.
10. Stop with a recording/E2E improvement list when evidence is missing or
   replay would require guessing.

After focused E2E passes, run the target repo's relevant quality checks. For
Rust, use the commands in `rust.md` unless the target repo already defines a
stricter standard.

For API/service scopes, verify the default runtime can start from normal
configuration without loading `tests/fixtures/recordings`. Prefer the command
facade, such as `scripts/<project>-cli start`, for the startup smoke. The smoke
should prove the service entrypoint exists and reaches bind or configuration
parsing. It may fail to connect to unavailable real dependencies only after
startup or when the migrated endpoint is exercised; it must not be hard-wired
to fixture data.

Do not complete the migration if the only runnable path is a recorded test app,
fixture-backed repository, or helper that requires a case directory. Add or
document the normal startup command, then update `.migration/e2e.yaml`.

## Completion Output

Keep output concise:

- migrated scope
- source repo path and recorded case path
- command facade, E2E command, and quality commands run
- schema validation status for DB-backed scopes
- runtime/startup command or verified startup status for service scopes
- pass/fail result
- blockers or recording improvement feedback only when present
