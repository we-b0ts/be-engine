# Migration Workflow

Use this reference when planning or executing one behavior-preserving rewrite
unit from a source repo into a target repo.

## Discovery

Inspect before implementation:

- source repo route definitions, scheduled jobs, workers, schemas, config, and
  relevant tests
- target repo structure, build system, `AGENTS.md`, existing test commands, and
  language conventions
- existing `docs/` structure, documentation conventions, and link-checking
  tools
- normal service startup entrypoints, runtime config, and dependency wiring
- existing command facade conventions such as Makefile, justfile, package
  scripts, or `scripts/*`
- existing config format and config directory conventions
- existing logging, tracing, access-log, and runtime artifact conventions
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
- managed dependency replay from `dependencies.jsonl`
- dependency coverage from `dependencies-summary.json`, when present
- JSON structural response compatibility, with exact-byte comparison only for
  non-JSON bodies or explicit exact-byte modes
- configured response ignores
- missing dependency diagnosis
- recording improvement feedback

Recorded dependency data is test evidence, not the target service's normal
runtime storage. The migrated implementation must have a real dependency
boundary for production-like startup, such as a database repository, external
service client, queue adapter, or scheduler input source. Recorded replay must
not replace that real runtime boundary; it belongs only inside the E2E harness
and replay tooling supplied by `recorded-e2e-cases`.

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

- ensure `AGENTS.md` exists or is merged as a concise documentation map
- ensure migration details live in structured docs under `docs/`, with
  `AGENTS.md` acting as a concise map
- create or update `.migration/e2e.yaml`
- create or reuse a repo-local development command facade
- create or reuse committed development config under `config/`
- create or reuse diagnostic logging for service startup, access, dependency
  failures, and replay diagnostics
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
- `runtime_stop_command`
- `runtime_status_command`
- `runtime_start_status`
- `config_files`
- `logging_config`
- `log_paths`
- `docs`
- `agents_md_status`
- `blockers`
- `recording_feedback`
- `runtime_dependency_status`
- `recorded_replay_status`

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
- `stop`: stop the local service idempotently without killing unrelated
  processes
- `restart`: run the same `stop` then `start` path
- `status`: report whether the service is running and include pid, port, or
  health details when available
- `e2e`: run the focused recorded E2E, or the configured recorded E2E suite
- `check`: run formatting, tests, linting, and relevant quality gates
- `build`: build the target artifact
- `release`: run the project's release/package flow when it exists
- `doctor`: print missing config, dependency, port, and toolchain problems

For the first migration slice, implement at least `start`, `stop`, `restart`,
`status`, `e2e`, `check`, and `doctor` when the target is a runnable service.
Commands may wrap language-native tools such as `cargo`, `go`, `npm`, Docker
Compose, `make`, or `just`; the stable interface for agents and users is the
facade command.

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

## Logging Contract

For runnable services, add or preserve diagnostic logs before declaring the
migration complete. Use [logging.md](logging.md) for the default contract.

When the target repo has no convention, default development logs to
`.migration/run/logs/` and include queryable categories for application
lifecycle, HTTP access or job triggers, actionable errors, and external
dependency calls. Keep logging configuration in `config/` with the rest of the
application runtime config.

Access logs are route/job-level summaries. They should show that the migrated
request entered the process, which route or job handled it, status or business
code, latency, request id, and recorded case id when present. Dependency logs
should preserve root causes from DB, HTTP, Redis, MQ, cache, and filesystem
boundaries. Error logs should make compatibility-hidden failures visible, such
as a source-compatible auth error whose real cause is a DB decode failure.

Do not log secrets, full DSNs, authorization headers, cookies, app keys, tokens,
or full request/response bodies by default. Prefer structured logs and
redaction. The command facade should make `status` show the log directory and
make E2E failures point to the relevant log path(s).

## Documentation Map Contract

Treat `AGENTS.md` as a navigation map, not the storage place for detailed
migration rules. Keep this contract short enough that agents can apply it
without a separate template file.

When creating or substantially updating target repo docs:

- keep `AGENTS.md` at 100 lines or fewer
- include only repo overview, essential entry points, and links to detailed
  docs
- place design decisions, execution plans, product/API specs, operations notes,
  recorded E2E contracts, failure handling, and references under `docs/`
- prefer the target repo's existing docs organization; if none exists, design a
  small structure under `docs/` that fits the project
- do not create empty boilerplate docs just to satisfy a template
- avoid duplicating the same rule in `AGENTS.md` and detailed docs
- update `.migration/e2e.yaml` with the docs paths and `agents_md_status`

If an existing `AGENTS.md` is already longer than 100 lines, do not make it
longer. Add the shortest possible migration map entry and move new migration
details into `docs/`. If safe, shrink the existing file into a map; otherwise
record a docs hygiene blocker.

Cross-links must be verifiable. Use the target repo's markdown/link checker or
CI convention when one exists. If none exists, make the command facade's
`doctor` or `check` verify that the files linked from `AGENTS.md` exist, and
record the command in `.migration/e2e.yaml`.

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
- recorded replay setup and case loaders used only by tests

Do not put the full migrated API into `main` plus one large library file merely
because the first recorded case is small. `main` should be bootstrap-only, and
the library root should mostly wire or export modules. Recorded replay wiring
should live in test support, E2E harnesses, or config used only by tests, not in
the normal runtime path. Combine responsibilities only when the scope is genuinely tiny
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
3. Add or reuse logging setup for startup, access, dependency, and replay
   diagnosis.
4. Choose or create the module layout before adding the handler/service code.
5. Confirm DB/MySQL schema evidence before finalizing runtime adapter field
   types. If schema is missing, record the unconfirmed status.
6. Implement or wire the real runtime dependency path separately from recorded
   replay. The default app/server startup must not require a recorded case path.
7. For API/service scopes, ensure a normal runnable entrypoint exists before
   declaring success. A library-only test harness is not enough for a migrated
   service API.
8. Run the focused recorded E2E through managed dependency replay.
9. Classify failures as target implementation bug, replay issue,
   incomplete recording, recording workflow improvement, or target setup issue.
10. Fix target implementation only when recorded replay evidence is complete.
11. Stop with a recording/E2E improvement list when evidence is missing or
   replay would require guessing.

After focused E2E passes, run the target repo's relevant quality checks. For
Rust, use the commands in `rust.md` unless the target repo already defines a
stricter standard.

For API/service scopes, verify the default runtime can start from normal
configuration without loading `tests/fixtures/recordings`. Prefer the command
facade, such as `scripts/<project>-cli start`, for the startup smoke. Use
`status` to confirm the local process and `stop` to clean it up. The smoke
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
- command facade lifecycle commands, E2E command, and quality commands run
- schema validation status for DB-backed scopes
- runtime lifecycle commands and verified process status for service scopes
- logging config and essential log path(s) for service scopes
- pass/fail result
- blockers or recording improvement feedback only when present
