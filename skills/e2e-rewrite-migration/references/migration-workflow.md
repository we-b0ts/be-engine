# Migration Workflow

Use this reference when planning or executing one behavior-preserving rewrite
unit from a source repo into a target repo.

## Contents

- [Discovery](#discovery)
- [Scope Selection](#scope-selection)
- [Recorded E2E Contract](#recorded-e2e-contract)
- [Metrics Contract](#metrics-contract)
- [Unit And Component Test Contract](#unit-and-component-test-contract)
- [Git Baseline And PR Delivery](#git-baseline-and-pr-delivery)
- [Target Artifacts](#target-artifacts)
- [Command And Config Contract](#command-and-config-contract)
- [Logging Contract](#logging-contract)
- [Documentation Map Contract](#documentation-map-contract)
- [Runtime Value Strategy](#runtime-value-strategy)
- [Module Design Contract](#module-design-contract)
- [Structural Convergence](#structural-convergence)
- [Schema Mapping Contract](#schema-mapping-contract)
- [Migration Semantics Review](#migration-semantics-review)
- [Implementation Loop](#implementation-loop)
- [Completion Output](#completion-output)

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
- recorded cases under the user-provided location or the target repo's existing
  configured case source, if any

The source repo is for understanding behavior and intent. Do not assume a
function-by-function translation is required. Preserve API/interface output
compatibility and use target-language architecture that is stable and
idiomatic. Existing target code is evidence of constraints and prior decisions,
but its structure is not an automatic precedent. Validate nearby patterns
against current target rules before extending them.

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

Recorded cases are mandatory and external to the target repository unless the
user explicitly approves committed fixtures. Use the `recorded-e2e-cases`
skill as the single source for case discovery, request construction, managed
replay, response comparison, dependency touch coverage, dynamic recorded
values, assertion configuration, and failure diagnosis.

For multiple APIs or collection paths, build a method/path-to-case matrix from
published child `request.json` files. Include every matching case for the
selected API; never select from `failed`, `staging`, or `.replay`, and do
not collapse a case set to one representative case.

Normal runtime must use real dependency boundaries and must not load recordings
or copy recorded params into product config. A migration remains incomplete
while replay has unexplained unmatched calls, unused case exchanges, missing
required side effects, or incomplete semantic evidence.

## Metrics Contract

Metrics are part of observable behavior when the source capability emits them.
Do not silently drop metrics during a rewrite just because the HTTP response
contract passes. Classify metrics by delivery model, not by source language,
framework, or metrics library:

- push metrics are outbound side effects. They may be sent over UDP, TCP, HTTP,
  or a company-specific transport. Validate them from recorded or replayed
  dependency evidence when that evidence exists.
- pull metrics are exported service state. They may be exposed through
  Prometheus, OpenMetrics, or a custom scrape endpoint. Validate them through
  the configured exporter or scrape endpoint when the source behavior includes
  one.

For push metrics, implement the real runtime metrics client or adapter that the
target service should use. Do not satisfy the migration by replacing metrics
with project-local mocks or by writing recorded metric payloads from the E2E
harness. Replay/report tooling owns side-effect comparison.

For pull metrics, ensure the service starts the exporter with normal runtime
startup and verify that a focused request or job updates the expected metric
family. Keep labels and dimensions stable; avoid high-cardinality request data
unless the source contract explicitly uses it.

When metrics behavior exists in the source code but recorded cases, replay
output, source docs, or existing tests are not enough to reproduce it, keep the
migration incomplete with `metrics_contract_status: metrics_unconfirmed`.
List the missing evidence and recommend the recording or verification step
needed to confirm the metrics contract.

## Unit And Component Test Contract

Recorded E2E is the compatibility contract, not the only test layer. Add
focused unit or component tests for local logic that would otherwise require a
full recorded replay to diagnose.

Prefer unit/component tests for:

- request parsing, response shaping, serializers, and compatibility helpers
- runtime config loading, environment overrides, redaction, and validation
- dynamic value strategies such as clocks, request ids, table suffixes, and
  generated ids
- schema/type mapping and external adapter conversion logic
- signing, canonicalization, metrics normalization, and protocol-specific
  payload builders
- error mapping, retry classification, and dependency boundary behavior

Do not create broad brittle tests that duplicate recorded E2E assertions. The
unit layer should make product logic easier to debug when recorded replay
fails. If a migrated scope changes non-trivial logic but has no meaningful unit
or component tests, record `unit_test_status: insufficient` and do not present
the quality gate as complete without calling out that gap.

## Git Baseline And PR Delivery

Use `dev-migration` as the target repo integration branch for migration work.
Do not commit completed rewrites directly to `main`, `master`, or
`dev-migration`.

Before implementation, or before handoff if work already exists, inspect
`git status --short` and the current branch in the target repo.

If the current branch is not `dev-migration`:

1. Preserve current updates with a named stash, including untracked files when
   needed.
2. Switch to `dev-migration`, using `origin/dev-migration` as the tracking
   source when the local branch does not exist.
3. Pull latest with a fast-forward-only update.
4. Create a scope branch from `dev-migration`.
5. Reapply the stash only if it contains intended migration work, resolve
   conflicts, and keep unrelated user changes separate or report them.

If the current branch is already `dev-migration`, still create a scope branch
before making migration commits. If `dev-migration` is missing locally and
remotely, stop and ask whether to create it instead of guessing the base.

Name the scope branch from the migrated unit, such as
`codex/migrate-api-user-list` or `migration/api-user-list`, following the
target repo's branch naming convention when one exists.

After E2E, startup smoke, quality checks, and reviews pass, commit the focused
changes and open a PR from the scope branch to `dev-migration`. Do not leave a
completed migration only unstaged, staged, stashed, or on a local branch with no
PR. If the repository has no reachable PR mechanism, keep the migration
incomplete and report the branch, commit, and blocker.

## Target Artifacts

Before implementing behavior:

- ensure `AGENTS.md` exists or is merged as a concise documentation map
- ensure migration details live in structured docs under `docs/`, with
  `AGENTS.md` acting as a concise map
- create or update `.migration/e2e.yaml`
- identify the rewrite input case paths separately from the PR E2E case source
- create or reuse a repo-local development command facade
- create or reuse committed development config under `config/`
- create or reuse diagnostic logging for service startup, access, dependency
  failures, and replay diagnostics
- choose the target package/module layout for the selected scope and apply code
  organization gates
- identify the focused recorded E2E command
- identify target quality check commands

`.migration/e2e.yaml` must remain small and auditable. Track:

- `source_repo`
- `target_language`
- `current_scope`
- `scope_case_matrix` when several APIs or case sets are involved
- `rewrite_input_cases`
- `pr_e2e_case_source`
- `pr_e2e_cases`
- `e2e_case_arg`
- `status`
- `git_base_branch`
- `git_work_branch`
- `pr_target_branch`
- `pr_url`
- `stash_name` when work was moved from another branch
- `command_facade`
- `package_layout`
- `workspace_decision`
- `module_plan`
- `module_topology_review`
- `architecture_review_status`
- `schema_sources`
- `schema_validation_status`
- `e2e_command`
- `unit_test_status`
- `quality_commands`
- `runtime_start_command`
- `runtime_stop_command`
- `runtime_status_command`
- `runtime_start_status`
- `config_files`
- `logging_config`
- `log_paths`
- `metrics_contract_status`
- `docs`
- `agents_md_status`
- `blockers`
- `recording_feedback`
- `runtime_dependency_status`
- `recorded_replay_status`
- `dynamic_value_strategy_status`
- `semantics_review_status`

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
- `e2e`: run the focused recorded E2E, or the configured recorded E2E suite;
  accept an external local case path such as `--case-dir <path>` unless the
  repo already has an equivalent case-source argument
- `check`: run formatting, tests, linting, and relevant quality gates
- `build`: build the target artifact
- `release`: run the project's release/package flow when it exists
- `doctor`: print missing config, dependency, port, and toolchain problems
  including `traffic-replay`, `traffic-replay-cli`, and
  `traffic-recorder-proxy` when recorded E2E is part of the repo workflow

For the first migration slice, implement at least `start`, `stop`, `restart`,
`status`, `e2e`, `check`, and `doctor` when the target is a runnable service.
Commands may wrap language-native tools such as `cargo`, `go`, `npm`, Docker
Compose, `make`, or `just`; the stable interface for agents and users is the
facade command. The focused recorded E2E should call `traffic-replay` from
`PATH` and control active cases with `traffic-replay-cli` from `PATH`, not a
skill-local helper path. It should pass the provided `--case-dir` through to
the replay/E2E harness and must not hardcode the user's rewrite input path in
source code, config, or tests. CI or PR workflows may download or mount cases
first, then call the same facade with `--case-dir`.

Place application config under `config/`. Development startup should read a
committed default config directly, such as `config/default.yaml`. Add
`config/e2e.yaml` when recorded E2E needs a different but still
source-controlled isolation config. Production may specify a different config
path, such as with `--config` or a project-specific environment variable.

Support environment-variable overrides for config values. The environment
variable name is the full config key path converted to uppercase snake case:
join nested keys with `_`, convert `-` and other non-alphanumeric separators to
`_`, and collapse repeated `_`. Examples:

- `aliyun.access_key_id` -> `ALIYUN_ACCESS_KEY_ID`
- `aliyun.access_key_secret` -> `ALIYUN_ACCESS_KEY_SECRET`
- `huaweiyun.regions.cn-north-4.secret_key` ->
  `HUAWEIYUN_REGIONS_CN_NORTH_4_SECRET_KEY`

Read config files first, then apply environment variables when they are
present. Environment variables have higher priority than committed config and
local config files.

Default runtime config must describe behavior, not a captured case. Examples:
use a strategy such as current-month table suffix, system clock, generated
request id, authenticated user, tenant from request/session, or ids read from
database state. E2E config may pin recorded values only when the pin is visibly
test-only and the normal startup path does not require it.

Keep real secrets and machine-local values out of committed config. For keys
whose name or meaning includes password, secret, appkey/app_key, access key,
token, authorization, or private credentials, keep the key present in
`config/default.yaml` but leave its committed value blank. Require runtime
values through environment variables or an ignored local override. When any
such key exists, create or maintain `config/.env.example` with the derived
variable names and blank values. Do not commit real `.env`, `.env.local`, or
`config/local.yaml` files. Do not use `.migration/e2e.yaml` or
`.recorded-e2e.yaml` as application runtime config: `.migration/e2e.yaml`
tracks migration state, while `.recorded-e2e.yaml` controls recorded assertion
behavior and dependency isolation.

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

## Runtime Value Strategy

Before declaring success, identify dynamic values seen in `request.json`,
`expected-response.json`, and `dependencies.jsonl`, then map each value to its
runtime source:

- request input or headers
- authenticated/session context
- database or external dependency result
- system clock or request-start time
- generated id or UUID
- deterministic product rule, such as current `YYYYMM` table suffix
- explicit product config supplied by the user or source repo
- E2E-only replay override

Values found only in recorded dependencies are not enough to create product
defaults. If source code does not show why the selected request owns a value or
dependency touch, keep `dynamic_value_strategy_status` incomplete and report a
source-analysis or recorder-correlation blocker. Do not add a config knob just
to make the replay coverage pass.

## Module Design Contract

Before writing behavior code, choose a small initial module plan that fits the
target repo and selected scope. Treat existing boundaries as candidate patterns
and validate their ownership, lifecycle, and dependency direction against the
target repo's current rules. If the repo is new or empty, create enough
structure for the first migrated slice to grow safely without adding empty
placeholder modules.

Review module topology before implementation and whenever expanding an existing
domain. Look for domain clusters, prefix-sprawl files, oversized files,
catch-all modules, and test/replay support leaking into normal runtime modules.
Choose a structure that makes ownership obvious. Directory namespaces are often
better when a domain has multiple cohesive sub-responsibilities, but do not
reorganize purely for aesthetics or against the repo's conventions.

Treat names as responsibility contracts. Use package and directory namespaces
for stable domain and capability ownership; use short leaf filenames for direct
responsibilities. Do not repeat parent prefixes to simulate hierarchy. Three or
more same-prefix sibling product files are a possible implicit namespace: when
they share one owner, lifecycle, and entry point, create a real namespace before
extending the cluster. Choose the parent by ownership, not by mechanically
copying the prefix or preserving the first protocol, vendor, or use case.

Production source composition such as Rust `include!` does not create a module
boundary or satisfy cohesion and size gates. Generated code and macro input are
valid exceptions; ordinary behavior should use the language's real module or
package mechanism and narrow interfaces.

Decide package layout before implementation. Default to one package/crate for
one API/function when the target repo has no stronger convention. Use a
workspace or multi-package layout only when the user asks for it, the target
repo already uses one, the selected scope spans multiple runnable artifacts, or
there is a real shared library boundary needed by multiple APIs, jobs, or
services. If the need is uncertain, record `workspace_decision:
needs_confirmation` and ask the user before creating the workspace.

Do not prescribe exact module or directory names. Choose names that fit the
project and source domain; require clear ownership boundaries rather than a
template vocabulary.

Record the pre-change decision in `module_topology_review` as `keep`,
`extract-first`, or `follow-up`. Use `follow-up` only when the current scope does
not expand the identified problem; use `extract-first` for the smallest boundary
needed by the current migration.

The pre-change decision is a hypothesis, not a promise that the first layout is
final. Reassess it after behavior and dependency paths exist, then update
`architecture_review_status` from the implemented structure rather than the
initial plan.

For service/API migrations, account for these responsibilities in the design:

- process startup and config loading
- router/controller or transport handlers
- service/business behavior
- domain/request/response models
- persistence or external client boundaries
- real runtime adapters for DB, HTTP, cache, MQ, or scheduler dependencies
- recorded replay setup and case loaders used only by tests

Keep responsibilities separated by dependency direction. Transport/handler code
parses requests and renders responses; it should not own SQL, cache, MQ, or
third-party protocol details. Service/use-case code owns business orchestration
and should not depend on framework request/response types. Domain and wire DTOs
should not depend on DB drivers, replay fixtures, or test harnesses. Adapters
own external protocol details behind narrow interfaces. Test support must not
be imported by the normal runtime path.

Treat broad `util` modules as temporary. A utility module should have a clear
topic such as time, ids, redaction, serialization, or config helpers. If a
utility file accumulates unrelated responsibilities, split it before completing
the migration.

Apply code-size gates to product source files. Warn and self-review when a new
or heavily modified file exceeds 600 lines; split or document the reason before
800 lines; do not mark the migration complete if a product source file exceeds
1000 lines without a user-approved exception. Exceptions are limited to
generated code, checked-in protocol tables, or repo conventions that are already
validated by the target project.

Do not put the full migrated API into `main` plus one large library file merely
because the first recorded case is small. `main` should be bootstrap-only, and
the library root should mostly wire or export modules. Recorded replay wiring
should live in test support, E2E harnesses, or config used only by tests, not in
the normal runtime path. Combine responsibilities only when the scope is
genuinely tiny and the module plan explains why.

## Structural Convergence

After the focused recorded E2E case set first passes, review the implemented
code against its actual responsibilities, names, dependency direction, and
runtime/test separation. The passing case set protects behavior while the
initial module hypothesis is refined.

Refactor the smallest relevant boundary when the migration introduced or
exposed any of these signals:

- a name or parent no longer covers the implemented behavior
- cross-domain behavior sits under one protocol, vendor, or first use case
- shared infrastructure is owned by one of several unrelated consumers
- inaccurate ownership requires wider visibility, copied code, or catch-all
  helpers
- new prefix sprawl or mixed runtime/test ownership appeared

This convergence pass is part of the current migration. Do not defer a mismatch
introduced or expanded by the migrated scope merely because E2E is green. Keep
unrelated legacy cleanup as follow-up work.

After structural changes, rerun the affected unit/component tests and the full
selected recorded E2E case set. Set `architecture_review_status` from that
post-refactor result. If the required convergence or verification is incomplete,
do not mark the migration complete.

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

## Migration Semantics Review

After implementation and before final success, review the target changes against
the source repo and replay report:

- every case-owned dependency touch is implemented or explicitly classified as
  unrelated/background with source or recorder evidence
- target E2E requests are built from each case's `request.json`, without
  hardcoded case-specific headers, query params, or bodies
- replay session readiness is verified before requests, every selected case is
  bracketed by begin/end, and aggregate replay reports are clean
- MySQL touches use the recorded business target host, database/schema, and
  username/role as dependency identity; log databases, read/write roles,
  tenants, and shards must map to explicit runtime adapters instead of sharing
  one pool by accident
- no normal runtime config or product logic contains fixed values copied from
  recorded dependency params
- dynamic values have runtime strategies recorded in `.migration/e2e.yaml`
- metrics emitted by the source capability are implemented, verified, or
  explicitly recorded as `metrics_unconfirmed`
- non-trivial local logic has focused unit or component tests, or
  `unit_test_status: insufficient` is recorded with a reason
- DB/MySQL adapter types come from explicit schema evidence, not source-language
  model guesses
- package/workspace decisions and module boundaries match the code that was
  actually implemented
- new or heavily modified product source files pass the code-size gates, or a
  user-approved exception is recorded
- E2E-only fixtures, replay listeners, and case loaders cannot be reached from
  the default service startup path
- intended behavior changes, including dropped legacy side effects, have
  explicit user approval

If any item is uncertain, do not mark the migration complete. Record
`semantics_review_status: incomplete` or `architecture_review_status:
incomplete` and include the specific blocker.

## Implementation Loop

Use at most 3 iterations:

1. Implement the smallest target behavior needed for the selected scope.
2. Add or reuse the command facade and config files needed for normal
   development startup.
3. Add or reuse logging setup for startup, access, dependency, and replay
   diagnosis.
4. Choose or create the package/module layout before adding the
   handler/service code.
5. Confirm DB/MySQL schema evidence before finalizing runtime adapter field
   types. If schema is missing, record the unconfirmed status.
6. Define runtime strategies for dynamic recorded values. Keep fixed recorded
   values out of normal config unless the source repo proves they are true
   product defaults.
7. Implement or wire the real runtime dependency path separately from recorded
   replay. The default app/server startup must not require a recorded case path.
8. For API/service scopes, ensure a normal runnable entrypoint exists before
   declaring success. A library-only test harness is not enough for a migrated
   service API.
9. Add or update focused unit/component tests for the local logic introduced by
   the scope.
10. Run the focused recorded E2E through managed dependency replay and verify
   that all selected case-owned dependency touches are matched.
11. After the focused case set first passes, perform structural convergence and
   rerun the affected unit/component tests and full selected case set.
12. Perform the migration semantics review against the converged implementation.
13. Classify failures as target implementation bug, replay issue,
   incomplete recording, recording workflow improvement, or target setup issue.
14. Fix target implementation only when recorded replay evidence is complete.
15. Stop with a recording/E2E improvement list when evidence is missing or
   replay would require guessing.

After focused E2E passes, run the target repo's relevant quality checks. For
Rust, use the commands in `rust.md` unless the target repo already defines a
stricter standard.

For API/service scopes, verify the default runtime can start from normal
configuration without loading recorded cases. Prefer the command facade, such
as `scripts/<project>-cli start`, for the startup smoke. Use `status` to
confirm the local process and `stop` to clean it up. The smoke should prove the
service entrypoint exists and reaches bind or configuration parsing. It may
fail to connect to unavailable real dependencies only after startup or when the
migrated endpoint is exercised; it must not be hard-wired to fixture data.

Do not complete the migration if the only runnable path is a recorded test app,
fixture-backed repository, or helper that requires a case directory. Add or
document the normal startup command, then update `.migration/e2e.yaml`.

## Completion Output

Keep output concise:

- migrated scope
- source repo path and recorded case path or selected case set
- git base branch, work branch, PR target, and PR URL when available
- command facade lifecycle commands, E2E command, and quality commands run
- schema validation status for DB-backed scopes
- runtime lifecycle commands and verified process status for service scopes
- logging config and essential log path(s) for service scopes
- selected recorded case set pass/fail result
- package/workspace decision and architecture review status
- dependency touch status, especially any unmatched target calls or unused case
  exchanges
- dynamic value strategy and semantics review status
- blockers or recording improvement feedback only when present
