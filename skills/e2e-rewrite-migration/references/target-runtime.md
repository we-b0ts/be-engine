# Target Runtime Contract

Read this reference when inspecting or changing target startup, configuration,
dependency wiring, command entrypoints, logging, or the repository map.

## Repository Instructions And Map

Inspect target `AGENTS.md` and linked documents before editing. This skill and
`recorded-e2e-cases` own the canonical migration definition of done; target
instructions may add stricter repository-specific requirements without
repeating those gates.

Record `repository_contract_status: agents_linked` when `AGENTS.md` declares
the canonical skills, or `repository_contract_status: skill_managed` when it
does not. Missing linkage alone is not a blocker. Stop with
`blocked_repository_contract` only for an unresolved target instruction that
conflicts with or weakens a canonical gate.

Treat repository policy as read-only during ordinary migration. If the current
change makes the factual map inaccurate or materially incomplete, add, update,
or remove only affected paths, entrypoints, commands, or documentation links.
Verify changed links against the final tree. Do not create `AGENTS.md`, change
policy, or alter its completion-gate declaration without an explicit user
request naming that policy change.

When migration notes and a migration changelog exist or are created, keep their
paths in this factual map. Mark the notes as required reading before migration
or replay and the changelog as one concise entry per delivered increment. See
[repository-memory.md](repository-memory.md) for content boundaries.

## Real Runtime And Replay Boundary

Implement a normal startup path that uses the target's genuine dependency
interfaces, production adapters, and real protocol clients. Recorded E2E MUST
exercise that same dependency path while traffic is intercepted or explicitly
routed to recorder-owned replay listeners.

Target product code, E2E code, test support, command facades, and normal config
MUST NOT read, parse, copy, or derive dependency results from
`dependencies.jsonl` or dependency fixtures. They also MUST NOT read
`expected-response.json` outside the final assertion path. Do not introduce a
recording-backed, fixture-backed, fake, or in-process dependency implementation
to make recorded E2E pass.

Focused unit tests may isolate pure local logic, but they cannot replace
recorded E2E or provide migration completion evidence for dependency behavior.

## Standard Project Facade

Every runnable migration target MUST expose one executable, source-controlled
facade at `scripts/<project>-cli`. Resolve `<project>` from the repository's
existing facade, stable project name, or target instructions. If the repository
already uses Make, just, Cargo, Go, npm, or another native command surface, keep
it and delegate to it from the facade rather than duplicating its logic.

The facade MUST provide these stable commands:

- `start`: start the normal runnable target without loading recordings;
- `stop`: idempotently stop only the process owned by this project command;
- `status`: report running state plus useful pid, port, health, or diagnostic
  location and return a non-zero status when the target is not running;
- `test`: run ordinary target unit and component tests without recorded E2E;
- `e2e --case-dir <path>`: execute the one currently active case through the
  target's genuine runtime path and perform only the final response assertion;
- `check`: run the target's submission-quality format, lint, static analysis,
  and test gates.

`build`, `restart`, `doctor`, and `release` are optional. Do not force them into
the first migration unless the target already has those commands or the current
scope needs them.

Keep the facade thin. It MUST:

- delegate to repository-native commands and propagate their exit status;
- keep `start`, `test`, and `check` independent of recorded case files;
- make `e2e` require the exact case directory supplied by `traffic-e2e` and
  propagate its assertion exit status;
- clean up processes it starts without killing unrelated processes;
- remain source-controlled and portable within the target repository.

It MUST NOT start or finalize replay, call begin/end, aggregate reports, update
progress, run verified-exclude eligibility, select an interception UID or user,
read dependency recordings to produce results, or use the expected response
outside final assertions. Its exit code is assertion output, never canonical
replay evidence.

Record the exact facade path in the project migration index and keep it in the
factual `AGENTS.md` repository map when that map exists. For runnable services,
require `start` and `status` to prove normal configuration and listener
initialization, then use `stop` for cleanup. Real dependencies may be unavailable
only after startup or when the migrated capability is invoked.

## Application Configuration

Follow the target repository's existing config format, environment override
convention, and local-file loading behavior. When it has no convention, use:

- committed `config/default.yaml` for ordinary non-sensitive defaults;
- committed `config/.env.example` to define supported environment variables;
- Git-ignored `config/.env` for actual local values used by normal startup.

Put secrets and other machine-local values in environment variables rather than
`config/default.yaml`. Every variable in `config/.env.example` MUST map to
target config code and the normal startup path MUST load `config/.env` when it
exists. Preserve explicit process-environment values over file values. Do not
create an inert template whose variables are never consumed.

Keep normal runtime config about product behavior, not one recording. Derive
runtime-generated values from request or session context, dependency state,
time, generated ids, or explicit product configuration proven by source
behavior.

## E2E Environment Materialization

Before materializing a value, trace its authoritative source through the source
startup path. Generate Git-ignored `.traffic-e2e/.env` only for values that the
source obtains directly from process environment, startup arguments, or
machine-local configuration. Recorded request or connection evidence, including
`dependencies.jsonl`, may supply such a value offline only after source code or
startup configuration proves that provenance.

When the source loads a value from a database, configuration service, secret
service, or another runtime dependency, implement the same genuine dependency
path in the target and let recorder-owned replay provide the result. Never infer
or materialize such a value from a recorded downstream request. Missing required
dependency evidence keeps the migration incomplete; do not bypass it with an
environment variable. Do not require a person to reconstruct a large eligible
startup configuration by hand, invent unavailable values, or copy case-specific
business data into configuration.

For eligible materialized inputs, this is an offline migration operation.
Target product code, test code, and command facades MUST NOT read
`dependencies.jsonl` at runtime; they receive only ordinary environment
variables. Make the recorded-E2E startup path actually load
`.traffic-e2e/.env`, preferably through
`traffic-e2e target exec --env-file`. Use this precedence:

1. explicitly supplied process environment;
2. `.traffic-e2e/.env`;
3. `config/.env`;
4. `config/default.yaml`.

Log which variable names were materialized, their source evidence, and any
unresolved names without printing values by default. Add `config/.env`,
`.traffic-e2e/.env`, and `.traffic-e2e/local/` to the target root `.gitignore`
and verify each path with `git check-ignore`.

## Replay-Owned Configuration

Keep replay-only dependency matching rules in the single source-controlled
`.traffic-e2e/replay.yaml` owned by `recorded-e2e-cases`; keep the traffic E2E
recorder configuration beside it as `.traffic-e2e/recorder.toml`. Do not
duplicate either in shell, target code, or application config.

## Diagnostics

Reuse existing logging and tracing. For a runnable service, require enough
startup, request or job, dependency-boundary, and error context to diagnose a
failed migration without logging secrets. Read [logging.md](logging.md) only
when the target lacks an equivalent diagnostic convention or the current
migration must change it.
