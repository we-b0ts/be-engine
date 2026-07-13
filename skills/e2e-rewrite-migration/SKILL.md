---
name: e2e-rewrite-migration
description: Use when rewriting or migrating one API, scheduled job, worker, or service capability from a local source repository into another language using recorded E2E cases as the behavior contract. Requires a user-provided source repo path, recorded cases, target repo or current workspace, a concise AGENTS.md map with linked migration docs, and E2E proof before completion.
---

# E2E Rewrite Migration

Rewrite behavior, not source text. Complete one API or function only when its
entire selected case set, dependency touch contract, normal startup, and target
quality checks pass.

## Required Inputs

- local source repository path
- target repository path, or the current workspace
- target language; read [rust.md](references/rust.md) for Rust
- at least one published recorded case for the selected scope

Stop and request any missing source path, target language, or recording before
implementation. Source E2E tests may supplement but not replace recordings.

## Workflow

1. Inspect source routes/jobs, target conventions and startup, and recorded
   cases. Build a method/path-to-case matrix when several APIs or a collection
   is supplied. If scope is unspecified, propose one complete low-risk GET and
   ask for confirmation.
2. Migrate one API/function at a time and include every matching case. Prefer
   GET, then scheduled jobs, then writes and complex side effects.
3. Prepare a scope branch from `dev-migration`. If that branch is missing,
   stop and ask; preserve unrelated work. Completed migrations require a
   focused commit and PR to `dev-migration`.
4. Keep target `AGENTS.md` as a concise navigation map with detailed migration
   rules under `docs/`. Create or update the small, auditable
   `.migration/e2e.yaml`, including project recorder config and route-pattern
   feedback state when present, as described in
   [migration-workflow.md](references/migration-workflow.md).
5. Treat recordings as external inputs. Do not copy or commit them unless the
   user asks or the target repo has that convention. Make the E2E command accept
   an external case path, normally `--case-dir <path>`.
6. Use `recorded-e2e-cases` as the single source for case selection,
   case-to-source-route association, request construction, managed replay,
   dependency coverage, response comparison, failure diagnosis, and recorder
   feedback. Keep replay and recordings read-only; place project-specific
   recorder config feedback in the target repo. Do not duplicate or weaken that
   contract in the target harness.
7. Reuse the target repo's command, config, and logging conventions. Treat
   existing package and module structure as a candidate pattern rather than an
   automatic precedent; validate it against current target rules. When a
   convention is absent, follow the defaults in `migration-workflow.md` and
   [logging.md](references/logging.md). Choose an initial topology before
   behavior code without assuming the first boundary will be final.
8. Implement an idiomatic real runtime dependency path and normal startup.
   Replay fixtures and recorded params must remain outside the default runtime
   path.
9. Map DB adapter types from explicit semantic dependency schema or a supplied
   schema. Record missing schema as unconfirmed and do not claim completion.
10. Preserve source metrics and side effects unless the user approves a
    contract change. Add focused unit/component tests for non-trivial local
    logic without duplicating recorded E2E assertions.
11. Iterate implementation, focused replay, and fixes at most three times.
    After the focused case set first passes, perform the structural convergence
    review in `migration-workflow.md`, rerun the selected cases, then perform
    the semantics review, startup smoke, and target quality checks.

## Completion Blockers

- no published case for the selected scope
- dirty or incomplete dependency replay
- no normal runnable startup, or startup requires recorded fixtures
- missing diagnostic logs for a runnable service
- recorded params embedded in normal config or product logic
- DB type mapping without explicit schema evidence
- source metrics or required side effects unimplemented or unverified
- architecture or required structural convergence incomplete
- unit-test, dynamic-value, or semantics review incomplete
- no focused branch, commit, or PR to `dev-migration`

When recording evidence is incomplete, stop with the missing evidence and
recorder improvement list instead of guessing.

## Output

Keep the final response short: migrated scope and source, rewrite input and PR
case sources, selected case-set result, startup/E2E/quality commands, PR target
and URL, blockers, route-pattern feedback status, and evidence-backed recording
feedback when present.
