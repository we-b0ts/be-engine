---
name: e2e-rewrite-migration
description: Use when rewriting or migrating one API, scheduled job, worker, or service capability from a local source repository into another language using recorded E2E cases as the behavior contract. Requires a user-provided source repo path, recorded cases, target repo or current workspace, a concise AGENTS.md map with linked migration docs, and E2E proof before completion.
---

# E2E Rewrite Migration

Rewrite behavior, not source text. Complete one API or function only when its
entire selected case set, dependency touch contract, normal startup, and target
quality checks pass.

## Mandatory Semantics

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Migration
completion is an AND gate, not a progress score. Partial implementation may be
handed off, but MUST remain `incomplete` or `blocked` until every required
evidence and delivery gate passes. A target helper's success message cannot
waive or satisfy a gate.

## Required Inputs

- local source repository path
- target repository path, or the current workspace
- target language; read [rust.md](references/rust.md) for Rust
- at least one published recorded case for the selected scope
- target `AGENTS.md` containing or linking the required recorded-migration
  definition of done; inspect it read-only

Stop and request any missing source path, target language, or recording before
implementation. Report a missing or incomplete target `AGENTS.md` contract as
`blocked_repository_contract`; do not add it. Source E2E tests may supplement
but not replace recordings.

## Workflow

1. Inspect source routes/jobs, target conventions and startup, and recorded
   cases. Build a method/path-to-case matrix when several APIs or a collection
   is supplied. If scope is unspecified, propose one complete low-risk GET and
   ask for confirmation.
2. Migrate one API/function at a time and include every matching case. Prefer
   GET, then scheduled jobs, then writes and complex side effects.
3. Prepare a scope branch from `dev-migration`. If that branch is missing,
   stop and ask; preserve unrelated work. Completed migrations require a
   focused commit, pushed scope branch, and PR to `dev-migration`.
4. Before changing product code, inspect target `AGENTS.md` as a read-only
   repository contract. It MUST state or link to a recorded-migration
   definition of done covering all of these clauses:
   - final-state replay of the entire selected case set;
   - required recorder-owned aggregate evidence;
   - managed `case_path_patterns` planning and application;
   - focused commit, pushed scope branch, and PR to `dev-migration`;
   - target scripts and AI-authored facades are helpers, not completion proof.
   This skill does not authorize creating or modifying target `AGENTS.md`.
   MUST NOT edit it unless the user separately and explicitly requests that
   exact change. If the contract is absent or weaker, stop before implementation
   with `blocked_repository_contract` and report the clauses the repository
   owner must add; do not repair it silently. Keep `.migration/e2e.yaml` as the
   small current-run index and store each recording run separately as described in
   [e2e-run-state.md](references/e2e-run-state.md) and
   [migration-workflow.md](references/migration-workflow.md).
5. Treat recordings as external inputs. Do not copy or commit them unless the
   user asks or the target repo has that convention. Make the E2E command accept
   an explicit external case path, normally `--case-dir <path>`. Never hardcode
   or silently default to a developer-machine recording path.
6. Use `recorded-e2e-cases` as the single source for case selection,
   case-to-source-route association, request construction, managed replay,
   dependency coverage, response comparison, failure diagnosis, and recorder
   feedback. Keep replay and recordings read-only; place project-specific
   recorder config feedback in the target repo. Do not duplicate or weaken that
   contract in the target harness. Keep any replay exception/background policy
   in one source-controlled target file shared by the command facade and
   target-language E2E; do not duplicate allowlists between them.
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

## Non-Negotiable Completion Gate

Apply these gates in order: repository contract, final replay, aggregate,
route-pattern feedback, startup/quality checks, focused commit, push, PR, and
run-ledger update. MUST NOT report a migration as complete or delivered until
every item is independently verified:

1. Set `repository_contract_status: confirmed` only after directly verifying
   every required target `AGENTS.md` clause and linked document. Any missing or
   weaker clause is `blocked_repository_contract`, not a warning.
2. Rerun the entire selected case set after the final change to product code,
   runtime/dependency config, E2E harness, replay/assertion policy, or dependency
   wiring. Any later change in those categories invalidates the replay and
   returns the workflow to this gate. Reaching the iteration limit after an
   unverified fix leaves the migration `incomplete`.
3. Satisfy the `recorded-e2e-cases` completion gate. Record its exact aggregate
   status/path/coverage and case-path-pattern plan status/path. Generic
   `not-applicable`, `skipped`, `not-needed`, or an unpersisted terminal result
   is forbidden.
4. Run normal-startup smoke and all target-required quality checks against the
   final verified tree. Record the exact commands and results. A subset of
   checks, an earlier run, or a facade summary cannot satisfy this gate.
5. Create a focused commit containing only the intended migration, push the
   scope branch, and create a PR targeting
   `dev-migration`. Verify the remote branch and PR target through canonical Git
   and hosting interfaces. Record the branch, commit SHA, PR target, and PR URL.
   A local branch, local commit, push without PR, or text saying a PR is planned
   is never delivery. If credentials, permissions, or missing authority prevent
   an external write, stop as `blocked_delivery`; do not silently omit it or
   claim completion. After committing, require no uncommitted intended-scope
   changes; otherwise the committed tree is not the verified final tree.
6. Store these artifacts in the per-run state: final case source and selected
   ids, final session ids and replay reports, aggregate status/path/counts,
   pattern status and plan/apply/verification paths, startup/quality results,
   branch, commit SHA, PR target, and PR URL. The ledger records evidence; it
   does not create evidence.

Treat target-project scripts and command facades, including AI-authored ones,
as convenience orchestration only. Their exit status or self-written ledger is
not proof of completion. MUST NOT add a completion gate only to such a facade
or patch it merely to claim compliance. Verify recorder artifacts, Git state,
pushed branch, and PR state independently through canonical interfaces.

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
- missing or incomplete target `AGENTS.md` recorded-migration contract
- final behavior-affecting change not replayed against the entire selected set
- missing or incomplete aggregate replay report
- missing applicable case-path-pattern plan report or unresolved plan diff
- no focused branch, commit, pushed branch, or PR to `dev-migration`

When recording evidence is incomplete, stop with the missing evidence and
recorder improvement list instead of guessing.

## Output

Start the final response with exactly one state: `complete`, `incomplete`, or
`blocked`. Then keep it short: migrated scope and current recording run,
rewrite input and PR case sources, final selected-case replay, aggregate and
pattern-plan artifact paths/statuses, startup/E2E/quality commands, branch,
commit SHA, PR target/URL, blockers, and evidence-backed recording feedback.
MUST NOT use success wording while any gate is missing.
