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

1. Inspect target conventions and startup, the supplied recording layout, and
   source route registrations. When several APIs or a collection are supplied,
   do not analyze every business implementation or build one simultaneous
   migration scope. Use the incremental directory and API-group selection in
   `recorded-e2e-cases`: select one unprocessed directory, resolve its first
   published case to a source route, then run `traffic-case-group ensure`
   without `--pattern` for a static route or with the safe pattern for a dynamic
   route. Retain the canonical grouping evidence. If scope is unspecified,
   start with one complete low-risk GET group.
2. Only after selecting a valid group, inspect and migrate that one API/function
   and include every returned matching case. Finish the group as `complete`,
   `incomplete`, or `blocked` before selecting another group. Prefer GET, then
   scheduled jobs, then writes and complex side effects.
3. Prepare a scope branch from `dev-migration`. If that branch is missing,
   stop and ask; preserve unrelated work. Completed migrations require a
   focused commit, pushed scope branch, and PR to `dev-migration`.
4. Before changing product code, inspect target `AGENTS.md` as a read-only
   repository contract. It MUST state or link to a recorded-migration
   definition of done covering all of these clauses:
   - source-route-resolved directory grouping before business implementation,
     exactly one API group at a time, and immutable published recordings;
   - final-state replay of the entire selected case set;
   - a source-controlled `config/replay.yaml`, validated dynamic-value policy
     evidence, and `expected-response.json` used only as the final assertion
     oracle;
   - required recorder-owned aggregate evidence;
   - managed `case_path_patterns` planning and application;
   - recorder-owned `verified-excludes ensure` after final aggregate and
     assertions, with no AI eligibility decision;
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
   contract in the target harness. Maintain the single source-controlled
   `config/replay.yaml` required by `recorded-e2e-cases`, validate it before
   replay, and pass it explicitly to every replay. `expected-response.json`
   MUST remain assertion-only: product code, test setup, dependency mocks,
   replay rules, branch decisions, cache decisions, and side effects MUST NOT
   read it to construct actual behavior. Replay-policy v1 does not support
   background/noise exceptions or case-id allowlists; keep such groups
   incomplete or re-record them instead of duplicating exceptions elsewhere.
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
11. Iterate implementation, focused replay, and fixes while each cycle produces
    new evidence or fixes a distinct evidenced defect. Always replay after a
    behavior-affecting change; final verification is mandatory and is not a
    retry. If the same root cause repeats for three consecutive cycles without
    new evidence or meaningful progress, stop that group as `blocked` or
    `incomplete`. After the focused group first passes, perform the structural
    convergence review in `migration-workflow.md`, rerun that group, then
    perform the semantics review, startup smoke, and target quality checks.

## Non-Negotiable Completion Gate

Apply these gates in order: repository contract, canonical API grouping, final
replay, aggregate, route-pattern feedback, startup/quality checks, focused
commit, push, PR, and run-ledger update. MUST NOT report a migration as complete
or delivered until every item is independently verified:

1. Set `repository_contract_status: confirmed` only after directly verifying
   every required target `AGENTS.md` clause and linked document. Any missing or
   weaker clause is `blocked_repository_contract`, not a warning.
2. Verify every selected directory and case belongs to exactly one ordered API
   group from `recorded-e2e-cases`. Retain each static validation or dynamic
   `traffic-case-group ensure` report and returned group directory or manifest.
   Require the current group to reach a terminal state before the next begins,
   and confirm the original recording tree was not moved, copied, renamed,
   deleted, or edited. A blocked group permits an explicit partial handoff but
   keeps the parent selected scope incomplete.
3. Rerun the entire selected case set after the final change to product code,
   runtime/dependency config, E2E harness, replay/assertion policy, or dependency
   wiring. Any later change in those categories invalidates the replay and
   returns the workflow to this gate. Any unverified fix leaves the migration
   `incomplete`.
4. Validate the target `config/replay.yaml`, record its canonical path and
   fingerprint, require zero unused applicable rules, and retain a direct audit
   showing that `expected-response.json` is read only by final assertion code.
   Any reverse data flow from the expected response into actual responses,
   dependency mocks, runtime inputs, branches, caches, or side effects is a
   hard failure, even when all assertions pass.
5. Satisfy the `recorded-e2e-cases` completion gate. Record its exact aggregate
   status/path/coverage, case-path-pattern plan status/path, and verified API
   exclude threshold/count/ensure status and report path. Generic
   `not-applicable`, `skipped`, `not-needed`, or an unpersisted terminal result
   is forbidden.
6. Run normal-startup smoke and all target-required quality checks against the
   final verified tree. Record the exact commands and results. A subset of
   checks, an earlier run, or a facade summary cannot satisfy this gate.
7. Create a focused commit containing only the intended migration, push the
   scope branch, and create a PR targeting
   `dev-migration`. Verify the remote branch and PR target through canonical Git
   and hosting interfaces. Record the branch, commit SHA, PR target, and PR URL.
   A local branch, local commit, push without PR, or text saying a PR is planned
   is never delivery. If credentials, permissions, or missing authority prevent
   an external write, stop as `blocked_delivery`; do not silently omit it or
   claim completion. After committing, require no uncommitted intended-scope
   changes; otherwise the committed tree is not the verified final tree.
8. Store these artifacts in the per-run state: final case source; ordered API
   groups, member directories, grouping statuses/reports/manifests, and selected
   ids; replay-policy path/fingerprint/rule usage and expected-response audit;
   final session ids and replay reports; aggregate status/path/counts;
   pattern status and plan/apply/verification paths; verified-exclude assertion
   and ensure-report paths/status; startup/quality results;
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
- missing, invalid, implicit, or stale `config/replay.yaml`, or unused
  applicable dynamic-value rules
- `expected-response.json` read outside final assertion comparison, including
  any use to construct actual responses, dependency mocks, inputs, decisions,
  caches, or side effects
- missing or incomplete target `AGENTS.md` recorded-migration contract
- missing, mixed, ambiguous, stale, overlapping, or unprocessed API grouping
- published recording directories changed during grouping or migration
- final behavior-affecting change not replayed against the entire selected set
- missing or incomplete aggregate replay report
- missing applicable case-path-pattern plan report or unresolved plan diff
- missing verified-exclude ensure report/count when managed config exists,
  AI-authored eligibility branching, or an `applied` result without embedded
  apply and no-change verification evidence
- no focused branch, commit, pushed branch, or PR to `dev-migration`

When recording evidence is incomplete, stop with the missing evidence and
recorder improvement list instead of guessing.

## Output

Start the final response with exactly one state: `complete`, `incomplete`, or
`blocked`. Then keep it short: migrated scope and current recording run,
ordered API groups and grouping artifacts, rewrite input and PR case sources,
replay-policy path/fingerprint/rule usage, expected-response assertion-only
audit, final selected-case replay, aggregate, pattern-plan, and verified-exclude
artifact paths/statuses,
startup/E2E/quality commands, branch, commit SHA, PR target/URL, blockers, and
evidence-backed recording feedback. MUST NOT use success wording while any gate
is missing.
