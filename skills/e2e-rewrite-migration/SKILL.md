---
name: e2e-rewrite-migration
description: Use when rewriting or migrating one API, scheduled job, worker, or service capability from a local source repository into another language using recorded E2E cases as the behavior contract. Requires a source repo, target repo or current workspace, target language, published cases, real dependency paths, a standard project CLI facade, final E2E evidence, and PR delivery.
---

# E2E Rewrite Migration

Rewrite behavior, not source text. Complete one capability only when its entire
selected case set, genuine dependency path, normal startup, target quality
checks, focused commit, pushed branch, and PR are verified from the final tree.

## Mandatory Semantics

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Completion is
an AND gate. Partial implementation may be handed off, but remains `incomplete`
or `blocked`. Target helpers and migration ledgers are never canonical proof.

A blocker prevents a completion claim, but does not prevent incremental
delivery. Commit, push, and create a PR for useful focused changes while
accurately reporting unresolved blockers.

Use `recorded-e2e-cases` as the sole owner of case grouping, managed replay,
dependency coverage, response assertions, replay policy, aggregate reports,
route-pattern feedback, verified excludes, and their completion artifacts. Do
not duplicate or weaken that contract here or in the target repository.

Keep stable project metadata in `.migration/e2e.yaml`. Put every mutable or
generated migration artifact under the Git-ignored `.migration/local/` layout
defined by [e2e-run-state.md](references/e2e-run-state.md). MUST NOT stage,
commit, or force-add `.migration/local/`; ignoring it never waives evidence.

## Required Inputs

- local source repository path;
- target repository path, or the current workspace;
- target language;
- at least one published recorded case for the selected scope.

Stop and request a missing source path, target language, or published recording
before implementation. Source tests may supplement but never replace recordings.

## Reference Routing

- Read [migration-workflow.md](references/migration-workflow.md) for the stage
  order.
- Read the language reference only for the selected language, such as
  [rust.md](references/rust.md).
- Read [delivery.md](references/delivery.md) before choosing a branch and again
  before commit, push, and PR.
- Read [target-runtime.md](references/target-runtime.md) before changing startup,
  dependency wiring, config, commands, diagnostics, or `AGENTS.md`.
- Read [implementation-quality.md](references/implementation-quality.md) after
  grouping and again after the selected group first passes.
- Read [e2e-run-state.md](references/e2e-run-state.md) for the current run index
  and per-run evidence state.
- Read [logging.md](references/logging.md) only when runnable-service diagnostics
  are absent or changed by the current migration.

## Workflow

1. Inspect target instructions and conventions, the supplied recordings, source
   route registrations or job wiring, normal startup, and Git state. Before
   generating migration state, require `.migration/local/` in the target root
   `.gitignore` and verify it with `git check-ignore`.
2. Use `recorded-e2e-cases` to select exactly one canonical API/function group.
   If no API is named, begin with one complete low-risk GET group. Do not analyze
   every business implementation or build one simultaneous migration scope.
3. Resolve the PR base from user or repository evidence and create a focused
   feature branch when worktree state permits. Never assume a universal base
   branch or automatically stash and switch a dirty worktree.
4. Inspect only the selected source capability. Implement idiomatic target
   behavior with normal startup and the same genuine dependency interfaces,
   production adapters, and protocol clients used during recorded E2E.
   Provide the standard `scripts/<project>-cli` facade and delegate its commands
   to the target repository's native build and test tools.
5. Target product code, E2E code, test support, commands, and normal config MUST
   NOT read `dependencies.jsonl`, dependency fixtures, or
   `expected-response.json` to produce actual behavior. The expected response is
   assertion-only; recorded dependency data is supplied only by recorder-owned
   replay.
6. Run the entire selected group through `recorded-e2e-cases`. Fix product code
   only after replay evidence proves a real behavior defect. Finish or
   explicitly block the current group, including its applicable immediate
   verified-excludes result, before selecting another.
7. After the group first passes, perform structural convergence and migration
   semantics review, then rerun the entire selected group. Run normal-startup
   smoke and target-required quality checks from the final tree.
8. Update only factual `AGENTS.md` map entries made inaccurate or materially
   incomplete by the current change. Do not create the file or change repository
   policy or completion gates without explicit user authorization.
9. Commit only intended changes, push the feature branch, create a PR to the
   resolved integration branch, verify the remote state, and update the run
   index with canonical artifact paths and identifiers. Exclude all files under
   `.migration/local/` from staging and delivery. Do not skip incremental
   delivery solely because the migration remains `incomplete` or `blocked`.

Continue the implementation/replay loop while each cycle adds evidence or fixes
a distinct evidenced defect. If the same root cause repeats for three
consecutive cycles without progress, stop that group as `blocked` or
`incomplete`. A final verification after the last behavior-affecting change is
mandatory and is never counted as a retry.

## Non-Negotiable Completion Gate

MUST NOT claim a migration complete or delivered unless all items hold:

1. Target instructions are inspected. Record
   `repository_contract_status: agents_linked` when they declare the canonical
   skills, or `repository_contract_status: skill_managed` when they do not.
   Missing linkage is not a blocker; an unresolved conflicting or weakening
   instruction is `blocked_repository_contract`. The final factual repository
   map matches the implemented tree for the current scope.
2. The integration branch is resolved from user or repository evidence, the
   intended work is isolated on a focused feature branch, and unrelated changes
   are preserved.
3. `recorded-e2e-cases` returned one valid canonical group containing every
   selected case exactly once, and published recordings remain unchanged.
4. Normal runtime and recorded E2E use genuine dependency paths. No target-side
   recording-backed, fixture-backed, fake, or in-process dependency
   implementation reads recorder dependency data or constructs actual results
   from the expected response.
5. Source metrics and required side effects, explicit DB schema evidence when
   applicable, meaningful local tests, architecture review, structural
   convergence, and semantics review are complete. Any explicit blocker keeps
   the migration incomplete.
6. The full `recorded-e2e-cases` completion gate is satisfied from its canonical
   final-state artifacts. A target facade or ledger cannot substitute for any
   recorder-owned evidence.
7. The standard project facade exposes working `start`, `stop`, `status`,
   `test`, `e2e --case-dir`, and `check` commands for the runnable target.
   Normal-startup smoke and all target-required quality checks pass against the
   same final tree. Any later behavior, wiring, policy, assertion, or structural
   change invalidates earlier replay evidence.
8. A focused commit is pushed and a PR to the resolved integration branch is
   independently verified. The per-run state records, but does not manufacture,
   the exact evidence and delivery identifiers. `.migration/local/` is ignored
   and contains no tracked or staged file.

## Completion Blockers

- missing published cases, ambiguous grouping, or changed recordings;
- incomplete or dirty `recorded-e2e-cases` evidence;
- target-side use of recorded dependency files, dependency fixtures, or the
  expected response to create actual behavior;
- no normal runnable startup or no genuine runtime dependency path;
- missing or non-conforming `scripts/<project>-cli` core command facade;
- missing required schema, metrics, side effects, tests, convergence, or
  semantics evidence;
- unresolved target-instruction conflict or stale current-scope `AGENTS.md` map;
- final behavior-affecting change not replayed and rechecked;
- missing `.migration/local/` ignore rule, or any tracked or staged local
  migration artifact;
- unresolved integration branch, focused commit, push, or PR.

## Output

Use the migration status template only when this turn executes migration work,
hands off partial migration state, or makes a completion/delivery claim. Start
that output with exactly `complete`, `incomplete`, or `blocked`, then report the
selected scope, case source and canonical group, recorded-E2E artifact status,
startup/quality results, branch, commit, PR base/URL, run-state path, and exact
blockers. Include the resolved project-facade path and commands. For analysis,
review, or design questions that do not execute a migration, answer normally
without a synthetic migration status.

Never use success wording while an applicable gate is missing.
