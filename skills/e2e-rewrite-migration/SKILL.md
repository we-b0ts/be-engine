---
name: e2e-rewrite-migration
description: Use when rewriting or migrating one API, scheduled job, worker, or service capability from a local source repository into another language using recorded E2E cases as the behavior contract. Requires a user-provided source repo path, recorded cases, target repo or current workspace, AGENTS.md migration rules, and E2E proof before completion.
---

# E2E Rewrite Migration

Rewrite behavior, not source text.

Use recorded E2E cases as the compatibility contract. A migration is complete
only when the target implementation passes recorded E2E replay plus the target
repo's relevant quality checks, or when blocked output identifies missing
recording/E2E evidence.

## Required Inputs

- Require a local source repo path. If missing, stop and ask for it.
- Require a target repo path, or use the current workspace as the target repo.
- Require recorded cases before implementation starts. Existing source E2E tests
  may supplement recorded cases but cannot replace them.
- Require a target language. For Rust rewrites, read
  [rust.md](references/rust.md).

## Workflow

1. Inspect source repo routes/jobs, target repo structure, and recorded cases.
2. If the user did not specify a scope, propose one low-risk HTTP GET with
   route and case evidence, then ask for confirmation before implementing.
3. Migrate one API/function at a time. Prefer GET first, scheduled jobs after
   GET, then write operations and complex side effects.
4. Ensure target repo `AGENTS.md` exists and includes migration rules. Read
   [agents-template.md](references/agents-template.md).
5. Create or update `.migration/e2e.yaml` with source repo, target language,
   scope, case paths, command facade, schema status, runtime startup status,
   blockers, and recording feedback.
6. Place copied recorded cases under `tests/fixtures/recordings` by default and
   preserve original case files.
7. Use `recorded-e2e-cases` for recorded replay, dependency mocks, byte-level
   response compatibility, configured ignores, and recording feedback rules.
8. Ensure a repo-local development command facade exists. Prefer an existing
   project convention; otherwise create `scripts/<project>-cli`.
9. Manage runtime config under `config/`. Development startup should read a
   committed default config directly; production may specify another config file
   or use environment overrides.
10. Choose the target module layout before writing behavior code. Let the agent
    pick names that fit the repo, such as `api`, `store`, `service`, or `util`;
    require a clear design, not fixed module names.
11. For DB/MySQL-backed behavior, map runtime adapter types from explicit schema
   evidence: semantic column schema in `dependencies.jsonl`, or schema supplied
   by the user. If schema is missing, continue only with
   `schema_validation_status: unconfirmed` and do not call the migration
   complete.
12. Implement the real runtime dependency path and normal startup entrypoint for
   the migrated scope. Recorded dependencies may power tests and mocks, but the
   default service startup must not require recorded case data.
13. Implement the target behavior idiomatically. Do not assume mechanical
   translation is required; API/interface output compatibility is the contract.
14. Iterate implementation -> recorded E2E -> fix at most 3 times.
15. Run the recorded E2E, normal runtime/startup smoke for service targets, and
    relevant target quality checks before completion.

Read [migration-workflow.md](references/migration-workflow.md) for the complete
migration loop, missing-recording behavior, and failure classification.

## Stop Conditions

- If no source repo path is provided, stop and request it.
- If no recorded case exists for the selected scope, stop before rewriting and
  recommend a concrete API/function to record, preferably a low-risk GET.
- If an API/service migration has no runnable normal startup path, or the
  startup path loads recorded fixtures, do not mark the migration complete.
- If DB/MySQL runtime type mapping lacks explicit schema evidence, keep the work
  as incomplete and report the schema gap even if recorded E2E passes.
- If replay cannot pass because recorded evidence is incomplete, output the
  missing evidence and recording workflow improvement list instead of guessing.

## Output

Keep the final response short: migrated scope, source and case paths, pass/fail
status, E2E/quality/startup commands run, and recording improvement feedback
only when real replay or mock pain exposed a recording gap.
