---
name: e2e-rewrite-migration
description: Use when rewriting or migrating one API, scheduled job, worker, or service capability from a local source repository into another language using recorded E2E cases as the behavior contract. Requires a user-provided source repo path, recorded cases, target repo or current workspace, a concise AGENTS.md map with linked migration docs, and E2E proof before completion.
---

# E2E Rewrite Migration

Rewrite behavior, not source text.

Use recorded E2E cases as the compatibility contract. A migration is complete
only when the selected recorded case set passes replay plus the target repo's
relevant quality checks, or when blocked output identifies missing
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
   If the user provides multiple APIs or a recording collection, scan
   `request.json` files first and build a scope/case matrix.
2. If the user did not specify a scope, propose one low-risk HTTP GET with
   route and case evidence, then ask for confirmation before implementing.
3. Migrate one API/function at a time. If one API has multiple recorded cases,
   all of that API's cases must pass before the API is complete. For multiple
   APIs, prefer GET first, scheduled jobs after GET, then write operations and
   complex side effects.
4. Prepare the target repo branch from `dev-migration` before implementation
   or handoff. If current work is on another branch, preserve it with stash,
   switch to `dev-migration`, pull latest, create a scope branch, then reapply
   intended migration work there. Completed migrations must be committed and
   opened as a PR to `dev-migration`, not left staged or only local.
5. Ensure target repo `AGENTS.md` exists as a concise navigation map and links
   to detailed migration docs under `docs/`; follow the Documentation Map
   Contract in [migration-workflow.md](references/migration-workflow.md).
6. Create or update `.migration/e2e.yaml` with source repo, target language,
   scope, scope/case matrix when applicable, rewrite input case paths, PR E2E
   case source, command facade, branch/PR status, package/workspace decision,
   module plan, schema status, metrics contract status, runtime startup status,
   architecture review status, blockers, and recording feedback.
7. Treat user-provided recorded cases as external rewrite inputs, not target
   repo files. Do not copy or commit those cases unless the user explicitly
   asks or the target repo already has that convention. The target E2E facade
   should accept an external case path, normally `e2e --case-dir <path>`, so PR
   actions/workflows can supply cases at runtime. If the user provides a case
   collection directory or run directory, select cases by each published child
   `request.json.uri` matching the migration scope. Do not scan `failed`,
   `staging`, or `.replay` directories or consume `.partial` / `.truncated`
   failed cases. Do not collapse multiple matching cases into one.
8. Use `recorded-e2e-cases` for recorded request replay, managed dependency
   replay, dependency summary coverage, JSON structural response compatibility,
   configured ignores, exact-byte modes, recording feedback rules, and the
   dependency touch contract. For MySQL, preserve business target host,
   database/schema, and username/role identity before comparing SQL and params.
   A matching HTTP response is only partial success until all case-owned
   dependencies are matched. Recorded request construction must come from each
   case's `request.json`; do not hardcode case-specific headers, query params,
   or bodies in target tests. For case sets, use the replay session lifecycle:
   start `traffic-replay`, wait ready with `traffic-replay-cli`, then
   begin/end each case and require a clean aggregate report. Treat recorded
   metrics dependencies as behavior, not optional observability.
9. Ensure a repo-local development command facade exists. Prefer an existing
   project convention; otherwise create `scripts/<project>-cli`. Runnable
   services must expose `start`, `stop`, `restart`, `status`, `e2e`, `check`,
   and `doctor`. The `e2e` command must accept an external case directory
   argument such as `--case-dir <path>` unless an existing equivalent already
   exists.
10. Manage runtime config under `config/`. Development startup should read a
   committed default config directly, then let environment variables override
   config values by full config path converted to uppercase snake case. Keep
   password, secret, appkey/app_key, access key, token, and authorization-like
   keys present in `config/default.yaml` with blank values; when such keys
   exist, provide `config/.env.example` with the environment variable names.
11. Add or preserve a diagnostic logging setup for runnable services. Default
   to predictable development logs under `.migration/run/logs/`; read
   [logging.md](references/logging.md).
12. Choose the target package/module layout before writing behavior code. Do a
    module topology review, not only a file-name plan. Let the agent pick names
    and directory namespaces that fit the repo; require clear ownership
    boundaries and code-size gates, not fixed module names.
13. For DB/MySQL-backed behavior, map runtime adapter types from explicit schema
   evidence: semantic column schema in `dependencies.jsonl`, or schema supplied
   by the user. If schema is missing, continue only with
   `schema_validation_status: unconfirmed` and do not call the migration
   complete.
14. Implement the real runtime dependency path and normal startup entrypoint for
   the migrated scope. Recorded dependencies may power E2E replay, but the
   default service startup must not require recorded case data or recorded
   dependency params.
15. Implement the target behavior idiomatically. Do not assume mechanical
   translation is required; API/interface output compatibility is the contract.
16. Add focused unit or component tests for non-trivial local logic. Recorded
   E2E proves compatibility but does not replace tests for parsers, config,
   signing, metrics, dynamic values, error mapping, and adapters.
17. Iterate implementation -> recorded E2E -> fix at most 3 times.
18. Perform a migration semantics review, then run the recorded E2E, normal
    runtime/startup smoke for service targets, and relevant target quality
    checks before completion.

Read [migration-workflow.md](references/migration-workflow.md) for the complete
migration loop, missing-recording behavior, and failure classification.

## Stop Conditions

- If no source repo path is provided, stop and request it.
- If no recorded case exists for the selected scope, stop before rewriting and
  recommend a concrete API/function to record, preferably a low-risk GET.
- If an API/service migration has no runnable normal startup path, or the
  startup path loads recorded fixtures, do not mark the migration complete.
- If a runnable service lacks diagnostic logs for startup, access, dependency
  failures, and E2E replay failures, add them or keep the migration incomplete.
- If normal runtime config or product logic contains recorded params whose
  provenance cannot be traced to source behavior, keep the migration incomplete.
- If DB/MySQL runtime type mapping lacks explicit schema evidence, keep the work
  as incomplete and report the schema gap even if recorded E2E passes.
- If replay cannot pass because recorded evidence is incomplete, output the
  missing evidence and recording workflow improvement list instead of guessing.

## Output

Keep the final response short: migrated scope, source path, rewrite input case
paths, PR E2E case source, selected recorded case set pass/fail status, PR
target branch and URL when available, E2E/quality/startup commands run, and
recording improvement feedback only when real replay pain exposed a recording
gap.
