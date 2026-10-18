# Coordinator Repository Analysis

Use for `repository_analysis_required`, after static/dynamic path identification
and inventory installation. Complete this stage before Replay or implementation
dispatch. It creates no implementer binding or worktree.

Execute `commands.context` (`repository-analysis context`). Assign one read-only
`repository-analyst` the returned batch, Source repository locations and complete
context. It includes `workflow_id`, `recording_run_id`, `source_revision`,
`batch_id`, selected `scope`, `pending_apis`, `catalog_revision` inside `catalog`,
and all existing group definitions and API assignments. Reuse existing analysis;
only pending canonical routes need grouping. Analysis and Replay do not overlap.

The project catalog is
`.traffic-e2e/local/repository-analysis/catalog.json`; it survives purposes and
recording changes and is engine-owned. Read through the context command, never
edit the catalog or rely on conversation history as the existing-group record.
Group count is unrelated to implementer count. Group by shared behavior, modules,
state machines and anticipated write hotspots; a route prefix alone is insufficient.

Require one complete incremental JSON submission from the analyst:

```json
{
  "schema_version": 1,
  "catalog_revision": "<exact context.catalog.catalog_revision>",
  "groups": {
    "wework-auth": {
      "summary": "Enterprise login session lifecycle",
      "source_refs": ["src/auth/routes.py:create_session"],
      "shared_modules": ["auth/session"],
      "write_hotspots": ["src/wework_auth.rs"]
    }
  },
  "assignments": {
    "/api/auth/wework/sessions": "wework-auth",
    "/api/auth/wework/sessions/*": "wework-auth"
  }
}
```

The `assignments` keys must cover exactly `pending_apis`. Include definitions only
for new groups. Joining an existing group uses its ID in `assignments` without
redefining it in `groups`. Existing group definitions and route assignments are
immutable in this incremental interface. Do not invent a regrouping operation.

Store the analyst's submission in a private local file, recheck global status,
then execute the returned apply command with
`BACKEND_REWRITE_REPOSITORY_ANALYSIS_FILE` or `--file`:

```text
backend-rewrite --target-root <canonical-root> repository-analysis apply <batch-id> --file <analysis.json>
```

The engine checks batch/catalog/recording/Source identity, exact coverage and
references before saving. Identical retries are safe. A stale batch needs fresh
context and a reconciled analyst result. Follow the returned action; no second
user confirmation is required for internal grouping.
