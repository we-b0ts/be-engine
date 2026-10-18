# Coordinator Repository Analysis

Use for `repository_analysis_required`, after static/dynamic path identification
and inventory installation. Finish grouping before Replay or implementation.

Execute `commands.context` (`repository-analysis context`). Give one read-only
`repository-analyst` the returned `pending_apis`, Source repository location and
`catalog_path`. The analyst reads existing assignments from that file and only
classifies the pending APIs. If `catalog_revision` is `absent`, no catalog exists.
Do not inline the catalog in status or agent assignments.

The project-wide `.traffic-e2e/local/repository-analysis/catalog.json` contains
only `api_groups`, mapping canonical API routes to group names. It survives
workflow and recording changes. Existing assignments are reused unchanged.
Groups have no separate definitions, evidence requirements or count limit.
The analyst chooses how to group APIs; the engine does not judge that choice.

Return an incremental submission containing exactly the pending routes:

```json
{
  "schema_version": 1,
  "catalog_revision": "<exact context.catalog_revision>",
  "assignments": {
    "/api/auth/wework/sessions": "wework-auth",
    "/api/auth/wework/sessions/*": "wework-auth"
  }
}
```

Store the submission privately, recheck global status and execute the returned
apply command with `BACKEND_REWRITE_REPOSITORY_ANALYSIS_FILE` or `--file`:

```text
backend-rewrite --target-root <canonical-root> repository-analysis apply <batch-id> --file <analysis.json>
```

The engine checks complete API coverage, valid group names and stale submission
identity before saving. Existing API assignments cannot be changed by this
incremental interface. Identical retries are safe. For stale input, obtain fresh
context. No evidence bundle, call graph or justification report is required.
