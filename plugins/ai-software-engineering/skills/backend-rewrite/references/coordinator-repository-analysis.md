# Coordinator Repository Analysis

Use for `repository_analysis_required` before Replay or implementation.
Execute `commands.context` and give one read-only `repository-analyst` the
complete returned context, an assignment ID and the Source repository location.
Keep the exact workflow, recording, Source revision and batch in the assignment
and result.

Read the project catalog at `catalog_path`. In `apis.yaml`, each group name maps
to its canonical route list. A legacy JSON catalog uses `api_groups` with route
keys. A revision of `absent` means there is no existing catalog. Existing
assignments carry forward across workflows and recordings.

For `context.case_patterns.candidates`, return one entry per concrete API.
Use the Source-proven wildcard path for a dynamic route and JSON `null` for a
confirmed static route. Include Source file or symbol references in the analyst
handoff. Omit `case_patterns` if the context has no such field.

Return `assignments` for `pending_apis` and each newly confirmed route that
needs a group in `apis.yaml`. For a legacy catalog, apply
`case_patterns.only_apis` and `case_patterns.skipped_apis` to the resolved
routes, with skips taking precedence. Use canonical path keys for HTTP APIs. Multiple concrete
paths and methods of the same canonical HTTP route share one assignment. Reuse
existing group assignments. For a context with `grouping_enabled: false`,
submit empty `assignments`.

```json
{
  "schema_version": 1,
  "catalog_revision": "<exact context.catalog_revision>",
  "case_patterns": {
    "GET /api/auth/sessions/123": "/api/auth/sessions/*",
    "GET /api/health": null
  },
  "assignments": {
    "/api/auth/sessions/*": "auth",
    "/api/health": "health"
  }
}
```

Store the submission privately, recheck global status and execute the returned
apply command with `BACKEND_REWRITE_REPOSITORY_ANALYSIS_FILE` or `--file`:

```text
backend-rewrite --target-root <canonical-root> repository-analysis apply <batch-id> --file <analysis.json>
```

The engine checks complete coverage, effective route identity and batch
revisions before publication. Commit changes to `apis.yaml` when the
configuration commit action is returned before Replay. Retry interrupted
publication with the same batch and submission. For stale analysis, use fresh
context.
