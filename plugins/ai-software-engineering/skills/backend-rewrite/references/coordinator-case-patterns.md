# Coordinator Case Patterns

Use only for `case_pattern_identification_required`. Keep configuration
application here and delegate source route analysis.

`action.details.candidates` contains concrete APIs absent from the historical
catalog and not covered by existing `case_path_patterns`. Retain this complete
batch and its workflow/recording identity as one assignment.

Dispatch `repository-analyst` with `task=route_analysis`, an assignment ID, the
source repository location, and the exact candidate batch. This read-only task
uses [repository-analyst.md](repository-analyst.md). Do not call the engine's
`worker confirm` for this task or invent an API issue; it has no
implementation-worker binding.
Retain its actual runtime handle and resume that task for missing source proof.

Require the same assignment and complete input batch in the result, plus one
JSON pattern array and source references. Re-read global status before applying.
If the candidate batch or recording changed, reject the stale result and follow
the current action. Do not merge partial or conflicting analyses yourself.

Set the environment variable named by
`action.details.pattern_input.environment_variable` to the complete returned
JSON array (`[]` is valid for an entirely static batch). Execute the exact
`action.commands.apply` argv without adding pattern arguments.

Apply updates the managed source traffic policy and derived catalog/inventory;
it does not edit or move recorded cases. Follow the returned `advance_required`.

After canonical inventory installation, `repository_analysis_required` separately
uses the same analyst role to trace module relationships and group only new APIs.
Read [repository analysis](coordinator-repository-analysis.md) for its distinct
context/submission schema. Finish both analysis stages before Replay.
