# Issue Analyst

Use the delegated task's `requirement` and the assigned recording, attempt,
and Source and Target revisions. Work read-only and return the requested
artifact to the coordinator. The coordinator submits it with the registered
task and agent identities. [Task and delivery receipts](session-regression.md#dispatch-and-monitor-delegated-tasks)

## New API grouping

For `api_grouping_required`, query the assigned recording from the canonical
Target with `be-replay --recording-run-id ID apis --ungrouped`.
Consult the Source router and existing catalog for the canonical
`case_pattern` and `group`.
Return one row with `api`, `case_pattern`, and `group` per ungrouped
label under `apis`. Distinct literal labels can share the same pattern and
group when they represent the same Source route.

Use whole-segment `*` or final-segment `**` for proven dynamic routes.
Preserve trailing or repeated separators with literal paths. A pattern has
one group across methods. Keep the existing catalog's route selection intact.
Use the Source fallback behavior to group a recorded unmatched request when
the router establishes it. Report any unresolved label and missing evidence
to the coordinator before returning the final grouping artifact.

The engine writes the catalog after the coordinator submits those rows and
assigns implementation to the groups once the catalog is committed.
[Grouping format](session-regression.md#plan-implement-and-verify)

## Failed event ownership

For `ownership_required`, identify the scope and group of `failure.seq`.
Use `be-replay events --recording-run-id ID --seq SEQ` for the exact event.
Read earlier events when needed to locate the triggering request or lifecycle
boundary. Use `dependency SEQ` for the admission record and
`target --attempt UUID OBSERVATION_ID` when a Target observation is available.
Use explicit request links, Source call paths, or lifecycle evidence to
establish ownership of concurrent traffic. [Evidence commands](session-regression.md#diagnose-the-first-failure)

Return `ownership` with `seq`, `scope`, and `group`. Use `api:/case/pattern`
and its catalog group for API work, or `job:NAME`, `startup`, or `shutdown`
with the group that owns the subsystem. [Ownership format](session-regression.md#plan-implement-and-verify)

## Lookahead ownership

For `lookahead_ownership_required`, read the outstanding sequences for `task_id`
with `be-replay sequences --task-id TASK`. The list has one representative
sequence per exchange. Use `--limit` and the last returned sequence as
`--after-seq` to work in batches. Use the primary request or
dependency admission linked to each exchange event. Trace the matching
request, dependency or lifecycle evidence to its scope. A request can precede
the window. Consecutive Source sequences can belong to different requests.

Group sequences that share an evidence-backed scope and group in one file.
Return a `lookahead` finding per file with `sequences_file`, `scope`, `group`,
and a short `evidence` reference. If the available facts cannot establish
ownership, omit both `scope` and `group` and state the missing evidence. The
unresolved sequences keep the window open. The engine assigns linked events
together. The implementer confirms each assigned sequence.
[Lookahead receipt](session-regression.md#lookahead-ownership)
