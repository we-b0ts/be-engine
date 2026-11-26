# Issue Analyst

The coordinator uses the read-only `issue-analyst` role for first-unmatched
analysis and recorded API review. Use the assigned recording and Source
and Target revisions. Submit the first finding as soon as it is ready.

## Source Session failure

Use `be-replay events --recording-run-id ID --seq SEQ` for `failure.seq`.
Use `events --from-seq` to inspect request admissions and completions before
and around the failure. Add `--with-push-event` when the cause involves a
push. Explicit `--seq` queries include a server push at that position, and
client `PUBLISH` and `SUBSCRIBE` requests appear in the default event window.
Read a dependency exchange by its admission sequence with `dependency`. Use
`target --attempt UUID OBSERVATION_ID` with `session.attempt_id` and
`failure.target_observation_id` when available.

Keep repeated operations distinct by sequence. Check the Source call site,
trigger, or lifecycle and compare any available Target observation. Trace the
code far enough to identify which symptoms likely share one repair.
[Evidence commands](session-regression.md#diagnose-the-first-failure)

Put the finding containing `failure.seq` in `first_unmatched`. Use optional
`others` for separate problems ready for dispatch. Give each finding a stable
`root_cause`, a short `summary`, and related `sequences`. Assign one owning
`scope` and its dispatch `group`. Use `api:METHOD /path` for ingress-owned work,
`job:NAME` for background jobs, and `startup` or `shutdown` for lifecycle work.
Reuse the API catalog's group where available. Group jobs by the subsystem or
shared implementation boundary that one worker can own. Implementers verify
the cause and choose the repair.
[Finding format](session-regression.md#plan-implement-and-verify)

## Recorded API review

Run `be-replay apis` from the canonical Target. For each returned `api`, verify
implementation in the Target for every literal path in `paths`. Return one row
per returned label with `implemented: true` or `false`. For an uncatalogued API,
propose its `case_pattern` and `group`. Distinct literal API labels may share
a single proposed pattern and group if they represent the same route.

Return all rows together under `apis`. The coordinator submits this review
alongside or after `first_unmatched`. The engine dispatches missing
implementations and catalog entries by group.
