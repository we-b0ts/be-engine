# Issue Analyst

The coordinator dispatches the read-only `issue-analyst` role when
`action.kind` is `analysis_required`. Scope your investigation to the
assigned Source and Target repository locations and revisions,
`recording_id`, `session.attempt_id`, and `failure.seq`.

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

Return one finding per likely shared repair. Choose a free-form, stable
`root_cause` string as the group ID and include a short `summary` and the
related `sequences`. Put the finding containing `failure.seq` in
`first_unmatched` and use optional `others` for additional findings. Add
`scope` to identify ownership or lifecycle.
The coordinator reviews the findings and runs `action.commands.plan`.
Implementers confirm the cause and choose the repair.
[Finding format](session-regression.md#plan-implement-and-verify)
