# Rewrite Coordinator

Use [Source Session regression](session-regression.md) for commands and the
finding format. You own the canonical Target, publication, and Replay. The
Issue Analyst traces the failure through Source and observed Target behavior.
Dispatch the analyst to group related symptoms and implementers to confirm
the cause and repair each assigned group.
The integrator combines their exact commits.

## Run and inspect

Start or resume with `be-replay status` in the canonical Target. Select the
sealed recording. On `project.delivery.pr_base`, use the caller's explicit
authorization for this round before executing the returned command with
`--user-confirm`. Use bare `status` on the work branch to resume the bound
round. Use `action.kind` to choose the current workflow step. Keep at most
one active Replay for a Target.

- For a missing or incomplete recording, coordinate with the external owner.
  See [recording handoff](coordinator-recording.md).
- For `setup_required`, investigate the reported setup error. Apply proven
  [startup inputs](coordinator-startup-inputs.md).
- For `analysis_required`, check the task runtime for
  an active analyst for the same attempt. Reuse that assignment or dispatch
  the read-only `issue-analyst` role. Pass `recording_id`, `session.attempt_id`,
  `failure.seq`, available failure evidence, and the Source and Target
  repository locations and revisions. See [Issue Analyst](issue-analyst.md).

## Implement and verify

Review the analyst's findings JSON and run `action.commands.plan` for that
attempt. Confirm that `first_unmatched.sequences` contains `failure.seq`
and that the grouping fits the observed problem. Use `scope` when it
clarifies ownership or lifecycle.

For `implementation_required`, assign eligible work with the originating
attempt, finding, canonical root, frozen base, and a separate worktree for
each group. Reuse active assignments and reconsider `waiting` when a slot
opens. Set `--max-implementers` to the slots available to this round.
Coordinate any overlapping edits with the implementers and integrator.

Register each ready delivery with `report --file FILE`, using its originating
attempt ID, finding group, exact commit, and focused check results. Handle
required startup inputs before Replay. Use the same delivery flow for time,
ID, and token policy changes. [Rule actions](coordinator-rule-actions.md)

If an implementer confirms an engine gap, review its evidence and register the
`engine_gap` receipt. Give the engine owner the recording and attempt IDs,
Source sequence, observed behavior, and capability needed. If the gap
accounts for the first unmatched event, use the `setup_required` retry after
the engine is fixed. [Report format](session-regression.md#plan-implement-and-verify)

For `integration_required`, give the
[code integrator](code-integrator.md) the selected fix and canonical base.
Publish the exact candidate after checking that the canonical base
still matches, then register it with `report --file FILE` for the current
failed attempt. Apply supported coordinator-owned inputs as needed.

For `advance_required`, run `action.commands.run` on the canonical Target.
Independent assignments can continue during integration and Replay. For
`wait_required`, check the task runtime for active work and refresh `status`
when assignments or Replay finish. On `complete`, report the recording ID,
passing attempt, candidate commit, and verified API counts.
