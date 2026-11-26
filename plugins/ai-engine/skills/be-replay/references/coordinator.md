# Rewrite Coordinator

You own the canonical Target, publication, and Replay. The Issue Analyst
confirms recorded APIs and identifies the owner of the failed event when the
engine requests it. Implementers diagnose and repair their assigned groups.
The integrator combines the selected commits. [Source Session regression](session-regression.md)

## Run and inspect

Start or resume with `be-replay status` in the canonical Target. Select the
sealed recording. On `project.delivery.pr_base`, use the caller's explicit
authorization for this round before executing the returned command with
`--user-confirm`. Use bare `status` on the work branch to resume the bound
round. Use `action.kind` to choose the workflow step and pass
`action.command` to `be-replay` as arguments when present. Keep at most one
active Replay for a Target.

- For a missing or incomplete recording, coordinate with the external owner.
  See [recording handoff](coordinator-recording.md).
- For `configuration_commit_required`, review the Target-relative paths in
  `action.details.files`. Commit the intended configuration and check `status`
  again. The engine checks the project file, API catalog, and effective policy
  before Replay, planning, and candidate publication.
- For `setup_required`, investigate the reported setup error. Apply proven
  [startup inputs](coordinator-startup-inputs.md).
- For `api_review_required`, obtain the complete API review and submit it
  using `plan --findings FILE`. Dispatch the missing API implementations and
  start the first Replay when `status` allows it.
- For `ownership_required`, check for an active analyst for `failure.seq` or
  dispatch the read-only `issue-analyst` role. Pass the recording ID, failed
  attempt, sequence, evidence, and the Source and Target locations and
  revisions. Request only the event's scope and group, then submit its
  `ownership` record using `plan --findings FILE`. [Issue Analyst](issue-analyst.md)

## Implement and verify

Check that the API review covers the sealed inventory. For a requested
ownership record, check that `seq` matches `failure.seq` and that its scope
and group follow the recorded evidence. [Plan format](session-regression.md#plan-implement-and-verify)

Dispatch each entry in `action.details.assignments` to one `api-implementer`
while you follow the action for the round. Use `status --with-assignments`
for the full handoff. Resolve `worktree` against the canonical Target root
and create it at `base_commit` if needed. Pass the group, `assignment_id`,
recording and attempt context when available, the assigned scopes and
sequences, and any API work.
Reuse the active worker and worktree for new items in the same group. The
engine can assign other groups as slots open. Set `--max-implementers` to
the slots available to this round. If a worker exits before delivering, resume
or reassign its reservation using the same name and worktree.

Register ready work with `report --file FILE` using the assigned group,
`assignment_id`, exact sequences, and checks. Include the full commit ID for
a code or policy repair. Keep the recording and assignment from the original
handoff when receiving a late delivery. Deliveries can arrive while Replay
runs. Handle required startup inputs before the relevant Replay. [Rule actions](coordinator-rule-actions.md)

If an implementer confirms an engine gap, review its evidence and register the
`engine_gap` receipt. Give the engine owner the recording and attempt IDs,
Source sequence, observed behavior, and capability needed. If the gap
accounts for the first unmatched event, use the `setup_required` retry after
the engine is fixed. [Report format](session-regression.md#plan-implement-and-verify)

For `integration_required`, give the
[code integrator](code-integrator.md) the selected fixes and canonical base.
Publish the exact candidate after checking that the canonical base
still matches, then register it with `report --file FILE` for the current
finished attempt. Apply supported coordinator-owned inputs as needed.

For `advance_required`, run `action.command` on the canonical Target.
When `action.details.reason` is `engine_changed`, the engine has authorized
one retry on its new revision with the same Target code, including any
committed configuration updates. Independent assignments can continue during
integration and Replay. For `wait_required`, check the task runtime for
active work and refresh `status` when assignments or Replay finish. On
`complete`, report the recording ID, passing attempt, candidate commit, and
verified API counts.
