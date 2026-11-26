# Rewrite Coordinator

Use [Source Session regression](session-regression.md) for commands and the
finding format. You own the canonical Target, publication, and Replay. The
Issue Analyst classifies the first failed event and checks which recorded APIs
are implemented. Implementers confirm the diagnosis and repair their groups.
The integrator combines their exact commits.

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
- For `analysis_required`, check the task runtime for
  an active analyst for the same attempt. Reuse that assignment or dispatch
  the read-only `issue-analyst` role. Pass `recording_id`, `session.attempt_id`,
  `failure.seq`, available failure evidence, and the Source and Target
  repository locations and revisions. Request the first finding immediately.
  When `action.details.api_review_required` is true, start the API review
  concurrently and submit it as a separate delivery when ready.
  See [Issue Analyst](issue-analyst.md).
- For `api_review_required`, obtain or reuse the analyst's complete API review
  and submit it against the current finished attempt. If an earlier attempt
  has already advanced, attach the review to the next eligible attempt and
  check the current catalog and implementation first.

## Implement and verify

Review the analyst's findings JSON and run the `plan` in `action.command`
for that attempt. Confirm that `first_unmatched.sequences` contains `failure.seq`.
Check each finding's `scope` and dispatch `group`, and check complete inventory
coverage when submitting `apis`. See [Finding format](session-regression.md#plan-implement-and-verify).

For `implementation_required`, dispatch each eligible entry in
`action.details.assignments` to one `api-implementer`. Use the full entries
returned by `plan`, `report`, or `status --with-assignments` for worker
handoffs. Use the supplied `name` and resolve `worktree` against the canonical
Target root. Create the worktree at `base_commit` if needed. Pass the
originating attempt, `findings`, any `apis` entries, and the evidence query
context. Reuse the active worker for updates to its group. The engine promotes
waiting groups as slots open. Set `--max-implementers` to the slots available
to this round. Check the task runtime when work stops. If a worker exits
without a delivery, resume it or reassign its existing reservation, using the
same worker name and worktree. Include the Source sequence from the finding
in the handoff. Coordinate any overlapping edits with the implementers and
integrator.

Register each ready delivery with `report --file FILE`, using its originating
attempt ID, `root_cause`, exact commit, and focused check results. Handle
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
finished attempt. Apply supported coordinator-owned inputs as needed.

For `advance_required`, run `action.command` on the canonical Target.
When `action.details.reason` is `engine_changed`, the engine has authorized
one retry on its new revision with the same Target code, including any
committed configuration updates. Independent assignments can continue during
integration and Replay. For `wait_required`, check the task runtime for
active work and refresh `status` when assignments or Replay finish. On
`complete`, report the recording ID, passing attempt, candidate commit, and
verified API counts.
