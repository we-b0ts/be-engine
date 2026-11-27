# Rewrite Coordinator

Own the canonical Target, orchestration, candidate publication, and Replay.
Delegate grouping and unresolved ownership to the Issue Analyst, diagnosis and
repairs to implementers, and candidate assembly to the code integrator.

## Run and inspect

Start or resume with `be-replay status` in the canonical Target. On
`project.delivery.pr_base`, obtain the caller's approval for this round before
using the returned command with `--user-confirm`. Use bare `status` on the
work branch to resume the round. Keep one active Replay per Target.
`action.kind` selects the coordinator's step. `action.command` gives the
next coordinator invocation when present, and `action.query` reads
supporting state. [Source Session status](session-regression.md#inspect-a-replay-attempt)

- For missing or incomplete recordings, coordinate with the external owner.
  See the [recording handoff](coordinator-recording.md).
- For `configuration_commit_required`, review and commit the intended files
  listed in `action.details.files`, then check `status`.
- For `setup_required`, resolve the reported Replay setup issue or send a
  confirmed engine gap to its owner. Apply proven [startup inputs](coordinator-startup-inputs.md).
- For `advance_required`, run Replay on the canonical Target. An
  `engine_changed` reason authorizes one retry on the eligible engine
  revision. For `wait_required`, follow the active Replay or registered
  workers and refresh `status` when they have news.
- The first `complete` on the candidate starts
  [pre-final validation and Replay](#pre-final-validation-and-replay).

## Dispatch and accept a delegated task

At `dispatch_task`, start a separate agent in the runtime using the role named
in `action.details.task`. Include the task details, recording ID, canonical
Target location, and available Source and Target revisions in its assignment.
Ask the agent to load the current `be-replay` skill for the assigned role.
Use the Source revision from the recording handoff and the canonical Target's
current commit. For `ownership_required`, pass the attempt, failed sequence,
and any evidence references already available. For `lookahead_ownership_required`,
pass the task identity and Source window. For `integration_required`, use
`status --with-assignments` to obtain every ready window fix and rule plan.
Pass those commit and rule plan IDs, canonical base, current attempt, and
integration worktree. Request the exact merged candidate and test results
only for any conflict resolution. Keep
follow-ups within merge conflicts and route product repairs or refactors to
the responsible implementer. Engine `review check`, formatting commands,
standalone builds, and `cargo clippy` are prohibited in integration assignments
and follow-ups during progression.

Once the runtime returns a handle, register it with
`be-replay report --file FILE`. The receipt uses `kind: task_dispatch` and
`state: started`. If registration is interrupted, refresh `status` and recover
the handle from the runtime before launching another agent. If the runtime
cannot start the required role, report the blocker and keep the task pending.

At `await_delivery`, follow the registered `agent_handle` in the runtime.
Once it returns the artifact, submit it with the current `task_id` and
`agent_handle`. Use `be-replay plan --findings FILE` for grouping or ownership
and `be-replay report --file FILE` for a candidate. If the agent exits without
delivering, report its exit and follow the resulting dispatch action. Return
incomplete artifacts to the responsible role for correction. For an API
grouping delivery, the engine writes the catalog and requests its commit
before implementation dispatch. For an integration delivery, confirm the
canonical base, publish the exact returned commit, and submit its receipt for
the current attempt. [Task and delivery receipts](session-regression.md#dispatch-and-monitor-delegated-tasks)

## Dispatch and follow implementers

Use `status --with-assignments` for engine-issued assignments. Resolve the
`worktree` against the canonical Target root and prepare it at
`base_commit` if needed. Before reusing a slot for a different assignment,
coordinate the previous worker's exit and preserve its changes. Give each
worker its group, `assignment_id`, scopes, applicable API work, window bounds,
and recording or attempt context. Reuse an active worker and worktree when
the engine adds to the same group.

At `dispatch_required`, or when `pending_dispatch` appears alongside another
action, launch assignments without handles in parallel. Tell the implementer
to load the current `be-replay` skill, confirm every assigned sequence,
implement required Target changes, and run focused tests for the changes.
Engine `review check` and `cargo clippy` are prohibited in
implementer assignments and follow-ups during progression. Register the
handles returned by the runtime with
`be-replay report --file FILE`. At `worker_status_required`, query the runtime
and report the observed states.
If it confirms a worker exited without delivering, report `state: exited`
and resume or replace it in the same reservation.
[Implementer receipts](session-regression.md#plan-implement-and-verify)

Register ownership claims so the engine can assign the sequences for
confirmation. Submit the implementer's confirmations, fixes, rule plans,
and engine gaps with the original recording and `assignment_id`. The engine
requests integration after every required sequence has a result. Follow
`advance_required` for the next Replay after the engine accepts the candidate
with all window repairs applied. Register rules against a finished attempt.
Route an engine gap with the recording and attempt IDs,
the Source sequence, observed behavior, and needed capability. Apply supported
coordinator-owned inputs before the relevant Replay. [Rule actions](coordinator-rule-actions.md)

## Pre-final validation and Replay

When a full Replay first passes on the current commit and `status` reports
`complete`, freeze that commit, recording, and Target inputs for delivery.
The coordinator runs `cargo clippy` for a Rust Target and the engine's final
`review check` when the active workflow provides it. The standalone
`review check` entrypoint belongs to the Case workflow.

After the checks pass, run `be-replay run` again on the same commit, inputs,
and recording for final revalidation. Use that attempt's passing result and
`complete` status for delivery. Record the commit, recording ID, final attempt,
API counts, and check results together.

Run final checks once per delivery revision. Checking intermediate candidates
repeats work as fixes arrive. If a check requires a change, route it to the
responsible implementer and resume progression on the corrected revision.
