# Rewrite Coordinator

Own the canonical Target, orchestration, candidate publication, and Replay.
Delegate grouping and failure ownership to the Issue Analyst, diagnosis and
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
- For `complete`, report the recording ID, passing attempt, exact revision,
  and verified API counts.

## Dispatch and accept a delegated task

At `dispatch_task`, start a separate agent with the role and requirement in
`action.details.task`. Resolve `role_reference` relative to the loaded
`be-replay` skill and give the agent that reference, the task and its input
context, the canonical Target location, and relevant Source and Target
revisions. Use the Source revision from the recording handoff and the
canonical Target's current commit. Register the handle returned by the
runtime using the task's `register_command`. If registration is interrupted,
refresh `status` and recover the handle from the runtime before launching
another agent. If the runtime cannot start the required role, report the
blocker and keep the task pending.

| Requirement | Brief and expected artifact |
| --- | --- |
| `api_grouping_required` | Give the Issue Analyst the recording and Source router context and pass along `task.input_query` for its inventory lookup. Ask for the complete `apis` grouping list with one `api`, `case_pattern`, and `group` per uncatalogued label. |
| `ownership_required` | Give the Issue Analyst the recording ID, current attempt, failed sequence, and available evidence pointers. Ask for one `ownership` record with that `seq`, its `scope`, and its `group`. |
| `integration_required` | Fetch ready fixes with `status --with-assignments`. Give the code integrator the selected fixes, canonical base, current attempt, and integration worktree. Ask for a validated candidate with its exact commit, included fixes, and checks. |

At `await_delivery`, follow the registered `agent_handle` in the runtime.
Submit the returned artifact with the current `task_id` and `agent_handle`
using `task.submit_command`. If the agent exits without delivering, report
its exit and follow the resulting dispatch action. Return incomplete
artifacts to the responsible role for correction. For an API grouping
delivery, the engine writes the catalog and requests its commit before
implementation dispatch. For an integration delivery, confirm the canonical
base, publish the exact validated commit, and submit its receipt for the
current attempt. [Task and delivery receipts](session-regression.md#dispatch-and-monitor-delegated-tasks)

## Dispatch and follow implementers

Use `status --with-assignments` for engine-issued assignments. Resolve the
`worktree` against the canonical Target root and prepare it at
`base_commit` if needed. Before reusing a slot for a different assignment,
coordinate the previous worker's exit and preserve its changes. Give each
worker its group, `assignment_id`, scopes, sequences, applicable API work,
and recording or attempt context. Reuse an active worker and worktree when
the engine adds to the same group.

At `dispatch_required`, or when `pending_dispatch` appears alongside another
action, launch assignments without handles in parallel and register the
actual handles. At `worker_status_required`, query the runtime and report
the observed states. If it confirms a worker exited without delivering,
report `state: exited` and resume or replace it in the same reservation.
[Implementer receipts](session-regression.md#plan-implement-and-verify)

Register returned fixes, reviews, or engine gaps with the original recording
and `assignment_id`. Deliveries can arrive while Replay runs. Route a
confirmed engine gap with the recording and attempt IDs, the Source sequence,
observed behavior, and needed capability. Apply supported coordinator-owned
inputs before the relevant Replay. [Rule actions](coordinator-rule-actions.md)
