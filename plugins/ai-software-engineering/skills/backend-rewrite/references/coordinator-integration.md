# Coordinator Integration

Use for `integration_required` or a source-review assignment. Own dispatch,
result reconciliation, canonical publication, and engine reports. Delegate code
analysis and merge preparation to `code-integrator`.

## Retain One Integrator

Keep one integrator handle and one separate integration worktree per workflow.
Use the runtime's actual spawn/resume capability with the role and skill
entrypoint; a role name is not a fabricated runtime type or handle. Keep its
assignment record outside engine-owned runtime files. Retain the handle and
worktree through final delivery.

Run one integrator assignment at a time. Record its task identity, actual
runtime state, input identities, base, and any returned candidate. Do not put
this handle into an API worker binding or report integrator activity through
`worker report`. The engine has no separate integration-task lifecycle API.

## Dispatch

For `integration_required`, first match the accepted handoff to its original
API/process-output binding and dispatch. Record the canonical commit and
relevant content/configuration state. Create or mechanically synchronize the
integration worktree without discarding existing work. Delegate source conflicts.

Send only the data needed for the assignment:

- role `code-integrator`, task `integrate`, unique assignment ID;
- canonical root, absolute integration worktree, canonical base commit, source
  repository locations;
- exact scope, original workflow/recording, worker binding/dispatch, handoff ID,
  worker base, delivery commit, accepted review and local-test results;
- shared impact, previous integration provenance, and required-input references.

For `review`, supply the same role, roots, base and assignment ID, plus exact
findings/report and available work-item provenance. Match the inspected target
version and prepare the retained worktree at that base, preserving unfinished
work. A review does not imply an API implementation issue.

Keep the original payload across interruptions. Do not replace its identity
with newer status fields to make an old result current.

## While The Task Runs

Collect runtime events and continue already-issued independent worker
confirmation, feedback, and dispatch when allowed. An unchanged
`integration_required` for the active handoff is not another dispatch request.
Use bounded runtime waits when this assignment is the outstanding operation;
do not invent an engine wait command or call `next` to bypass it.

Do not start canonical verification, publish another change, or apply related
configuration while an integration result is being published. Preparation in
its separate worktree does not grant authority for another traffic operation.
Actual runtime rejection is backpressure; do not confirm a nonexistent task.

## Reconcile The Result

Require the original assignment ID, handoff/dispatch or finding identity, and
observed base. An unrelated workflow revision alone does not invalidate it.

- `ready`: require the exact candidate, checks, provenance, conflict resolutions,
  evidence, and necessary inputs. For a read-only review, consume its evidence
  or owner without inventing a code candidate.
- `rework`: retain cause and provenance. For an accepted handoff, report
  `rework_required` using its original worker handle and handoff ID when the
  engine permits it, then resume that worker. Use formal review's work-item
  routing for published defects; do not invent an integration-owner selector.
- `stale`: preserve useful work, refresh global status, and reassign only current
  work on the current base.
- `needs_input`: return the specific request to its source owner.
- `execution_failed`: reconcile actual task/local steps and resolve the named
  cause before retrying; never count it as API completion.

A result for a superseded assignment cannot advance state. A duplicate matching
result must not repeat publication or worker reports.

## Publish A Ready Candidate

Re-read engine status. Match the original handoff and dispatch, canonical base,
relevant configuration, and exact candidate. Require conflict-free fast-forward
ancestry and no unrelated working-tree changes. Respect the engine's live
verification/traffic owner. If any prerequisite changed, return to status or
the integrator instead of resolving a source conflict yourself.

Record publication as in progress before changing canonical HEAD. Fast-forward
to the exact candidate using Git; when candidate equals base, verify that identity
and leave HEAD in place. No new engine publication command is implied.
Apply required inputs through [coordinator-startup-inputs.md](coordinator-startup-inputs.md)
or [coordinator-rule-actions.md](coordinator-rule-actions.md), and follow
configuration commit requirements. Only when code and required inputs are in
place, report `integrated` with the accepted handoff ID and original worker
handle. Then refresh global status and execute the returned quality/acceptance
action. Local integrator checks never replace formal integrated review.

For a source-evidence-only review candidate, publish the exact evidence commit
while verification is idle, then use the current review/quality action. Do not
manufacture an API handoff or report `integrated` for this metadata-only task.

If an input requires system repair or fresh recording, follow its existing
engine action and recheck assignment identity before any subsequent report.
Never relabel an invalidated handoff after changing the recording.

## Resume Publication

Git changes, input application, and worker reporting are separate steps.
Restore the retained assignment and actual canonical state before proceeding.
A matching already-published candidate is not merged again. Complete missing
supported input/report steps before starting acceptance. If publication cannot
be proven from the retained identity, obtain the exact missing result or runtime
state; do not reset code, assume completion, or fabricate a recovery command.
