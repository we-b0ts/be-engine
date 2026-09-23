# Coordinator Integration

Use for `integration_required` or a source-review assignment. Own dispatch,
result reconciliation, canonical publication, and engine reports. Delegate code
analysis and merge preparation to `code-integrator`.

The code integrator prepares and reviews a candidate; the coordinator publishes
that exact candidate and reports it to the engine. The code integrator is not an
API implementer, does not own an API binding, and never reports `worker`
activity.

Only the coordinator publishes candidates, applies rule or startup inputs,
reports API-implementer activity, invokes traffic acceptance, and releases
retained implementation or integration tasks after final delivery.

## Retain One Integrator

Keep one integrator handle and one separate integration worktree per workflow.
Use the runtime's actual spawn/resume capability with the role and skill
entrypoint; a role name is not a fabricated runtime type or handle. Keep its
assignment record outside engine-owned runtime files. Retain the handle and
worktree through final delivery.

Run one integrator assignment at a time. Record its task identity, actual
runtime state, input identities, base, and any returned candidate. Do not put
this handle into an API-implementer binding or report integrator activity through
`worker report`. The engine validates candidate reports but has no separate
integration-task lifecycle API.

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
findings/report when available and available work-item provenance. Missing or
stale final quality reports also use this assignment. Match the inspected target
version and prepare the retained worktree at that base, preserving unfinished
work. A review does not imply an API implementation issue.

When canonical code was updated outside this workflow, use its current commit
as the review assignment base. If the retained integration branch is an
ancestor and its worktree is clean, fast-forward it to that base. If it has
diverged, preserve its commits and unfinished work and ask the integrator to
identify any undelivered changes; do not merge old history merely to refresh a
review worktree. With no remaining delivery, prepare a clean branch at the
current base in the retained worktree and review that exact commit. External
publication does not itself provide a quality receipt or authorize a new API
handoff.

Keep the original payload across interruptions. Do not replace its identity
with newer status fields to make an old result current.

## While The Task Runs

Collect runtime events and continue already-issued independent worker
confirmation, feedback, and dispatch when allowed. An unchanged
`integration_required` for the active handoff is not another dispatch request.
Use bounded runtime waits when this assignment is the outstanding operation;
do not invent an engine wait command or call `next` to bypass it.
Before waiting and after each wait, actually invoke runtime list/status tools
following the [runtime query protocol](coordinator-agent-protocol.md#mandatory-runtime-queries).
An old running observation or absence of a completion event is insufficient.

Do not start canonical verification, publish another change, or apply related
configuration while an integration result is being published. Preparation in
its separate worktree does not grant authority for another traffic operation.
Actual runtime rejection is backpressure; do not confirm a nonexistent task.

## Reconcile The Result

Require the original assignment ID, handoff/dispatch or finding identity, and
observed base. An unrelated workflow revision alone does not invalidate it.

- `ready`: require the exact candidate, passing integration review report,
  checks, provenance, conflict resolutions, evidence, and necessary inputs.
  For a read-only ownership review, consume its evidence
  or owner without inventing a code candidate.
- `rework`: retain cause and provenance. For an accepted handoff, report
  `rework_required` using its original worker handle, handoff ID and worker or
  integration `--review-report` when the
  engine permits it, then resume that worker. For source findings from an
  unpublished candidate, use `review rework --report /absolute/failed-report.json`
  with the exact finding and responsible work-item owner. Standard command
  and isolation/domain failures use the accepted handoff's `rework_required`
  path with precise logs/locations; they need not have a source finding ID.
  Do not invent an integration-owner selector.
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

The integrator must run `review check --integration` on the final candidate,
using the original work-item selector and accepted `--handoff-id`. The report
must cover every required source, isolation and engine-standard quality check, and
the canonical inputs that will be used for acceptance. If applying required
inputs changes that context, complete the supported input transition and send
the candidate back for review before reporting integration. Do not rerun quality
commands in the coordinator or accept only the worker's earlier report.

Record publication as in progress before changing canonical HEAD. Fast-forward
to the exact candidate using Git; when candidate equals base, verify that identity
and leave HEAD in place. Compare commit IDs, not just file diffs: a distinct
candidate with identical files still requires publication before admission.
No new engine publication command is implied.
Apply required inputs through [coordinator-startup-inputs.md](coordinator-startup-inputs.md)
or [coordinator-rule-actions.md](coordinator-rule-actions.md), and follow
configuration commit requirements. Only when code and required inputs are in
place, report `integrated` with the accepted handoff ID, original worker handle,
and `--review-report /absolute/integration-report.json`. The engine verifies
the candidate's original handoff, published code and quality inputs before
admission; a stale or failing report requires integrator recheck. Then refresh
global status and execute the returned Replay/Comparison acceptance action.
The coordinator validates receipts without executing quality checks again.

For a source-evidence-only review candidate, publish the exact evidence commit
while verification is idle, then execute `review accept --report
/absolute/integration-report.json` (or set `BACKEND_REWRITE_REVIEW_REPORT`). The
global report must come from `review check --integration` without a scope or
handoff ID. Use the same path for final quality refreshes. Do not
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

If admission reports a HEAD mismatch, compare the published HEAD, report
`head_revision`, and `integration.canonical_base_revision` before retrying.
When the canonical branch remains at the reviewed base, complete the missing
publication after checking assignment and input freshness, then submit the same
passing receipt. If the canonical branch moved elsewhere, reconcile the current
assignment and refresh stale work through the integrator. Repeating review
checks does not publish a candidate; do not loop check/accept while these
identities remain unchanged.
