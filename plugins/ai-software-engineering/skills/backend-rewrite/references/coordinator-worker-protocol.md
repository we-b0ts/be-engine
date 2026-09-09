# Coordinator Worker Protocol

Audience: the workflow coordinator. Read for dispatch, resume, worker status
checks, completion events, integration, or binding recovery. The coordinator
executes the workflow mutations in this guide and delegates code operations.
Follow the main loop in
[coordinator.md](coordinator.md#coordinator-loop) throughout these operations.

## Persistent Assignment

Maintain one exact work item to one dedicated task runtime handle and one worktree:

```text
API method/pattern or process_output:<id> <-> worker handle <-> worker worktree
```

Issue IDs, attempts, and workflow revisions can change without changing this
binding. Store the task runtime handle in the coordinator's assignment
record; the CLI deliberately persists only its fingerprint and optional name.
A finished worker turn does not release ownership. Retain the binding and
worktree through final workflow completion.

Create worktrees from the integrated target revision under:

```text
<coordinator-root>/.traffic-e2e/local/rewrite-worktrees/<workflow.id>/<work-item-slug>
```

Use `api-` and `process-output-` slug prefixes. Dispatch only:

- Role: `api-implementer` for API scope; retain the generic implementation-worker
  assignment for existing process-output scope.
- Exact work scope: API method/pattern or process-output ID.
- Absolute canonical target root for engine evidence queries.
- Absolute assigned worktree for edits and local tests.
- Source repository locations for behavior analysis.
- On a post-input resume, the completed input transition and remaining delivery
  requirement; the worker still retrieves all current issue facts itself.

The worker obtains the current issue, binding/dispatch identity, and diagnostic
facts from the engine's scoped evidence entrypoint. Do not attach action JSON,
evidence IDs, evidence commands, or diagnostic bodies to the assignment. Retain
the dispatched identity and actual runtime handle in the coordinator's assignment
record so returned handoffs can be matched to the correct turn. Workers edit and
test only their worktrees; they do not initialize a private rewrite workflow or
operate other work items.

## Dispatch And Resume

For `implementation_required`:

1. Read `details.worker.state` and recover the assigned handle if one exists.
2. For `dispatch_required`, create its worktree and dispatch a real dedicated
   worker. For `resume_required`, refresh the retained worktree from the
   integrated revision when synchronization is conflict-free, preserving all
   unintegrated changes. Otherwise leave source conflict resolution to that
   worker. Resume the same handle with the same assignment fields; its evidence
   context supplies the frozen base for this dispatch.
3. After the task runtime accepts the submission, execute `commands.confirm_worker`
   with `BACKEND_REWRITE_SUBAGENT_HANDLE` and optional
   `BACKEND_REWRITE_SUBAGENT_NAME`. Register the assigned absolute worktree using
   `--worktree` or `BACKEND_REWRITE_WORKER_WORKTREE`; repeat this on resume so the
   engine freezes the new dispatch's base. Confirm accepted queued work as well; report
   `queued` when the task runtime exposes that state.
4. Confirmation records the accepted binding only. Report `running` or `queued`
   explicitly using the owning action's `commands.report_worker` when that state
   is known, then continue with the returned global action. A confirmation with
   no activity report remains `worker_status_required` in `pending`.

Confirmation gates that work item's evidence and acceptance. It does not block
another work item's dispatch or feedback. Never perform API diagnosis in the
coordinator to bypass missing worker capability. Confirmation is delivery of a
dispatch, not proof that the worker remains running or has completed its work.

A later failed acceptance creates a new dispatch for the same worker. An
unavailable stored handle requires explicit caller approval for ownership
transfer. Preserve the worktree, create the approved replacement, then execute
`worker transfer <binding-id>` with its actual handle, a single-line reason, and
`--approve-ownership-transfer`. The current binding ID is available in scoped
status or inventory, including parked items. Never give two workers simultaneous
ownership of one work item.

## Runtime Events And Handoffs

Use completion events from the task runtime as the normal notification path.
Match the handoff's original workflow/recording, scope, issue, binding and dispatch
identities to the retained assignment before reporting it. Do not replace a stale
callback's identity with one from fresh status. The coordinator consumes a matching
result and executes that work item's `commands.report_worker`. Supply its actual
handle plus `BACKEND_REWRITE_WORKER_ACTIVITY`:

| Activity | Meaning |
| --- | --- |
| `queued` | Task runtime accepted the task and is waiting to run it. |
| `running` | The coordinator reports that this dispatch is running. |
| `idle` | The worker stopped without a usable handoff; resume is required. |
| `handoff_ready` | The coordinator received a reviewable handoff. |
| `integrated` | The identified handoff and required inputs have been integrated. |
| `rework_required` | The identified handoff needs worker changes, such as an integration conflict or a failed quality gate. |

For `handoff_ready`, `integrated`, and `rework_required`, also supply the same stable
`BACKEND_REWRITE_WORKER_HANDOFF_ID`, normally the worker commit or another exact
handoff identity. The engine rejects an integration report without a matching
received handoff. Duplicate handoff events do not create duplicate work. Stale
attempts or wrong handles cannot advance the current issue; recover its current
status without replacing the dedicated worker.

For a result containing only rule, route, capture, or startup inputs, reconcile
its original identity and execute the supported plan/apply or route transition
before reporting `idle` when that transition is permitted. An idle
report creates an unconfirmed dispatch and can invalidate the required planner
or route preconditions. After the mutation, refresh status. If it advanced or
parked the original implementation issue, do not report the old completion as
`idle`, `handoff_ready`, or `integrated`. If the same dispatch still requires an
implementation handoff, report the ended worker as `idle` and resume its handle
for the remaining engine requirement. When no code repair remains, request review
and delivery of the unchanged current target: its existing commit and a passing
local report are sufficient. Do not request an artificial patch or new commit.
Input application alone is not acceptance.

If the input transition must wait and the engine requires a worker status report,
report the actual `idle` state. Retain the old result as context; have the same
worker revalidate its inputs after the next dispatch is confirmed. Do not relabel
old evidence or claim the ended worker is running to preserve a planner.

A usable code handoff requires a passing `review check` report for its final code;
follow [coordinator-review.md](coordinator-review.md). Require the returned
source evidence; send semantic questions back to its author.
Report `handoff_ready` with `--review-report` or
`BACKEND_REWRITE_WORKER_REVIEW_REPORT`. An unaccepted incomplete delivery from
an ended worker is `idle`, so the same worker can resume and finish its review.

A usable handoff contains the original overview's workflow/recording,
work scope, issue, binding and dispatch identities, proven cause and
supporting evidence, commit/patch identity, changed files and shared-module
impact, local test results, the passing review's absolute `report_path` and any
spawn ownership evidence, necessary coordinator transition inputs, and any
remaining risks. After consuming any non-code result as above, a task ending
with no usable handoff for its still-current dispatch is `idle`. Reporting idle
issues a fresh dispatch identity for the same worker; reject late completion
from the superseded turn and follow the returned resume action.
After `backend-rewrite wait` returns `worker_events_required`, inspect available
completion and interruption events in the task runtime and report actual
changes before refreshing global status. Keep original dispatch and handoff
identities; do not manufacture a running observation from a historical
confirmation. Do not re-report every running worker on each wait. The engine
continues scheduling explicit status checks after sixty-minute expiry.

The worker returns the handoff and ends its turn; it does not wait for Replay.

After interruption, on `worker_status_required`, or when an observation expires,
inspect the actual task runtime task and report its state through `report_worker`.
The engine trusts the coordinator's explicit report; it does not query Claude
Code or another task runtime, or independently prove liveness. Never report running
merely because a dispatch was previously confirmed. A repeated confirmation does
not create or refresh an activity report. Running/queued reports are fresh for
60 minutes after the most recent explicit report; another running/queued report
resets that interval. Handoff-ready and integrated observations do not expire
while awaiting integration or verification. Expiry requests a check; it
does not prove that a worker stopped and never authorizes a duplicate worker.
Missing or legacy unclassified observations on confirmed bindings also request
a coordinator status check. Recover the retained assignment before reporting;
unknown activity is not evidence of either running or idle.
Completion events should be reported immediately, not held until that interval.

## Integration And Focused Acceptance

For `integration_required`, follow
[coordinator-integration.md](coordinator-integration.md). Delegate preparation to
`code-integrator`, publish only the matched candidate, apply necessary inputs,
and report with the original implementation worker handle and accepted handoff
ID. Do not analyze or resolve code conflicts in the coordinator.

If an accepted handoff requires API changes, report `rework_required` when the
engine permits it and resume the same binding. Preserve its original handoff
ID; the new dispatch invalidates late results from the previous attempt.
For a failed quality operation, integrate the corrected handoff before the
returned retry; that retry validates the current integrated gate identity.

Evidence-backed rule, route, capture, and startup inputs use the existing
coordinator interfaces with their original evidence/plan identities. Read
[coordinator-rule-actions.md](coordinator-rule-actions.md) or
[coordinator-startup-inputs.md](coordinator-startup-inputs.md) for the returned input kind.
The canonical target environment remains coordinator-owned.

One API's integrated handoff schedules only its required quality checks, Replay,
and batch-required Comparison. An unsuccessful acceptance resumes its original
worker. Do not schedule speculative extra APIs from shared-impact notes; final
unified verification covers the integrated target after ordinary work drains.

Only the coordinator confirms/reports/transfers worker bindings, applies rules,
advances the engine, requests recording, invokes formal quality/acceptance, and
executes repair verification or recovery. The integrator returns code results;
its runtime task is not an API worker activity. Release retained implementation
and integration bindings/worktrees only after `terminal_allowed` and final
delivery no longer need them.
