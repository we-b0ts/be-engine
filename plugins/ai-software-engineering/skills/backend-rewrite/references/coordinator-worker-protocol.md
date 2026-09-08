# Coordinator Worker Protocol

Audience: the workflow coordinator. Read for dispatch, resume, worker status
checks, completion events, integration, or binding recovery. The coordinator
executes the mutations in this guide; implementation workers diagnose, implement,
test, and return handoffs. Follow the main loop in
[workflow.md](workflow.md#coordinator-loop) throughout these operations.

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

- Role: implementation worker; follow this Skill's worker diagnosis instructions.
- Exact work scope: API method/pattern or process-output ID.
- Absolute canonical target root for engine evidence queries.
- Absolute assigned worktree for edits and local tests.

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
   integrated revision and resume the same task runtime handle with those same
   assignment fields. The worker fetches the new engine context itself.
3. After the task runtime accepts the submission, execute `commands.confirm_worker`
   with `BACKEND_REWRITE_SUBAGENT_HANDLE` and optional
   `BACKEND_REWRITE_SUBAGENT_NAME`. Confirm accepted queued work as well; report
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

A usable handoff contains the original overview's workflow/recording,
work scope, issue, binding and dispatch identities, proven cause and
supporting evidence, commit/patch identity, changed files and shared-module
impact, local test results, necessary coordinator transition inputs, and any
remaining risks. A task ending without that handoff is `idle`, not completed. Reporting idle
issues a fresh dispatch identity for the same worker; reject late completion
from the superseded turn and follow the returned resume action.
After `backend-rewrite wait` returns `worker_events_required`, inspect available
completion and interruption events in the task runtime and report actual
changes before refreshing global status. Keep original dispatch and handoff
identities; do not manufacture a running observation from a historical
confirmation. Do not re-report every running worker on each wait. The engine
continues scheduling explicit status checks after fifteen-minute expiry.

The worker returns the handoff and ends its turn; it does not wait for Replay.

After interruption, on `worker_status_required`, or when an observation expires,
inspect the actual task runtime task and report its state through `report_worker`.
The engine trusts the coordinator's explicit report; it does not query Claude
Code or another task runtime, or independently prove liveness. Never report running
merely because a dispatch was previously confirmed. A repeated confirmation does
not create or refresh an activity report. Running/queued reports are fresh for
fifteen minutes. Expiry requests a check; it
does not prove that a worker stopped and never authorizes a duplicate worker.
Missing or legacy unclassified observations on confirmed bindings also request
a coordinator status check. Recover the retained assignment before reporting;
unknown activity is not evidence of either running or idle.
Completion events should be reported immediately, not held until that interval.

## Integration And Focused Acceptance

`integration_required` identifies the exact received handoff. Integrate its
patch/commit and source-proven coordinator inputs in the canonical target,
then execute the returned report command with the matching handoff ID. Normal
merges are mechanical; return conflicts requiring API implementation decisions
to the responsible worker: report `rework_required` with the current handoff ID when verification is idle,
then follow the new dispatch for the same binding. The engine invalidates the
old dispatch so late handoff callbacks cannot undo the rework decision. For a
failed quality operation, integrate the corrected handoff before executing its
retry command; the retry validates the current integrated gate identity.

If a worker returns evidence-backed rule, route, capture, or startup inputs,
follow the relevant returned engine-issued commands. Its original evidence and
plan identities remain authoritative. Canonical `.traffic-e2e/local/target.env`
is coordinator-owned; apply source-proven startup inputs through the startup
interface, never a separate worker-local environment file.

One API's integrated handoff schedules only that API's quality checks, Replay,
and, when required by this recording batch, Comparison. An unsuccessful
acceptance resumes its original worker. Other workers keep implementing. Do
not schedule extra APIs for speculative shared-service impact; final unified
verification covers the integrated target after ordinary work drains. Preserve
the existing final fingerprint and terminal gates.

Workers start or resume with `evidence --api '<METHOD pattern>'` or
`evidence --process-output <id>`, bound to the canonical target root. They may
also execute assigned read-only scoped status, case-dependency, and returned
read-only query/help commands in the canonical command `cwd`. The engine
supplies diagnostics directly; the coordinator obtains fresh scheduling and
acceptance commands from scoped status when handling a handoff.

Only the coordinator executes mutations: worker confirmation/report/transfer,
integration, quality checks, `next`, recording, rule plan/apply, routing, repair
verification, and recovery. Execute returned argv unchanged with their absolute
`--target-root`. Release bindings and worktrees only after `terminal_allowed`
and final delivery no longer need them.
