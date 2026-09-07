# Implementation Worker Coordination

Use this guide for dispatch, resume, worker completion events, integration, and
session recovery. The main/root agent is the **state-machine coordinator**. It
executes engine-issued actions and reports results. Dedicated workers own API
or process-output diagnosis, implementation, and local tests.

## Post-Dispatch Scheduler

Schema v24 exposes one top-level `pending`: the number of operations the
coordinator can perform now. `pending > 0` requires consuming the returned
`action`; `pending = 0` means wait for an event or the returned polling delay.
Check `terminal_allowed` separately before ending the workflow.

```text
state = status()
while not state.terminal_allowed:
    collect and report any arrived worker completion events
    while state.pending > 0:
        execute the action's coordinator command or runtime operation
        report the actual result when that action requires confirmation
        state = the returned current action, or status() if it was lost
    wait for a worker event or up to 30 seconds
    state = status()
```

`next` means advancing one coordinator step, including executing any returned
runtime action and reporting its result. The CLI cannot create task-runtime
handles. The coordinator invokes the runtime's real dispatch/resume capability
for implementation actions; it never invents a handle or substitutes a TODO.
Do not repeatedly call `next` while ignoring the action it returns.

The engine selects across the complete inventory, including parked
`implementation_required` items. The coordinator does not infer runnable work
from `api_inventory.unverified`, enumerate APIs to build its own scheduler, or
fetch evidence to decide which API to repair. Use `inventory` only when a
scheduling breakdown or binding recovery is needed. Its English `details.ready`
counts sum to `pending`; `details.waiting` is excluded.

No worker concurrency limit belongs to the coordinator. Submit every returned
dispatch/resume to the runtime; the runtime controls concurrency and queuing.
Accepted queued work retains its actual handle. A rejected submission is not a
confirmed dispatch. Respect runtime backpressure before retrying a submission.
One failed or waiting item must not cause the coordinator to ignore other
engine-issued executable work.

`next` and `target-quality run` start detached engine operations when execution
is needed. Recording already has a detached executor. Consume the returned
action immediately; do not background these commands yourself or wait for a
worker's entire lifecycle. Recording, Replay, and Comparison retain their
serialized traffic lease. Worker dispatch, confirmation, and feedback remain
available during a live operation. Integration waits while the canonical target
is being verified. If every remaining item is waiting for Replay, waiting is
correct. The engine's `wait_required` response supplies the exact status command
and polling delay. Worker completion events can wake the coordinator sooner.

A detached operation's `execution_failed` response waits for its reported cause
to be resolved. It includes the only retry command. Do not hot-loop that retry;
continue other returned worker actions. A stopped executor requires the returned
recovery action. Neither condition means successful completion.

## Persistent Assignment

Maintain one exact work item to one dedicated runtime handle and one worktree:

```text
API method/pattern or process_output:<id> <-> worker handle <-> worker worktree
```

Issue IDs, attempts, and workflow revisions can change without changing this
binding. Store the runtime-returned handle in the coordinator's assignment
record; the CLI deliberately persists only its fingerprint and optional name.
A finished worker turn does not release ownership. Retain the binding and
worktree through final workflow completion.

Create worktrees from the integrated target revision under:

```text
<coordinator-root>/.traffic-e2e/local/rewrite-worktrees/<workflow.id>/<work-item-slug>
```

Use `api-` and `process-output-` slug prefixes. Pass the absolute worktree path,
exact work scope, compact action, issue/dispatch identity, evidence entrypoint,
and required handoff to the worker. Workers edit and test only their worktrees;
they do not initialize a private coordinator or operate other work items.

## Dispatch And Resume

For `implementation_required`:

1. Read `details.worker.state` and recover the assigned handle if one exists.
2. For `dispatch_required`, create its worktree and dispatch a real dedicated
   worker. For `resume_required`, refresh the retained worktree from the
   integrated revision and resume the same runtime handle with the new action.
3. After the runtime accepts the submission, execute `commands.confirm_worker`
   with `BACKEND_REWRITE_SUBAGENT_HANDLE` and optional
   `BACKEND_REWRITE_SUBAGENT_NAME`. Confirm accepted queued work as well; report
   `queued` when the runtime exposes that state.
4. Consume the returned action and continue scheduling immediately.

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
The coordinator consumes the returned result and executes the work item's
`commands.report_worker`. Supply its actual handle plus
`BACKEND_REWRITE_WORKER_ACTIVITY`:

| Activity | Meaning |
| --- | --- |
| `queued` | Runtime accepted the task and is waiting to run it. |
| `running` | Runtime observation confirms this dispatch is running. |
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

A usable handoff contains the exact work scope and issue, proven cause and
supporting evidence, commit/patch identity, changed files and shared-module
impact, local test results, necessary coordinator transition inputs, and any
remaining risks. A task ending without that handoff is `idle`, not completed. Reporting idle
issues a fresh dispatch identity for the same worker; reject late completion
from the superseded turn and follow the returned resume action.
The worker returns the handoff and ends its turn; it does not wait for Replay.

After interruption, on `worker_status_required`, or when an observation expires,
inspect the actual runtime task and report its state through `report_worker`.
Running observations are fresh for five minutes. Expiry requests a check; it
does not prove that a worker stopped and never authorizes a duplicate worker.
Missing observations on legacy confirmed bindings also request a runtime check.
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
follow the relevant returned coordinator commands. Its original evidence and
plan identities remain authoritative. Canonical `.traffic-e2e/local/target.env`
is coordinator-owned; apply source-proven startup inputs through the startup
interface, never a separate worker-local environment file.

One API's integrated handoff schedules only that API's quality checks, Replay,
and, when required by this recording batch, Comparison. An unsuccessful
acceptance resumes its original worker. Other workers keep implementing. Do
not schedule extra APIs for speculative shared-service impact; final unified
verification covers the integrated target after ordinary work drains. Preserve
the existing final fingerprint and terminal gates.

Workers may execute assigned read-only scoped status, evidence, case-dependency,
and returned read-only help commands in their canonical command `cwd`. After
confirmation, fetch `commands.evidence`; read the full issue from `facts.issue`
and API detail commands from `queries`. Process-output evidence uses
`facts.issue.comparison_observation` and has no API queries. The coordinator
forwards these entries without retrieving diagnostics for scheduling.

Only the coordinator executes mutations: worker confirmation/report/transfer,
integration, quality checks, `next`, recording, rule plan/apply, routing, repair
verification, and recovery. Execute returned argv unchanged with their absolute
`--target-root`. Release bindings and worktrees only after `terminal_allowed`
and final delivery no longer need them.
