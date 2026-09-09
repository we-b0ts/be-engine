# Coordinator

Audience: the workflow coordinator. Read at every session start or resume,
including sessions waiting for assigned agents. Own action execution, result
reconciliation, waiting, and completion. Delegate source diagnosis, code edits,
and integration analysis. Load only the coordinator references linked at the
relevant action below.

## Contents

- Session start and resume
- Coordinator loop
- Engine phase order
- Core action handling
- API inventory and serialized traffic
- Completion invariants

## Session Start And Resume

Start and resume from the initialized canonical target repository:

```bash
backend-rewrite status
```

Follow the returned action to start an absent rewrite workflow.
Before the first standard recording, add `--api '<METHOD path-or-pattern>'`
only when the caller explicitly requests a single-API recording. After the
engine publishes its stable inventory, select work with the exact
inventory method/pattern. If an action response was lost or the session is
resuming, recover the engine scheduler's current action with unscoped read-only
`status`; scoped status serves work-item inspection. Execute the returned
action's command to advance the workflow.

After handling a user interruption, worker handoff, integration, or other side
work, and before waiting or ending the current turn, return to the
[coordinator loop](#coordinator-loop).
Status restores the next action, including a pending dispatch confirmation or
post-confirmation advance. Keep the complete response and execute its supplied
command directly; each response determines the following step. For a live
operation, execute its returned wait command and reconcile worker events on return.

At the start of every workflow-coordinator session, read
`.traffic-e2e/local/block.md` when it exists. Project initialization may create
it with temporary reference evidence about source configuration, Vintage
access, startup/process activity, and local caches. The first rewrite session
after initialization must read that evidence completely. Route source questions
in those notes to the responsible assigned agent.
Remove each entry after receiving a proven resolution, implementation, or
irrelevance result; keep no resolved history and remove the file when empty.
When progress is proven blocked and the workflow coordinator is about to
stop, create or update the same file with useful resume context. Treat it as
AI-owned reference and handoff context, never as engine state;
`backend-rewrite status` remains authoritative.

## Coordinator Loop

Use the existing `backend-rewrite` interface. Response schema v28 actions have
exactly `kind`, `summary`, `details`, and `commands`. Status/next expose scheduling
and short issue facts, not diagnostic payloads. Default `workflow` has `id` and
`revision`; use `inventory` for binding recovery and scheduling detail. Never
infer scheduling from a phase field or create another task queue.

Start with unscoped `status` in the canonical target repository. Top-level
`pending` counts operations the coordinator can perform now, including one
explicit wait when no productive action is ready. The engine selects
across all APIs and process outputs, including parked implementation issues.
Use `pending`, `action`, and `terminal_allowed`; do not reconstruct scheduling
from `workflow.phase`, `current_api`, or `api_inventory.unverified`.

```text
state = status()
while true:
    reconcile implementation-worker results through the worker protocol
    reconcile integrator and route-analysis results with retained assignments
    refresh state from the latest report response, or status() if needed
    if state.terminal_allowed:
        finish delivery and break
    if state.action.kind == "blocked":
        preserve resume context, report the blocker, and stop this run
    if the current action needs an integrator or route-analysis task already running or queued:
        wait on that runtime task for a bounded interval and continue
    if state.pending > 0:
        execute the returned action's command or task runtime operation
        report its actual result when confirmation or feedback is required
        state = the current response, or status() if the response was lost
        continue
    handle any reported input requirement or execution failure
    do not infer completion from zero pending
```

Reconcile retained integrator assignments through
[coordinator-integration.md](coordinator-integration.md). An active runtime
assignment for the current handoff prevents duplicate dispatch; wait on that
actual task when no independent permitted action remains. Never report its
handle as an implementation worker or invent new engine activities.
This wait guard does not apply to worker confirmation, status checks, or feedback;
execute those engine actions even when the implementation worker is running.

Check for arrived events after every action, even while `pending` stays positive;
do not hold handoffs until the queue drains or a fifteen-minute activity report
expires. Report responses replace the previous scheduling action. Preserve each
event's actual worker handle, dispatch identity, and delivered handoff identity;
check them against the engine's current binding. Never relabel a stale event
with a newer dispatch or another handoff ID. An unknown worker activity is not
a running or idle observation.

When no productive action is ready but workers or engine operations remain,
`pending=1` selects `commands.wait`. Execute it; the command waits at most
30 seconds and may return sooner when engine-observable state changes. The
returned `worker_events_required` asks you to inspect task-runtime completion,
failure and interruption events, report actual changes, then execute global
`commands.status`. Use `commands.inventory` only when bindings need recovery.
This is event reconciliation, not a requirement to re-report every running
worker every 30 seconds. Fifteen-minute activity expiry still requests explicit
worker status checks. Unknown runtime state is never reported as running.

A zero-pending `blocked` action stops this coordinator run without completing
the workflow. Retain bindings, worktrees and blocker context. Resume through
its `commands.resume` after the external repair is installed. The engine does
not wake a stopped AI session; the caller or task runtime must resume it.
Input requirements and execution failures retain their explicit handling;
never hot-loop a failed command. A task-runtime event can wake the loop sooner
when that runtime provides such a capability.

`next` advances an engine step and returns an action. When that action requires
a worker, the coordinator must invoke the task runtime and confirm the accepted
submission; the CLI cannot create task handles. Do not repeatedly call `next`
while ignoring its returned action.

The coordinator imposes no worker concurrency limit. Submit every returned
dispatch/resume to the task runtime, retain the actual handle for accepted queued
work, and respect runtime backpressure after a rejected submission. A rejected
submission is not confirmed. One waiting or failed item must not prevent other
engine-issued executable work from being handled.

`next`, `target-quality run`, and recording execution start detached engine
operations when needed. Consume their returned actions immediately; do not
background the commands yourself or wait for a worker's entire lifecycle.
Recording, Replay, and Comparison share a serialized traffic lease. Dispatch,
confirmation, and feedback remain available during verification; integration
waits while the canonical target is being verified. When every remaining item
is waiting for Replay, execute the returned bounded wait command. A stopped executor requires its recovery action; an
`execution_failed` operation requires its reported cause to be resolved before
its returned retry, without a hot loop.

Use `inventory` when a scheduling breakdown or binding recovery is needed.
`details.ready` counts sum to `pending`; `details.waiting` describes outstanding
work. When waiting is the selected coordinator operation, `details.ready.wait=1`. Scoped
status retains global `pending` while showing one item's action. After inspecting
an item, return to global status for the loop. Worker event, dispatch, and handoff
mechanics are in [coordinator-worker-protocol.md](coordinator-worker-protocol.md).

## Engine Phase Order

The engine owns this phase order and returns the legal next action:

```text
record configured traffic -> identify patterns only for new uncovered APIs
           -> stable API inventory + source process outputs
           -> serialize prepare/focused E2E for API A
           -> API A implementation issue (AI work may run in parallel)
           -> serialize focused E2E for API B
           -> API B implementation issue (AI work may run in parallel)
           -> process-output comparisons after every API is dispatched
           -> process-output implementation issues (AI work may run in parallel)
           -> serialize each Replay/comparison transition
           -> all API slices and process outputs complete at one fingerprint

explicit user authorization
           -> fresh standard recording -> prepare -> focused E2E

source-proven bypassed backend -> apply capture rule -> API waits
           -> drain other runnable API work -> one full-scope fresh recording

source-proven Redis rule -> derive safe snapshot overlay from old Global evidence
           -> reuse the same immutable recording
           -> on strict derivation failure only, join the full-scope fresh recording fallback
```

## Core Action Handling

The stable action envelope has `kind`, `summary`, `details`, and `commands`.
Read kind-specific facts only from `details` and execute only command roles
present in `commands`, except for the documented `input_required` continuations.
An empty command object alone never authorizes a fallback. Status
does not guarantee an unconditional top-level `next` command. Source-process
traffic is issue-scoped evidence, not engine state. Both unscoped and
scoped status return compact scheduling actions, as does `next`. Dispatch the
worker assignment as defined
in [coordinator-worker-protocol.md](coordinator-worker-protocol.md). Implementation
workers fetch their own diagnostics. Do not attach diagnostic payloads or
investigate business source in the coordinator.

### `wait_required` and `worker_events_required`

Execute `commands.wait` when verification resources are occupied or all workers
are running/queued. Preserve the reported blocking API and operation as context;
never start another traffic operation or recover a live owner. Wait returns
`worker_events_required`: inspect actual completion, failure and interruption
events in the task runtime, report each with its original dispatch/handoff
identity, then execute `commands.status`. Inspect `commands.inventory` only to
restore missing bindings. The engine does not inspect the task runtime itself.
The coordinator performs coordination while idle; implementation and diagnosis
remain assigned to workers.

### `blocked`

All remaining incomplete APIs require external system repair, no implementation
worker needs coordination, and eligible revalidation has drained. End this run
as blocked; `pending=0` and `terminal_allowed=false`. The action lists repair
APIs and any process outputs whose final baseline depends on them. Those outputs
remain incomplete. Preserve the worktrees and resume context. Execute
`commands.resume` only after repair or an explicit resumed session; do not loop
on it immediately and do not claim successful delivery.

### `recording_required`

Read [coordinator-recording.md](coordinator-recording.md), execute its exact
recording action, and poll only the status command returned by that execution.
Do not reconstruct a recording command or discover its run by recency.

### `recording_in_progress`

Read [coordinator-recording.md](coordinator-recording.md) and execute `commands.wait`. After it returns, reconcile worker events and
refresh global status. Do not start another executor or advance before the exact
finalized run becomes `advance_required`.

### `case_pattern_identification_required`

Read [coordinator-case-patterns.md](coordinator-case-patterns.md). Delegate
read-only route analysis of the complete batch, then apply its matched result
through the returned command. Do not create an implementation issue for it.

### `plan_apply_required`

Execute the exact unchanged `commands.apply` once; never rerun planning or
reconstruct selector inputs. For response-rule, recorder-capture, or
process-owned-dependency plans, first read
[coordinator-rule-actions.md](coordinator-rule-actions.md). A response
rule plan remains bound to its existing evidence and plan ID.

### `advance_required`

The prerequisite in `summary` is already available. Execute the exact
`commands.advance` argv once. Never rerun the preceding recording, Replay,
comparison, implementation, or quality command.

### `comparison_recording_required`

Read [coordinator-recording.md](coordinator-recording.md) and execute the exact
`commands.execute` for its allocated run ID. This creates comparison evidence;
it never replaces the shared standard cases or authorizes a standard recording
request.

### `input_required`

This action has no returned command. Retain the triggering invocation and its
`cwd`; after resolving the named input, repeat it with only that requested input
changed. The recovery commands below are explicit exceptions to opaque-argv
execution, not permission to synthesize other actions.

When `details.reason=configuration_commit_required`, match the listed persistent
configuration changes to the returned input/plan and commit exactly those files
in the canonical target. Return unresolved semantic questions to their source
owner. Then repeat the original `next` command with the same scope and inputs.
This gate covers `project.yaml`, `source-traffic-policy.yaml`, and
`verification.yaml`, including staged and new files. Staging is not sufficient.
`status` reports this requirement without writing files; `next` stops before
dispatch or verification, including when preparation creates a policy change.
An active operation keeps its existing wait/recovery action. Routine generated
`progress.yaml` updates retain the final-delivery commit flow below.

When `details.reason=source_route_required`, the selected dynamic API lacks a
proven source registration route. Assign
`api-implementer` a read-only `route_analysis` task with the exact API, source
location, and a retained assignment ID. Retain its actual runtime handle and
resume the same task for missing proof. Require that same identity and a
source-proven complete route. Re-read status and match the same API and request
before repeating the retained invocation with `--source-route`.
If the invocation was lost for an existing workflow, recover the exact API from
public status/inventory and confirm that it still requires this input, then run:

```text
backend-rewrite --target-root <canonical-root> next --api '<exact API>' --source-route '<proven complete route>'
```

Before workflow creation, the missing-route response persists no API selection.
Recover the caller-authorized selector from retained task context; if it is
unavailable, return that missing input. Never infer a single-API recording from
source analysis. Do not invent a worker issue or change the shared recording scope.

When `details.reason=verification_progress_commit_required`, every API is
verified but terminal delivery is still forbidden. Commit exactly the listed
engine-managed delivery files without editing or resetting the generated
`progress.yaml`, then execute `backend-rewrite next` again. The list includes
the dirty `.traffic-e2e/source-traffic-policy.yaml` or
`.traffic-e2e/verification.yaml` when applicable, alongside the final public
progress snapshot. Intermediate failed or passing attempts do not
require progress commits.

### Worker And Integration Actions

For `implementation_required`, `worker_status_required`, and
`integration_required`, follow
[coordinator-worker-protocol.md](coordinator-worker-protocol.md).
Dispatch/resume, task runtime observations, handoffs, and integration are reported
through the exact returned commands. Confirmation belongs to one work item;
it does not freeze scheduling or feedback for other items. A worker ending
without a handoff requires resume, not acceptance.

`pending` counts executable coordinator actions, including these worker
operations. If worker delivery or a Replay resource is the only remaining
activity, one explicit `wait` contributes one pending operation.
The engine returns work across the whole inventory before returning a global
wait. The coordinator consumes actions and reports task runtime events; it does not
rebuild that queue from API counters or historical confirmations.

An integrated API handoff schedules only its own Replay and required Comparison.
Do not promote other APIs for speculative shared-code impact. After ordinary
work drains, the engine performs final verification against one integrated
content fingerprint. Process-output work follows the same worker event protocol
and retains its existing capture and final verification dependencies.

### `execution_failed`

A detached engine operation failed. `pending` excludes that failed
operation until its reported cause is resolved and its returned `commands.retry`
is executed. Continue other executable worker actions. Never hot-loop the retry
or treat the failure as completion. A stopped operation without a completion
record uses the existing recovery action.

### `source_review_required`

Worker handoffs require a passing local review report. The integrated quality
operation also runs the mandatory source review. A `source_review_required`
action requests inspection, spawn evidence or worker rework through
[coordinator-review.md](coordinator-review.md). It is actionable work, not an execution
failure. Return to global status after handling it. Final delivery requires a
current source review even when no API remains in implementation.
Once a finding has been routed, worker dispatch, status and integration take
priority. With no such action ready, `wait_required` on `source_review_rework`
waits for that repair; follow `commands.wait` and runtime events. Scoped status
continues exposing each worker's own handoff commands.

### `target_quality_required`

Execute only `action.commands.execute` in its absolute canonical `cwd`. The
only permitted command extension is one or more exact
`--hardcode-ai-verified` arguments after this built-in gate reports the matching
locations and the required source evidence has been committed. Never run this
gate in a worker worktree. The command launches a detached operation; continue
consuming its returned action. Successful execution records the integrated
target fingerprint and makes focused Replay eligible through `advance_required`. A later integration or quality-gate configuration change
creates a new fingerprint and another quality action. On failure, obtain the
assigned agent's repair/evidence result and publish it before executing the
returned `execution_failed.commands.retry`; never repair source yourself.

The built-in isolation gate remains mandatory even with no configured repository
checks. For source-evidence findings, delegate a `review` task through
[coordinator-integration.md](coordinator-integration.md), passing the exact
findings, current target version, and known source locations. Receive committed
source-evidence mappings or a responsible repair owner; do not prove constants
or trace callers yourself.

Publish any exact evidence-only candidate before retrying. After the gate has
reported the matching source-sensitive public-domain findings, the permitted
extension is one `--hardcode-ai-verified` per returned, committed mapping. Pass
those mappings unchanged. This exception never waives private Replay markers.
Re-read status if the inspected version, input, or findings changed.

### `system_repair_required` and `recovery_required`

Read
[coordinator-recovery.md](coordinator-recovery.md) and execute only
the engine-issued repair or recovery command. `wait_required` never
authorizes recovery.

### `recording_refresh_pending`

The scoped API is parked until one consolidated standard recording can replace
the baseline. Read [coordinator-recording.md](coordinator-recording.md), execute `commands.wait`, and never execute its stale acceptance.
Continue other runnable work only through current engine-issued commands.

### `complete`

API-scoped `complete` means only that API satisfies the current batch's focused
E2E and required Comparison gates. Process-output-scoped `complete` means only
that output
passes its configured comparison for the current target fingerprint. Finish
repository-wide verification and delivery only when `terminal_allowed=true`
proves every API and process output is complete for the same target content
fingerprint and the final public `progress.yaml` is committed. Use
`backend-rewrite inventory` when delivery needs the full per-API list.

## API Inventory And Serialized Traffic

Every initialized action or status includes a bounded `api_inventory` summary:
`total`, `completed`, `unverified`, `implementation_required`,
`system_repair_required`, `awaiting_recording_refresh`, `revalidation_pending`, `current_index`, and
`current_api`. The engine owns this inventory. In expanded `inventory`,
`workflow.scope` is the selector of the shared standard recording and is separate
from the selected API. An
omitted selector produces `recorded_api_inventory`: every API that actually
publishes a case in the selected standard recording enters the inventory, while
an API with no observed traffic is not required and does not block completion.
The scope remains stable as selected workers change.

Every `implementation_required` action uses a worker. Inventory size controls
only how much work the engine can make ready. Worker concurrency belongs to
the task runtime; the coordinator does not impose a limit. The engine may park
implementation and system-repair issues while it serializes the selected API's Replay or
comparison. Expensive worker diagnosis, coding, and
tests may overlap; only one traffic operation may be live.

Use the [coordinator loop](#coordinator-loop) for advancing ready work,
resuming from status, and waiting for handoffs.

Keep finalized standard cases immutable through ordinary repair attempts. A
failed focused attempt changes the target and reuses the same cases; it does
not authorize fresh traffic. Read
[coordinator-recording.md](coordinator-recording.md) before explicitly requesting a
new standard recording or handling a consolidated capture refresh.

If the target fingerprint changes during focused Replay, discard that result
and return the API to Replay. If later integration changes the fingerprint of a
completed API, move it to deferred `revalidation_pending`. Ordinary pending and
implementation actions run first. When none is executable and verification
resources are free, the engine selects one stale API in stable inventory order,
even while other workers run or APIs wait for system repair. A passing API is
verified for the current fingerprint; a target-code failure dispatches/resumes
its worker, and a system failure is parked with its repair route. Continue
selecting eligible work until all APIs pass or remaining failures require
external system repair. A later integration may invalidate earlier successes;
final completion still requires one current content fingerprint. A commit with no effective content change does
not create a new validation epoch.

For a high-impact shared module, global configuration, or startup change, the
caller may explicitly request earlier verification for selected stale APIs; routine
coordination already uses idle verification capacity without such a request:

```text
backend-rewrite verification request \
  --api 'GET /api/a' \
  --api 'POST /api/b' \
  --reason 'shared response mapper changed'
```

Execute the returned `next.action.commands.advance`. Only
`revalidation_pending` APIs are eligible. This optional check spends extra
serialized traffic time and never replaces the mandatory final epoch.

`awaiting_recording_refresh` is parked, not complete or blocked. Continue other
pending APIs and resume existing workers until the engine returns one
consolidated full-scope recording action. Follow
[coordinator-rule-actions.md](coordinator-rule-actions.md) for the
capture/rule transition and [coordinator-recording.md](coordinator-recording.md)
for that recording.

## Completion Invariants

Keep worker handoff, work-item completion, and workflow completion distinct. A
worker handoff supplies a reviewed code version, local results, and required inputs; only integrated
acceptance can complete its API or process output. Later integrated changes may
make that item `revalidation_pending`. Retain every work item's worker binding
and worktree until `terminal_allowed=true` and final delivery no longer needs
them.

Preserve `workflow.require_comparison` for the current recording batch. When
false, Replay may complete an API while `comparison_current=false`. The first
completed batch enables Comparison for future recordings without changing this
batch; follow its final `advance_required` to persist the transition. Never
infer requirements from historical pass counts.

Only `terminal_allowed=true` permits successful workflow completion. Finish the
caller-required repository checks and delivery after the engine's final gates.
A worker's external-input blocker is evidence for the existing route, not
permission to mark completion. Preserve bindings and evidence when the engine
returns global `blocked`, and resume through its returned action after repair.
