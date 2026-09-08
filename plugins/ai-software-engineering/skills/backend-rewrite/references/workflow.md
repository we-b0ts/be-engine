# Workflow Coordinator

Audience: the workflow coordinator. Read at every session start or resume,
including sessions waiting for existing workers. This is the single guide for
the coordinator loop, action handling, waiting, and completion. The rewrite
engine selects actions; the coordinator executes and reports them. Load detailed
references through the role and action routing in `SKILL.md`.

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
after initialization must read that evidence completely. Remove each entry
after the rewrite has fully understood it, implemented the required behavior,
or proved it irrelevant; keep no resolved history and remove the file when it
is empty. When progress is proven blocked and the workflow coordinator is about to
stop, create or update the same file with useful resume context. Treat it as
AI-owned reference and handoff context, never as engine state;
`backend-rewrite status` remains authoritative.

## Coordinator Loop

Start with unscoped `status` in the canonical target repository. Top-level
`pending` counts operations the coordinator can perform now, including one
explicit wait when no productive action is ready. The engine selects
across all APIs and process outputs, including parked implementation issues.
Use `pending`, `action`, and `terminal_allowed`; do not reconstruct scheduling
from `workflow.phase`, `current_api`, or `api_inventory.unverified`.

```text
state = status()
while true:
    collect worker events already available from the task runtime
    match each event to its dispatch and report through its owning engine command
    refresh state from the latest report response, or status() if needed
    if state.terminal_allowed:
        finish delivery and break
    if state.action.kind == "blocked":
        preserve resume context, report the blocker, and stop this run
    if state.pending > 0:
        execute the returned action's command or task runtime operation
        report its actual result when confirmation or feedback is required
        state = the current response, or status() if the response was lost
        continue
    handle any reported input requirement or execution failure
    do not infer completion from zero pending
```

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
present in `commands`; an empty command object never implies a fallback. Status
does not guarantee an unconditional top-level `next` command. Source-process
traffic is issue-scoped evidence, not engine state. Both unscoped and
scoped status return compact scheduling actions, as does `next`. Dispatch the
worker role, exact scope, canonical target root, and absolute worktree as defined
in [coordinator-worker-protocol.md](coordinator-worker-protocol.md). The worker
fetches its own overview through `evidence --api` or `evidence --process-output`,
then selects relevant commands from `queries`. Scheduling responses contain no
evidence command or diagnostic payload. An API worker executes the returned
`source_process_traffic` command only when startup,
configured process-owned traffic, background refresh, or local-cache behavior
is relevant.

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

Read [recording-lifecycle.md](recording-lifecycle.md), execute its exact
recording action, and poll only the status command returned by that execution.
Do not reconstruct a recording command or discover its run by recency.

### `recording_in_progress`

Read [recording-lifecycle.md](recording-lifecycle.md) and execute `commands.wait`. After it returns, reconcile worker events and
refresh global status. Do not start another executor or advance before the exact
finalized run becomes `advance_required`.

### `case_pattern_identification_required`

This rare post-recording batch belongs only to the workflow coordinator. Read
[case-pattern-identification.md](case-pattern-identification.md); do not
dispatch it to an API worker or handle it as ordinary issue diagnosis.

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

Read [recording-lifecycle.md](recording-lifecycle.md) and execute the exact
`commands.execute` for its allocated run ID. This creates comparison evidence;
it never replaces the shared standard cases or authorizes a standard recording
request.

### `input_required`

When `details.reason=configuration_commit_required`, the workflow coordinator reviews
and commits exactly the listed persistent configuration changes in the canonical
target worktree, then repeats the original `next` command with the same scope
and inputs. This gate covers `project.yaml`, `source-traffic-policy.yaml`, and
`verification.yaml`, including staged and new files. Staging is not sufficient.
`status` reports this requirement without writing files; `next` stops before
dispatch or verification, including when preparation creates a policy change.
An active operation keeps its existing wait/recovery action. Routine generated
`progress.yaml` updates retain the final-delivery commit flow below.

When a selected dynamic API pattern lacks a proven source registration route,
provide only the requested `--source-route` through the returned command. Do
not infer additional input or change the shared recording scope.

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

### `target_quality_required`

Execute only `action.commands.execute` in its absolute canonical `cwd`. The
only permitted command extension is one or more exact
`--hardcode-ai-verified` arguments after this built-in gate reports the matching
locations and the required source evidence has been committed. Never run this
gate in a worker worktree. The command launches a detached operation; continue
consuming its returned action. Successful execution records the integrated
target fingerprint and makes focused Replay eligible through `advance_required`. A later integration or quality-gate configuration change
creates a new fingerprint and another quality action. On failure, fix the
reported cause and execute the returned `execution_failed.commands.retry`.

The gate list always starts with the built-in `replay-isolation` scan. Relative
to the configured `pr_base`, it checks only added lines in changed or untracked
Rust files in the integrated worktree, including staged and unstaged changes.
It scans text directly without parsing Rust syntax. Added comments,
documentation, macros, invalid intermediate Rust, and test code are therefore
visible to the gate; an unchanged legacy occurrence in a modified file is not.

Every added Rust line, including files below `tests/`, is rejected when it
contains the replay-only `.trp.test` suffix. Other replay-private environment,
fake-IP, runtime-path, and recording-artifact markers remain restricted to
production paths. Every added Rust line is also checked case-insensitively for
`sample.test` and `demo.test`. Those public domains are allowed only when the
workflow coordinator proves that the same value is hardcoded in source code and
records one commit trailer per target occurrence:

```text
Hardcode-Source-Evidence: TARGET_FILE:LINE:COLUMN <= SOURCE_REPOSITORY@SOURCE_REVISION:SOURCE_FILE:LINE:COLUMN
```

`SOURCE_REVISION` must be the 7-64 hexadecimal commit ID inspected by the AI;
traffic, recordings, logs, runtime configuration, and container state are not
source-code proof. After committing the trailer, rerun the unchanged quality
command with one repeatable target-to-source evidence mapping per occurrence.
The argument must exactly match the committed trailer:

```text
--hardcode-ai-verified TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@SOURCE_REVISION:SOURCE_FILE:LINE:COLUMN
```

The target occurrence itself must be committed at that exact position; an
uncommitted line cannot reuse evidence from another commit. Missing, duplicate,
stale, or unrelated positions fail closed. This approval applies only to the
two source-sensitive public-domain rules and never exempts
`.trp.test` or another replay-private marker. Repository quality-gate
configuration may add commands but cannot disable this scan; an explicit empty
gate list still leaves `replay-isolation` active.

### `system_repair_required` and `recovery_required`

Read
[recovery-and-system-repair.md](recovery-and-system-repair.md) and execute only
the engine-issued repair or recovery command. `wait_required` never
authorizes recovery.

### `recording_refresh_pending`

The scoped API is parked until one consolidated standard recording can replace
the baseline. Read [recording-lifecycle.md](recording-lifecycle.md), execute `commands.wait`, and never execute its stale acceptance.
Continue other runnable work only through current engine-issued commands.

### `complete`

API-scoped `complete` means only that API has current passing focused E2E and
comparison evidence. Process-output-scoped `complete` means only that output
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
[recording-lifecycle.md](recording-lifecycle.md) before explicitly requesting a
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
capture/rule transition and [recording-lifecycle.md](recording-lifecycle.md)
for that recording.

## Completion Invariants

Keep worker handoff, work-item completion, and workflow completion distinct. A
worker handoff supplies a tested patch and coordinator inputs; only integrated
acceptance can complete its API or process output. Later integrated changes may
make that item `revalidation_pending`. Retain every work item's worker binding
and worktree until `terminal_allowed=true` and final delivery no longer needs
them.

An evidence-proven unavailable external response-driving value may be blocked
under [worker-diagnosis.md](worker-diagnosis.md). A blocker is not successful
completion and must never be reported as `terminal_allowed=true`.
