# Coordinator

Audience: the workflow coordinator. Read at every session start or resume,
including sessions waiting for assigned agents. Own action execution, result
reconciliation, waiting, and completion. Delegate source diagnosis, code edits,
and integration analysis. Load only the coordinator references linked at the
relevant action below.

## Coordinator Boundary

The engine selects the legal action; the coordinator executes or delegates it.
API implementers own API diagnosis and implementation. The retained code integrator owns
candidate preparation and review. An engine-requested API expert investigates
read-only and reports through the coordinator to the existing API implementer. The
task runtime supplies live handles and events but does not replace engine state.

Do not turn a task mode into another role: `route_analysis` belongs to an API
implementer, and source review belongs to the code integrator. Only the coordinator reports
their results to the engine or performs coordinator-owned mutations.

## Contents

- Coordinator boundary
- Session start and resume
- Execution rules
- Action routing
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

If `status` returns `purpose_required`, handle it before all old dispatch,
expert and old-worker runtime-query actions. Read the
[purpose confirmation protocol](coordinator-agent-protocol.md#authorized-regression-start).
Actually query current-session active child agents (excluding self, unrelated
peers, engine bindings and historical sessions); require zero and supply count,
query command and time. Confirm the user's purpose through the returned command; the engine generates and
enters a fresh work branch. No branch creation or separate regression command is
required from the coordinator. Old workers are not queried, resumed or waited for.
The base branch always requires confirmation, even when code is unchanged or an
old workflow is unfinished. An explicit user request supplies purpose authorization;
otherwise ask the user to choose. On a work branch, continue the normal workflow.

Follow the returned action to start an absent rewrite workflow.
Before the engine adopts external standard recordings, omit `--api`. Missing
evidence returns `input_required`; follow
[external recording evidence](coordinator-recording.md). After the engine
publishes its stable inventory, select work with the exact API path/pattern.
The standalone recording service has no per-run API selector; ingress and
preserved Recorder include/exclude rules bound capture. If an action response was lost or the session is
resuming, recover the engine scheduler's current action with unscoped read-only
`status`; scoped status serves work-item inspection. Execute the returned
action's command to advance the workflow.

After handling a user interruption, worker handoff, integration, or other side
work, and before waiting or ending the current turn, return to the
[coordinator loop](#coordinator-loop).
Status restores the next action, including a pending dispatch confirmation or
post-confirmation advance. Keep the complete response and execute its supplied
command directly; each response determines the following step. For a live
operation, follow the mandatory runtime query pass before waiting and on return.

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

## Execution Rules

- Do not invoke `sleep`. Use the engine-returned wait command or the task
  runtime's bounded wait interface.
- Execute engine commands directly, one at a time. Do not wrap them in scripts
  or functions, or execute them through loops, command chains, or automatic runners.
- Read each complete response and handle task events before deciding the next
  engine command. Do not prearrange subsequent commands.

## Action Routing

Use `action.kind` and, for `input_required`, `details.reason` as the routing
contract. The engine remains authoritative for the exact command. Read only the
listed protocol before handling that action.

| Action | Coordinator responsibility | Agent or external owner | Protocol |
| --- | --- | --- | --- |
| `purpose_required` | Confirm the user-authorized purpose after the required live runtime query | None | [authorized regression start](coordinator-agent-protocol.md#authorized-regression-start) |
| `recording_in_progress`, `recording_refresh_pending` | Observe external publication and wait for the selected evidence | External recording owner | [recording actions](coordinator-recording.md) |
| `case_pattern_identification_required` | Retain the batch, delegate analysis, then apply the exact result | API implementer in read-only `route_analysis` mode | [case patterns](coordinator-case-patterns.md) |
| `implementation_required`, `worker_status_required` | Dispatch/resume/query the bound implementer and report actual runtime observations | API implementer | [agent protocol](coordinator-agent-protocol.md) |
| `expert_required` | Reserve, dispatch, reconcile, forward, and close exactly as returned | API expert, reporting to the existing API implementer | [API expert assistance](coordinator-agent-protocol.md#api-expert-assistance) |
| `integration_required` | Retain identity, publish only the reviewed candidate, then report integration | Code integrator | [integration](coordinator-integration.md) |
| `source_review_required`, `target_quality_required` | Delegate candidate review or rework and admit only a matching report | Code integrator; API implementer only for a routed work-item defect | [review actions](coordinator-review.md) |
| `plan_apply_required` | Apply the unchanged engine plan with source-proven inputs | Inputs originate from the assigned API implementer worker | [rule actions](coordinator-rule-actions.md) |
| `input_required` | Resolve only the named input and resume the retained invocation | Delegate semantic/source questions to the owning API implementer or code integrator | [input handling](#input_required) and, for startup inputs, [startup inputs](coordinator-startup-inputs.md) |
| `system_repair_required`, `recovery_required`, `blocked` | Execute only the returned acceptance/recovery action or stop with retained context | External system owner may install the named repair | [recovery and system repair](coordinator-recovery.md) |
| `wait_required`, `worker_events_required` | Perform the mandatory runtime query pass, reconcile events, then wait or refresh status | Task runtime provides live observations | [mandatory runtime queries](coordinator-agent-protocol.md#mandatory-runtime-queries) |
| `advance_required`, `execution_failed`, `complete` | Execute the returned advance/retry only when its stated prerequisite is satisfied; finish only with `terminal_allowed=true` | None | [core action handling](#core-action-handling) |

## Coordinator Loop

Use the existing `backend-rewrite` interface. Response schema v35 actions have
exactly `kind`, `summary`, `details`, and `commands`. Status/next expose scheduling
and short issue facts, not diagnostic payloads. Default `workflow` has `id` and
`revision`; use `inventory` for binding recovery and scheduling detail. Never
infer scheduling from a phase field or create another task queue.

Start with unscoped `status` in the canonical target repository. Top-level
`pending` counts operations the coordinator can perform now, including one
explicit wait when no productive action is ready. The engine selects
across all APIs, including parked implementation issues.
Use `pending`, `action`, and `terminal_allowed`; do not reconstruct scheduling
from `workflow.phase`, `current_api`, or `api_inventory.unverified`.

The following describes coordinator decisions; do not implement it as a script.

```text
state = status()
while true:
    if state.action.kind == "purpose_required":
        actually query active child sessions of this coordinator; require zero
        supply count, query command and time to the returned user-approved purpose command
        refresh status and continue
    reconcile implementation-worker results through the worker protocol
    reconcile integrator and route-analysis results with retained assignments
    reconcile expert results and forward reports through the worker protocol
    refresh state from the latest report response, or status() if needed
    if state.terminal_allowed:
        finish delivery and break
    if state.action.kind == "blocked":
        preserve resume context, report the blocker, and stop this run
    if the current action requires waiting on agents, checks worker status, or follows a bounded wait:
        actually invoke ListAgents (Claude Code) or equivalent runtime list/status tools
        match all outstanding assignments and query any unresolved entries
        reconcile returned states and results through the worker protocol
        refresh state after any reports and reconsider the action
    if the current action needs an integrator or route-analysis task just observed running or queued:
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
handle as an API implementer or invent new engine activities.
This wait guard does not apply to worker confirmation, status checks, or feedback;
execute those engine actions even when the API implementer is running.

Check for arrived events after every action, even while `pending` stays positive;
report handoffs immediately instead of holding their runtime events until the queue
drains or a sixty-minute activity report expires. The engine may keep a reported
handoff's integration waiting while it completes the first verification attempt for
every recorded API, allowing all independent implementation work to be dispatched
before ordinary integration begins. Dispatch experts only through engine-issued
[API expert assistance](coordinator-agent-protocol.md#api-expert-assistance);
do not initiate it yourself. Forward arrived expert reports on the same loop.
Report responses replace the previous scheduling action. Preserve each
event's actual worker handle, dispatch identity, and delivered handoff identity;
check them against the engine's current binding. Never relabel a stale event
with a newer dispatch or another handoff ID. An unknown worker activity is not
a running or idle observation.

When no productive action is ready but workers or engine operations remain,
`pending=1` selects `commands.wait`. Before waiting on agents, complete the
[mandatory runtime query pass](coordinator-agent-protocol.md#mandatory-runtime-queries)
and handle its results. Execute the returned wait only if it is still appropriate;
the command waits at most 30 seconds and may return sooner when engine-observable
state changes. On `worker_events_required`, actually invoke the runtime's
list/status tools again for all outstanding assignments, reconcile results and
events, report actual changes, then execute global `commands.status`. Use
`commands.inventory` to recover missing bindings or coverage. Querying every
worker does not require re-reporting every unchanged running observation.
The sixty-minute engine expiry never waives this per-wait query requirement.
Unknown runtime state is never reported as running.

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

`next` starts detached engine verification operations when needed.
Consume its returned actions immediately; do not
background the commands yourself or wait for a worker's entire lifecycle.
Replay verification holds a serialized traffic lease. External
recording has its own lifecycle. Dispatch,
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
mechanics are in [coordinator-agent-protocol.md](coordinator-agent-protocol.md).

## Engine Phase Order

The engine owns this phase order and returns the legal next action:

```text
adopt completed external traffic -> identify patterns for new uncovered APIs
    -> stable API inventory -> prepare -> focused Replay
    -> implementation issue -> reviewed handoff -> integration -> focused Replay
    -> API complete -> next API
    -> all included APIs pass at the current target fingerprint -> final delivery

source-proven capture gap -> apply capture rule -> API waits
    -> drain other runnable work -> wait for one full-scope external batch

source-proven Redis rule -> derive safe snapshot overlay from immutable evidence
    -> reuse the same recording
    -> require an external refresh only when strict derivation fails
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
in [coordinator-agent-protocol.md](coordinator-agent-protocol.md). Implementation
workers fetch their own diagnostics. Do not attach diagnostic payloads or
investigate business source in the coordinator.

### `wait_required` and `worker_events_required`

Execute `commands.wait` when verification resources are occupied or all workers
have just been queried and are running/queued. Follow the
[mandatory runtime query pass](coordinator-agent-protocol.md#mandatory-runtime-queries)
before waiting on agents and after each wait returns. Preserve the reported
blocking API and operation as context;
never start another traffic operation or recover a live owner. Wait returns
`worker_events_required`: a runtime list/status tool invocation is mandatory even
if no completion, failure or interruption event arrived. Reconcile all returned
worker states, report changes with their original dispatch/handoff identities,
then execute `commands.status`. Use `commands.inventory` to restore missing
bindings or coverage. The engine does not inspect the task runtime itself.
The coordinator performs coordination while idle; implementation and diagnosis
remain assigned to workers.

### `blocked`

All remaining incomplete APIs require external system repair, no implementation
worker needs coordination, and eligible revalidation has drained. End this run
as blocked; `pending=0` and `terminal_allowed=false`. Preserve worktrees and resume
context. Execute `commands.resume` after repair or an explicit resumed session;
do not loop on it immediately or claim successful delivery.

### `recording_in_progress`

The selected external recording is still being published. Execute `commands.wait`
and refresh status. The coordinator never starts or recovers its process.
See [external recording evidence](coordinator-recording.md).

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
`commands.advance` argv once. Never rerun the preceding recording, Replay, implementation, or quality command.

### `input_required`

For `recording_evidence_required`, follow
[external recording evidence](coordinator-recording.md). Place the completed
batch in the required directory, then repeat next. Rewrite does not execute recording.

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

When `details.reason=source_route_required`, a caller-selected dynamic API has
not yet produced a standard recording with confirmed case-pattern coverage and
lacks a proven source registration route. Recorded inventory APIs use their
confirmed case pattern without interrupting Replay. Assign
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

For `implementation_required`, `worker_status_required`, `integration_required`,
and `expert_required`, follow
[coordinator-agent-protocol.md](coordinator-agent-protocol.md).
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

An integrated API handoff schedules its own Replay. After ordinary work drains,
the engine verifies every included API against one integrated content fingerprint.

### `execution_failed`

A detached engine operation failed. `pending` excludes that failed
operation until its reported cause is resolved and its returned `commands.retry`
is executed. Continue other executable worker actions. Never hot-loop the retry
or treat the failure as completion. A stopped operation without a completion
record uses the existing recovery action.

### `source_review_required`

Worker and integration handoffs require passing reports from the same complete
local quality suite. A `source_review_required` action requests candidate
review, evidence or worker rework through
[coordinator-review.md](coordinator-review.md). It is actionable work, not an execution
failure. Return to global status after handling it. A new purpose trusts the
committed `pr_base` snapshot: adopt external evidence and run initial Replay
without source review.
If no source/configuration changes were made, passing verification and committed
progress can complete without a review receipt. Historical review files do not
change this. Once the purpose has changes relative to that baseline, verification
and final delivery require a current accepted integration quality report even
when no API remains in implementation. Delegate those checks to the integrator;
the coordinator consumes reports and does not run the quality suite itself.
Once a finding has been routed, worker dispatch, status and integration take
priority. With no such action ready, `wait_required` on `source_review_rework`
waits for that repair; follow `commands.wait` and runtime events. Scoped status
continues exposing each worker's own handoff commands.

### `target_quality_required`

This legacy action/command no longer executes quality checks in the coordinator.
`target-quality run` validates an already accepted current quality receipt.
Obtain missing or stale proof through `source_review_required` and the retained
code integrator, then admit its exact published report. Do not hot-loop a legacy
quality retry or use its arguments to waive missing candidate proof.

`review check` in both delivery worktrees runs the mandatory isolation gate even
with no configured repository checks, including source-sensitive public domains
such as `demo.test`. The assignee handles findings and evidence before delivery.
Review reports freeze code, configuration, rules and relevant runtime inputs;
changes require a new report before the coordinator can advance.

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

API-scoped `complete` means that API passes focused Replay for the current batch.
Finish repository-wide verification and delivery only when `terminal_allowed=true`
proves every included API passes at the current target fingerprint and the final
public `progress.yaml` is committed. Use `inventory` for the full per-API list.

## API Inventory And Serialized Traffic

HTTP worker scopes are canonical paths/patterns. The API inventory summarizes
routes and exposes each route's method-keyed verification ledger in `methods`;
it is not a list of worker assignments. Use
`details.worker.work_scope` and the engine-issued commands when dispatching,
resuming, integrating or accepting. A route acceptance selects all included
method cases and runs one Replay/target session; each method keeps its own
focused evidence and progress. Excluded methods stay skipped. HTTP coordinator
selectors accept only the route; `METHOD API` selectors are rejected.

Every initialized action or status includes a bounded `api_inventory` summary:
`total`, `completed`, `unverified`, `implementation_required`,
`system_repair_required`, `awaiting_recording_refresh`, `revalidation_pending`, `current_index`, and
`current_api`. Every count is a route count for HTTP. `current_api` is the
canonical path/pattern without a method; `current_index` addresses the stable
route `items` order, determined by each route's first occurrence in the
recorded method ledger. Expanded `inventory` items contain `api`, aggregate
`status`, and `methods` with the individual `METHOD API` verification states.
Only fully skipped routes count as skipped. All included methods must be
complete before a route counts as completed. Otherwise each route counts once
under its highest-priority outstanding state: system repair, recording refresh,
implementation, active verification, revalidation, then unverified. MOTAN
entries retain their existing protocol-qualified identity.
The engine owns this read-only projection; it does not change stored progress,
worker bindings, or receipts. In expanded `inventory`,
`workflow.scope` selects work from the adopted standard recording and is separate
from the selected API. An
omitted selector produces `recorded_api_inventory`: every API that actually
publishes a case in the selected standard recording enters the inventory, while
an API with no observed traffic is not required and does not block completion.
The scope remains stable as selected workers change.

Normal issued API commands use route selectors, including rule/repair Replay,
API completion and idle revalidation. `verification request --api
'/path-or-pattern' --reason '<shared change>'` promotes all included stale
methods on that route without selecting skipped methods. An unscoped `next`
uses the same route batch as an explicit route command. Methods are implementation
and verification details, never separate coordinator work items.

Every `implementation_required` action uses a worker. Inventory size controls
only how much work the engine can make ready. Worker concurrency belongs to
the task runtime; the coordinator does not impose a limit. The engine may park
implementation and system-repair issues while it serializes the selected API's Replay. Expensive worker diagnosis, coding, and
tests may overlap; only one traffic operation may be live.

While any recorded API has no focused verification attempt, the engine gives that
first-pass Replay priority over ready worker handoff integration and integrated
handoff acceptance. Worker dispatch, resume, status reconciliation, and feedback
remain immediately actionable. Once every API has an attempt, ordinary integration
and acceptance resume; final fingerprint revalidation still proves the combined
target.

Use the [coordinator loop](#coordinator-loop) for advancing ready work,
resuming from status, and waiting for handoffs.

Keep finalized standard cases immutable through ordinary repair attempts. A
failed focused attempt changes the target and reuses the same cases; it does
not authorize fresh traffic. Read
[coordinator-recording.md](coordinator-recording.md) when a new external standard
batch is required or a consolidated capture refresh is pending.

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
  --api '/api/a' \
  --api '/api/b' \
  --reason 'shared response mapper changed'
```

Execute the returned `next.action.commands.advance`. Only
`revalidation_pending` APIs are eligible. This optional check spends extra
serialized traffic time and never replaces the mandatory final epoch.

`awaiting_recording_refresh` is parked, not complete or blocked. Continue other
pending APIs and resume existing workers until the engine returns one
consolidated external recording requirement. Follow
[coordinator-rule-actions.md](coordinator-rule-actions.md) for the
capture/rule transition and [coordinator-recording.md](coordinator-recording.md)
for external evidence handoff.

## Completion Invariants

Keep worker handoff, work-item completion, and workflow completion distinct. A
worker handoff supplies a reviewed code version, local results, and required inputs; only integrated
acceptance can complete its API. Later integrated changes may
make that item `revalidation_pending`. Retain every work item's worker binding
and worktree until `terminal_allowed=true` and final delivery no longer needs
them.

Local `.traffic-e2e/regression.yaml` uses `only` to select exact inventory routes
without an HTTP method, including every recorded method on each route. A pattern
is an exact inventory name. Omitted, null or empty `only` selects all recorded APIs.
`skip` takes precedence; excluded APIs are explicitly skipped and do not block
completion. This ignored file does not change code fingerprints or require a commit.
Preserve the user's selected scope; a terminal result covers that scope.

Optional `recording_run_id` directly selects an existing completed standard
recording as the regression baseline. Missing or unusable recordings block
progress; do not substitute another recording or recapture historical requests.
Switching IDs resets current verification, with `only` / `skip` applied to the
selected inventory. Respect this selection; a required fresh capture needs the
user to remove or clear the field. Omitted, null or empty-string values keep the
current baseline in effect, or allow completed external evidence discovery when
no baseline has been adopted.

Only `terminal_allowed=true` permits successful workflow completion. Finish the
caller-required repository checks and delivery after the engine's final gates.
A worker's external-input blocker is evidence for the existing route, not
permission to mark completion. Preserve bindings and evidence when the engine
returns global `blocked`, and resume through its returned action after repair.

Redis lock token candidates are exposed by current `dirty_clusters` evidence,
including conditional `redis_lock` hints/planners. Use `dependency-rule plan
redis lock` with the returned evidence ID, explicit host/port/key scope and
implementer source proof; review/apply the returned plan and run fresh Replay.
Do not require UUID formatting, script SHA configuration or a second release
rule. The engine retains nonce correlation and every other command argument.
Old reports require fresh Replay to obtain witnesses. Wrong tokens after an
applied rule remain target defects, not a request to weaken the rule.
