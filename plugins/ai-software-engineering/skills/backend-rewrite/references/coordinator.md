# Coordinator

Audience: the workflow coordinator. Read at every session start or resume,
including sessions waiting for assigned agents. Own action execution, result
reconciliation, waiting, and completion. Delegate source diagnosis, code edits,
and integration analysis. Load only the coordinator references linked at the
relevant action below.

## Coordinator Boundary

The engine selects the legal action; the coordinator executes or delegates it.
Repository analysts own read-only source route, module-group and independent
dependency attribution analysis, including Source-proven task/lifecycle rule
proposals. API implementers own API diagnosis and implementation. The retained
code integrator owns candidate preparation and review. An engine-requested API expert investigates
read-only and reports through the coordinator to the existing API implementer. The
task runtime supplies live handles and events but does not replace engine state.

`route_analysis` belongs to the repository analyst, and source review belongs to
the code integrator. Neither task is an API-implementer assignment. Only the
coordinator reports their results to the engine or performs coordinator-owned
mutations.

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
| `case_pattern_identification_required` | Retain the batch, delegate analysis, then apply the exact result | Repository analyst in read-only `route_analysis` mode | [case patterns](coordinator-case-patterns.md) |
| `repository_analysis_required` | Complete incremental grouping before Replay | Repository analyst | [repository analysis](coordinator-repository-analysis.md) |
| `dependency_attribution_required` | Obtain the exact context, reconcile rule assessment and proposals, then apply independent ownership proof | Repository analyst in read-only `dependency_attribution` mode | [independent dependency attribution](coordinator-rule-actions.md#independent-dependency-attribution) |
| `implementer_dispatch_required` | Create/resume the fixed slot and confirm its exact same-group API batch | API implementer | [fixed implementers](coordinator-implementers.md) |
| `implementation_required`, `worker_status_required` | Dispatch/resume/query the bound implementer and report actual runtime observations | API implementer | [agent protocol](coordinator-agent-protocol.md) |
| `expert_required` | Reserve, dispatch, reconcile, forward, and close exactly as returned | API expert, reporting to the existing API implementer | [API expert assistance](coordinator-agent-protocol.md#api-expert-assistance) |
| `integration_required` | Retain identity, publish the exact merged candidate, then report integration without review check | Code integrator | [integration](coordinator-integration.md) |
| `source_review_required`, `target_quality_required` | Reconcile legacy requests; ordinary source review is deferred to final pre-revalidation | Code integrator; API implementer only for a routed work-item defect | [review actions](coordinator-review.md) |
| `pre_revalidation_review_required` | Delegate the configured quality requirement and final reporting command, publish the exact candidate, and accept its final-stage receipt | Code integrator | [final review](coordinator-review.md#final-review-before-full-revalidation) |
| `plan_apply_required` | Apply the unchanged engine plan with source-proven inputs | Inputs originate from the assigned API implementer or repository analyst | [rule actions](coordinator-rule-actions.md) |
| `input_required` | Resolve only the named input and resume the retained invocation | Delegate semantic/source questions to the owning API implementer or code integrator | [input handling](#input_required) and, for startup inputs, [startup inputs](coordinator-startup-inputs.md) |
| `system_repair_required`, `recovery_required`, `blocked` | Execute only the returned acceptance/recovery action or stop with retained context | External system owner may install the named repair | [recovery and system repair](coordinator-recovery.md) |
| `wait_required`, `worker_events_required` | Perform the mandatory runtime query pass, reconcile events, then wait or refresh status | Task runtime provides live observations | [mandatory runtime queries](coordinator-agent-protocol.md#mandatory-runtime-queries) |
| `advance_required`, `execution_failed`, `complete` | Execute the returned advance/retry only when its stated prerequisite is satisfied; finish only with `terminal_allowed=true` | None | [core action handling](#core-action-handling) |

## Coordinator Loop

Use the existing `backend-rewrite` interface. Actions have
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
drains or a sixty-minute activity report expires. Dispatch experts only through
[engine-issued API expert assistance](coordinator-agent-protocol.md#api-expert-assistance);
do not initiate it yourself. Forward arrived expert reports on the same loop.
Report responses replace the previous scheduling action. Preserve each
event's actual worker handle, dispatch identity, and delivered handoff identity;
check them against the engine's current binding. Never relabel a stale event
with a newer dispatch or another handoff ID. An unknown worker activity is not
a running or idle observation.

When no productive action is ready but workers or engine operations remain,
`pending=1` selects `commands.wait`. Follow the
[wait action handling](#wait_required-and-worker_events_required) before executing
it. The returned engine wait lasts at most 30 seconds and may return sooner when
engine-observable state changes.

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

The engine limits implementation slots to the workflow’s effective
`max_implementers` (default 16). Submit returned same-group batches to their fixed
slots, retain the actual handle for accepted queued work, and respect runtime
backpressure after a rejected submission. A rejected
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

Worker-proven rule proposals for other completed API attempts may also be
planned during Replay; see [rule actions](coordinator-rule-actions.md). Busy
Apply preserves the plan and returns waiting guidance. At the next idle
boundary the engine prioritizes pending plans after either a pass or an
implementation failure, before continuing verification or integration.

Use `inventory` when a scheduling breakdown or binding recovery is needed.
`details.ready` counts sum to `pending`; `details.waiting` describes outstanding
work. Scoped status retains global `pending` while showing one item's action.
After inspecting an item, return to global status for the loop. Worker event,
dispatch, and handoff mechanics are in
[coordinator-agent-protocol.md](coordinator-agent-protocol.md).

## Engine Phase Order

The engine owns this phase order and returns the legal next action:

```text
adopt completed external traffic -> identify patterns for new uncovered APIs
    -> stable API inventory -> finish incremental module analysis and grouping
    -> freeze group Replay round -> replay every admitted API, save each result
    -> dispatch same-group failure batch to its fixed implementer slot
    -> committed partial handoff (one/many APIs, possibly across assigned groups)
    -> integrate exact deliveries -> group acceptance Replay
    -> repeat failures or continue other groups
    -> final quality-check review -> one complete actual batch session
    -> project that session's method results -> final delivery

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

Before waiting on outstanding agents and after every bounded engine or task-runtime
wait, actually invoke runtime list/status tools for all outstanding assignments.
Follow the complete [runtime query protocol](coordinator-agent-protocol.md#mandatory-runtime-queries),
including parked workers and retained non-implementation tasks. Events, historical
observations and the sixty-minute engine expiry do not replace this pass. Unknown
runtime state is neither running nor idle.

Execute `commands.wait` only while its returned prerequisite still holds. On
`worker_events_required`, reconcile the required query pass and arrived results,
report changes with their original dispatch/handoff identities, then execute
`commands.status`. Use `commands.inventory` to restore missing bindings or coverage;
unchanged running observations need not be reported again. Preserve the blocking
API and operation; a wait never authorizes another traffic operation or recovery
of a live owner. Implementation and diagnosis remain assigned to workers.

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
read-only route analysis of the complete batch to the repository analyst, then
apply its matched result through the returned command. Do not create an
implementation issue for it.

### `repository_analysis_required`

Read [repository analysis](coordinator-repository-analysis.md). Give the analyst
fresh context containing all existing groups and exactly the pending APIs. Apply
one complete incremental submission through the returned batch/version-bound
command. Finish analysis before Replay; no overlap or implementer binding is
needed. Existing grouped APIs reuse the project catalog.

### `dependency_attribution_required`

Read [independent dependency attribution](coordinator-rule-actions.md#independent-dependency-attribution).
Dispatch the exact current context and relevant effective task/lifecycle
declarations to the read-only repository analyst. Reconcile both its ownership
proof and its assessment of whether the existing rule covers the Source lifecycle.
Publish supported rule changes through the existing plan/apply transaction,
obtain fresh context, then apply the proof. Reuse adequate rules and preserve the
ordinary manual-proof fallback described by that protocol.

### `implementer_dispatch_required`

Read [fixed implementers](coordinator-implementers.md). Accept the engine’s
round-robin group mapping or explicitly adjust future mapping, then dispatch the
exact same-group batch to the returned `api-implementer-N` slot and fixed path.
Confirm the accepted runtime handle through `commands.confirm`. More than 16
groups reuse the slots. Runtime reports and completed-subset handoffs retain
per-API dispatch and lease identities.

### `plan_apply_required`

Execute the exact unchanged `commands.apply` once; never rerun planning or
reconstruct selector inputs. For response-rule, recorder-capture,
process-owned-dependency or async lifecycle plans, first read
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
This gate covers `project.yaml` and its configured `project.policy` file,
including staged and new files. Staging is not sufficient.
`status` reports this requirement without writing files; `next` stops before
dispatch or verification, including when preparation creates a policy change.
An active operation keeps its existing wait/recovery action. Routine generated
`progress.yaml` updates retain the final-delivery commit flow below.

When `details.reason=source_route_required`, a caller-selected dynamic API has
not yet produced a standard recording with confirmed case-pattern coverage and
lacks a proven source registration route. Recorded inventory APIs use their
confirmed case pattern without interrupting Replay. Assign
`repository-analyst` a read-only `route_analysis` task with the exact API, source
location, and a retained assignment ID, following
[repository-analyst.md](repository-analyst.md). Retain its actual runtime handle and
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
the dirty configured `project.policy` file when applicable, alongside the final public
progress snapshot. Intermediate failed or passing attempts do not
require progress commits.

### Worker And Integration Actions

For `implementer_dispatch_required`, `implementation_required`,
`worker_status_required`, `integration_required`,
and `expert_required`, follow
[coordinator-agent-protocol.md](coordinator-agent-protocol.md).
Dispatch/resume, task runtime observations, handoffs, and integration are reported
through the exact returned commands. Pooled confirmation binds the returned same-group batch; it does not freeze
scheduling or feedback for other slots. A worker ending
without a handoff requires resume, not acceptance.

`pending` counts executable coordinator actions, including these worker
operations. If worker delivery or a Replay resource is the only remaining
activity, one explicit `wait` contributes one pending operation.
The engine returns work across the whole inventory before returning a global
wait. The coordinator consumes actions and reports task runtime events; it does not
rebuild that queue from API counters or historical confirmations.

An integrated API handoff schedules its own Replay. After ordinary work drains,
the engine requires final pre-revalidation review, then verifies the complete
sealed Source run once against the admitted candidate. The same actual session
supplies final method results; do not add per-API final runs or another sweep.

### `execution_failed`

A detached engine operation failed. `pending` excludes that failed
operation until its reported cause is resolved and its returned `commands.retry`
is executed. Continue other executable worker actions. Never hot-loop the retry
or treat the failure as completion. A stopped operation without a completion
record uses the existing recovery action.

### `source_review_required`

Ordinary worker and integration delivery no longer request this gate. Submit
committed delivery identities, publish the integrator's exact candidate, and
report integration without review check. Consolidated Source/isolation, file
size and asynchronous ownership checks run only at
`pre_revalidation_review_required`. Reconcile a retained legacy request with
current status rather than restarting a per-delivery check cycle. Source
findings routed from final review still use the existing repair protocol in
[coordinator-review.md](coordinator-review.md).

### `pre_revalidation_review_required`

This is an engine state-machine prerequisite before final full revalidation,
not a skill reminder. Delegate `details.quality_check`, `details.quality_paths`
and the returned `review check --pre-revalidation --quality-check TOOL
--worktree ...` to the retained integrator. It executes the required tool on the
final committed candidate before reporting success. The engine command performs
Source/isolation checks and records the attestation without executing repository
commands. The integrator fixes routine findings and returns the exact candidate
and final-stage receipt. Follow [final review](coordinator-review.md#final-review-before-full-revalidation).

Publish the exact candidate and submit `review accept`. The engine requires
current code, relevant inputs, check policy, inventory and immutable recording
bindings. Missing, failing, ordinary-integration and stale reports cannot permit
full revalidation. Relevant changes require fresh final proof; a progress-only
publication can retain an already admitted matching receipt. Return to global
status after admission; follow the returned `BatchReplay` action. One complete
actual Source-run session must also cover every required workflow method API.
Scoped capture does not erase that method requirement. Missing Source inputs
remain pending, and historical API receipts cannot substitute for the session.

### `target_quality_required`

This legacy action/command no longer executes quality checks in the coordinator.
`target-quality run` validates an already accepted current quality receipt.
Ordinary Replay no longer waits for source-review receipts. Follow current
status; final proof is issued only by `pre_revalidation_review_required`.
Source/Replay-isolation, public-domain hardcodes, file-size and spawn-ownership
checks are consolidated there. Ordinary integration only merges and resolves
conflicts; identity admission never executes source review or repository tools.

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
it is not a list of worker assignments. Use pooled dispatch/task identities (or legacy `details.worker.work_scope`)
and the engine-issued commands when dispatching,
resuming, integrating or accepting. A route acceptance selects all included
method cases and runs one Replay/target session; each method keeps its own
focused evidence and progress. Excluded methods stay skipped. HTTP coordinator
selectors accept only the route; `METHOD API` selectors are rejected.

`api_inventory` counts HTTP routes. All included methods must be complete before
a route counts as completed; only fully skipped routes count as skipped. Use
expanded `inventory` for aggregate route status and individual `METHOD API`
verification states. MOTAN entries retain their protocol-qualified identity.
These are engine-owned projections, not a coordinator scheduling queue.

`workflow.scope` selects work from the adopted standard recording independently
of the currently selected API. Without a selector, every API with a published
case enters the inventory; unobserved APIs do not block completion. The scope
remains stable as selected workers change.

Normal issued API commands use route selectors, including rule/repair Replay,
API completion and round revalidation. `verification request --api
'/path-or-pattern' --reason '<shared change>'` reports included stale methods
through the same all-accepted-or-gap and round-membership gates; it never promotes
them to ordinary pending work, selects skipped methods, interrupts the current
round or repeats a consumed member. An unscoped `next`
uses the same route batch as an explicit route command. Methods are implementation
and verification details, never separate coordinator work items.

New workflows have a fixed pool, default 16, and a project-level API grouping
catalog. Groups are unlimited and map round-robin to slots; coordinator-adjusted
mappings affect future dispatch. Each slot queues multiple APIs/groups but runs
one API at a time. The engine serializes traffic and publication while independent
implementer coding and tests may proceed.

Complete grouping for all new selected APIs before the first Replay. Each group
round freezes its eligible routes and target/recording identity, saves per-API
results, and continues after ordinary failures. Dispatch that group’s failed
APIs only once its round completes, before starting the next group's Replay.
At group boundaries, prioritize APIs with no Replay attempts over integration,
acceptance Replay and pending refreshes with prior attempts. Resume integration
and acceptance when no eligible first attempt remains, preserving rule, review
and repair gates. Acceptance rounds include only exact committed/integrated or
otherwise admitted API methods; an
unhanded sibling does not acquire Replay permission through group membership.
Infrastructure interruption preserves completed results and unfinished membership.

Use the [coordinator loop](#coordinator-loop) for advancing ready work,
resuming from status, and waiting for handoffs.

Keep finalized standard cases immutable through ordinary repair attempts. A
failed focused attempt changes the target and reuses the same cases; it does
not authorize fresh traffic. Read
[coordinator-recording.md](coordinator-recording.md) when a new external standard
batch is required or a consolidated capture refresh is pending.

If the target fingerprint changes during focused Replay, discard that unaccepted
result and keep the API eligible for a valid attempt. Later content changes mark
completed APIs `revalidation_pending` without immediately repeating Replay.
Follow the engine's revalidation actions only after pending workers, handoffs,
delivery acceptance and recording refresh finish and each included method is
complete, stale awaiting revalidation, or at a confirmed system gap.

Drain the current round even when an API fails: record the failure and continue
remaining members before dispatching repairs or integrating handoffs. Each method
runs once per round; later fingerprint changes affect the next round rather than
restoring consumed membership. Resume/recovery retains unfinished membership.
After the round, repair and accept all failures or confirm their system gaps
before another round. One successful repair cannot start another round while
other implementation/acceptance remains unfinished. Follow `blocked` if only
system gaps remain; success still requires current passing evidence for every
included method and the final publication gate. Content-preserving commits do not
invalidate evidence.

`awaiting_recording_refresh` is parked, not complete or blocked. Continue other
pending APIs and resume existing workers until the engine returns one
consolidated external recording requirement. Follow
[coordinator-rule-actions.md](coordinator-rule-actions.md) for the
capture/rule transition and [coordinator-recording.md](coordinator-recording.md)
for external evidence handoff.

## Completion Invariants

Keep worker handoff, work-item completion, and workflow completion distinct. A
worker handoff supplies a committed code version, local results, and required inputs; only integrated
acceptance can complete its API. Later integrated changes may
make that item `revalidation_pending`. Retain API delivery identities independently of the checkout. Accepted handoffs
release only their API leases; the slot/worktree can continue assigned work.
Keep the fixed pool and separate integration checkout through final delivery.

Local `.traffic-e2e/regression.yaml` uses `only` to select exact inventory routes
without an HTTP method, including every recorded method on each route. A pattern
is an exact inventory name. Omitted, null or empty `only` selects all recorded APIs.
`skip` takes precedence; excluded APIs are explicitly skipped and do not block
completion. This ignored file does not change code fingerprints or require a commit.
Preserve the user's selected scope; a terminal result covers that scope.

Optional `auto_next: true` lets one unscoped `next` continue successful Replay
only while the existing global scheduler selects another Replay. It defaults
to false. Returned next commands omit `--api`; execute them unchanged. Explicit
`--api` or source-route inputs select the entry API; pooled execution still
finishes the frozen group round before returning. Automatic continuation
preserves first-pass discovery, worker/expert actions, integration and review
priorities, scope and gates. Report arrived feedback immediately as before;
each Replay boundary re-evaluates it. Ordinary group-member failures continue to the remaining group APIs. Stale
Replay, execution errors and higher-priority non-Replay actions stop continuation. During execution, wait and independent
worker/expert actions expose actual `execution_mode: auto_next` or `single`.
Wait summaries also retain current Replay progress. Treat wait as observation,
without issuing an extra next.

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

Redis scalar ownership tokens use `redis.keys` with the generator's format,
for example `identity` with `{hex: 32}`. The engine shares complete Source/Target
correspondences across ordinary writes and later opaque EVAL/EVALSHA ARGV or
DELEX IFEQ references. Script bytes, numkeys, KEYS, TTL/options, lane order and
finite consumption remain strict. No lock-specific effect or planner exists.
