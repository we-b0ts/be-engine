# Coordinator Agent Protocol

Audience: the workflow coordinator. Read for dispatch, resume, worker status
checks, completion events, expert assistance, or binding recovery. The coordinator
executes the workflow mutations in this guide and delegates code operations.
Follow the main loop in
[coordinator.md](coordinator.md#coordinator-loop) throughout these operations.

## Role Language

In this protocol, **API implementer** means a fixed `api-implementer-N` slot
with a reusable worktree and runtime handle. It may retain several API tasks from
several groups, but develops at most one API at a time. Each API keeps its own
binding, dispatch, lease and review identity. Historical protocol names such as
`worker`, `subagent` and `agent_handle` do not create additional roles.

The **repository analyst** performs read-only static/dynamic source route analysis
and returns results to the coordinator. It has no implementation-worker binding
or implementation worktree and is never confirmed or reported as an API implementer.

The **code integrator** is one retained `code-integrator` task for the workflow
and is never stored or reported as an API-implementer binding. An **API expert** is a
read-only, engine-requested task whose findings are forwarded to the existing
API implementer. The **task runtime** supplies live task state; it is not the engine
and its observations advance workflow state only after the coordinator reports
them through the returned engine command.

## Persistent Assignment

For pooled workflows, read [fixed implementers](coordinator-implementers.md).
`inventory.implementers` is the authoritative slot, queue and group projection.
The default is 16 slots; the workflow captures `max_implementers` at creation.

```text
group -> fixed api-implementer-N slot -> actual runtime handle + fixed worktree
API -> original dispatch + lease generation + per-API handoff/review
```

An HTTP API includes every recorded method on its canonical route. Do not create
separate method implementers. Several APIs may share one handle; a plain handle
cannot select a pooled API observation. Match the engine's API/dispatch/lease
identities, never task names or directory contents. Supply the runtime's
addressable handle and retain any additional task ID required by its status API.

Use the returned absolute worktree, always under:

```text
<canonical-target-root>/.traffic-e2e/local/rewrite-worktrees/api-implementer-N
```

Do not add workflow prefixes or API slugs. Reuse its cache and preserve queued
or unhanded work. Retain a separate `integrator` checkout. Source analysis needs
no implementation checkout.

## Dispatch And Resume

For `implementer_dispatch_required`, delegate the returned same-group batch to
its fixed slot. Reuse its actual handle when present; create the runtime session
and checkout only when needed. Include the canonical target root, worktree,
Source locations, group context and original per-API identities. The implementer
reads its own scoped evidence before each API. Execute `commands.confirm` only
after runtime acceptance, including accepted queued work. Confirmation records
members as queued, not running.

Continue with the returned global action. Report real per-API activity through
`implementer report`, supplying slot, handle, API, original API dispatch and lease
generation. A slot may queue more batches from its other mapped groups while
working on one API. Handoffs release only the completed subset and do not make
remaining tasks idle. Follow [the exact CLI protocol](coordinator-implementers.md).

Restore current assignments from `inventory` after interruption. Resume the same
handle before replacing it. Proven runtime absence uses the slot-level
[`implementer replace-runtime`](coordinator-implementers.md#restore-a-missing-runtime)
command with an actual runtime query and timestamp. Reload all new dispatch/lease
identities after replacement. Do not infer completion from an ended runtime turn,
clear pending tasks or reset the tree to obtain an empty slot.

Legacy workflows without `inventory.implementers` retain their existing
`implementation_required` / `commands.confirm_worker` protocol. Their per-API
`worker confirm`, runtime observations and explicit `worker transfer` remain
compatibility interfaces, not the dispatch path for new pooled workflows.

## API Expert Assistance

Dispatch an expert only when the engine returns `expert_required` with
`details.state=dispatch_required` after reservation. The coordinator must not
initiate expert assistance based on elapsed time, difficulty, or its own judgment.

The engine returns `expert_required` when only one unfinished API remains in the
inventory, its implementer is running, and more than two hours have elapsed since
that API's last integrated code delivery (or its first binding before any such
delivery). HTTP methods on one route count as one API; every other API must be
complete or skipped, including APIs without worker bindings. An unconfirmed
reservation returns `not_due` without a dispatch command if another unfinished
API appears; already confirmed experts retain their report and cleanup lifecycle.
Handle the returned action;
the coordinator does not report timestamps, runtime duration, or calculate
eligibility. Empty handoffs and worker resumes do not reset this timer.

- For `details.state=prepare_required`, execute the exact `commands.prepare` to
  reserve the returned API. Do not spawn an expert yet.
- For `details.state=dispatch_required`, dispatch one `api-expert` for the
  API in `details.apis`, supplying the canonical root, each API's read-only worktree,
  evidence command, and source locations. Its role entrypoint is
  [api-expert.md](api-expert.md). Retain the task under `details.expert_id`;
  recover an existing submission before creating one after an interruption.
- Once the runtime accepts that task, including queuing, execute
  `commands.confirm_expert` with `BACKEND_REWRITE_EXPERT_HANDLE`. Continue the
  returned engine work while the expert runs. Never register or report its
  handle as an API implementer.
- Query the retained expert in the normal runtime pass. When it ends, forward
  each unfinished API's findings to its retained implementer with evidence/revision identity.
  For an unresolved, failed, or interrupted investigation, forward the available
  evidence and failure/missing-input result for each unfinished report as well.
  Then execute each `inventory.experts[].apis[].commands.report_delivered` with
  the expert handle, stable per-API report ID, and actual recipient handle.
  Retain report and task identities until acknowledgement succeeds.
- If the API passes first, follow `expert_required` with
  `details.state=close_required`. Query the retained task, stop it if running or
  queued, and confirm it has ended before executing `commands.close_expert`.
  If the reservation never spawned a task, close it directly. Recover and confirm
  an already accepted but unconfirmed task before closing; never create one to
  close it. Retain late reports as reference without forwarding them as new work.
  API success stands; closure releases the expert slot and preserves one-time
  coverage. The engine requests this cleanup before final workflow delivery.
- The engine permits only one active expert task. Another eligible API waits
  until the current report is forwarded and acknowledged, or closure is acknowledged.
  Each API is covered once per workflow, across retries, revalidation, transfers,
  and resumes. Recover the accepted task on failure; do not create a replacement
  expert. Expert reports do not satisfy implementation or verification gates.

## Runtime Events And Handoffs

Use completion events as the normal notification path, together with the
mandatory live query passes below. Preserve original results and review paths;
never relabel an old completion with the current API's dispatch or lease.

Pooled running/queued/idle observations use `implementer report` with explicit
API/dispatch/lease identity. A completed subset uses `implementer handoff --slot
N --agent-handle HANDLE --deliveries FILE`, whose JSON entries bind each API,
dispatch, lease generation, unique handoff ID and original passing review report.
This submission may cross assigned groups. See
[fixed implementers](coordinator-implementers.md#runtime-activity-and-partial-handoff).

| Activity or transition | Meaning |
| --- | --- |
| `queued` | This API was accepted and is waiting in the slot queue. |
| `running` | The runtime is developing this API; a slot can have only one. |
| `idle` | This API stopped without an accepted handoff and requires recovery/resume. |
| Batch handoff | Reviewable completed API subset; all unlisted tasks remain assigned. |
| `integrated` | The identified handoff and required inputs were published with matching integration proof. |
| `rework_required` | That handoff needs implementer changes; the integrator retains routine formatting/lint repair. |

Integration and rework retain `worker report` with the original handle, unique
handoff ID and original review report. Those exact delivery identities identify
one API even when the handle owns many. Do not use handle-only `worker report`
for pooled runtime observations or use it instead of batch handoff.

For rule, route, capture or startup-only results, apply the supported transition
with the original evidence identity before reporting idle when permitted. A new
idle dispatch can invalidate old planner preconditions. If the API no longer
needs implementation but its slot still retains a lease, report idle using that
lease to release it. Never relabel old results with a newly issued dispatch.

Every usable code delivery requires a current passing per-API `review check`
report. Retain workflow/recording, API/group, issue, binding, dispatch and lease;
proven cause, Source evidence, changed files/shared impact, exact commit, focused
test results, original absolute report path, required inputs and remaining risks.
The engine freezes accepted commits and reports before reusing the checkout.
Implementers need no mandatory Clippy run; the integrator executes the configured
quality_check and reports success at the existing final pre-revalidation stage. See [review](coordinator-review.md).

After a handoff, keep unlisted tasks queued/running according to real activity.
After a bounded wait returns `worker_events_required`, query all outstanding
runtime handles, reconcile each result and task identity, report changes, then
refresh global status. A handoff is neither Replay success nor whole-slot idle.
When integration is selected, follow
[coordinator integration](coordinator-integration.md).

## Authorized Regression Start

On `pr_base`, `status` returns `purpose_required`. Handle it before querying,
resuming or reconciling old workers/experts. This applies on every return to base,
regardless of code changes, earlier purpose approval or unfinished old work.

Execute the returned purpose confirmation command matching the user's explicit
request. If the user has not specified a purpose, ask them to choose. Branch
presence or previous approval does not authorize either command. First actually
query your runtime API/command (for example `ListAgents` or `/list-agents`) for
active child agents/sessions of your current coordinator session. Count only
those actual active child sessions: exclude yourself, unrelated independent
sessions, engine binding records and historical sessions. The result must be
zero. A new session or empty engine inventory is not evidence of zero. If the
query cannot establish this scope, do not claim zero. If nonzero, report the
conflict; do not stop sessions automatically.

Supply the observed count, actual query API/command and RFC 3339 query time via
the returned command's required environment names:
`BACKEND_REWRITE_SESSION_ACTIVE_AGENT_COUNT`,
`BACKEND_REWRITE_SESSION_QUERY_COMMAND`, `BACKEND_REWRITE_SESSION_QUERY_AT`.
Equivalent flags are `--active-agent-count`, `--runtime-query-command` and
`--runtime-query-at`. No JSON evidence file is needed. These are your declaration
of an actual query; the engine cannot inspect your runtime itself. With these
values supplied, execute the matching command:

```bash
backend-rewrite purpose confirm --purpose replay --user-approved
backend-rewrite purpose confirm --purpose record --user-approved
```

Do not supply a branch name or create the branch yourself. The engine creates and
switches to `replay/yyyyMMdd-<seq>` or `record/yyyyMMdd-<seq>` (local date,
sequence starting at 1), returns its name, and initializes an isolated
workflow. No separate regression-start command is needed. This transition consumes
the purpose permission; ordinary `status` / `next` then proceed on the work branch.
Returning to `pr_base` always requires a new purpose confirmation.

Do not query, stop, wait for, transfer or restore old workers as a prerequisite to
this entry. Old bindings, failures, review receipts and expert clocks are archived;
old reports must not be forwarded into the new workflow. They may describe code
already fixed externally. Only current verification failures can produce new
implementation assignments or expert assistance. Each API receives permission
for one new worker binding under the new purpose; consume it on that API's first
binding when needed. No additional approval or old-worker query is required.
Reuse the workflow’s fixed slots for later batches; a new API does not create
another worktree. Restore active leases through their owning slot. Legacy
workflows retain the explicit-approval or `runtime_api_confirmed_missing` transfer
contract for replacement of their per-API owner.

The captured committed `pr_base` revision is the trusted review baseline. Old
source-review files must not trigger startup review. If the purpose makes no
source/configuration changes, complete after passing verification and publishing
progress without creating an integrator solely for a review receipt. New changes
require delegated integration review before verification; pending worker handoff
and finding admission keep their existing contract.

For `replay`, follow `next` into fresh verification of the selected recording.
For `record`, the engine requests new external live traffic, then proceeds through
publication/case preparation to Replay. It supersedes the old recording pin for
this workflow. Preserve local API selection. Do not
request an API implementer or expert before fresh verification needs one.
Actual live/stale engine operations retain their finish/recovery contract; they
are not task-runtime worker cleanup requirements.

## Mandatory Runtime Queries

At session start/resume with retained assignments, after interruption, on
`worker_status_required`, before waiting on outstanding agents, and after every
bounded engine or task-runtime wait, **actually invoke a runtime agent-list or
status tool**. Query all slot handles still awaiting results in one pass, then reconcile every
assigned API; several APIs sharing a handle need only one runtime query. Include
parked APIs in that coverage. Also check retained integrator,
repository-analyst, and expert tasks before waiting on them, without reporting their
handles as API implementers. A pass just completed after a wait can serve the
immediately following wait; repeat after intervening work or assignment changes.

- In Claude Code, **invoke the built-in `ListAgents` tool (`/list-agents`)**
  for every required pass when it is available. Other runtimes use their
  equivalent live agent-list/status API. Do not merely mention the command or
  execute slash-command text through a shell. See the
  [Claude Code listing contract](https://code.claude.com/docs/en/cross-session-messaging#see-which-sessions-claude-can-reach).
- Match returned entries to the engine's `agent_handle` and work scope, using
  additional runtime task IDs where required; exclude unrelated peer sessions from worker coverage. A matching
  total count, an agent definition catalog, or a business `TaskList` is not
  worker coverage. `claude agents --json --all` lists independent sessions,
  so it cannot substitute for querying in-session subagents.
- If a listing omits an assigned worker or does not expose its activity, invoke
  the runtime's per-task status query unless a matching result already resolves
  that dispatch. Disappearance alone does not prove completion. If no bulk query
  exists, issue independent per-task queries together before reporting. Claude Code's
  `TaskOutput` with `block: false` is a fallback where available; use the returned
  task status, not the retrieval status. It is deprecated in current releases.
- Retain the actual query call/result reference and the matched per-worker
  states in the coordinator's assignment context. Never claim a query occurred
  without a tool invocation and returned result. Cached engine observations,
  confirmation, worker messages, hooks, and absence of stop events do not
  substitute for this pass, even while a running observation is unexpired.
- An omitted, unreadable, or failed query is unknown, not running or idle.
  Resolve it through an available equivalent query. If no query capability can
  establish the state, identify the runtime interface gap; do not repeatedly
  wait as though the worker were known to be running or create a duplicate.
- An actual query establishing that the stored handle no longer exists permits
  pooled `implementer replace-runtime` (or legacy `runtime_api_confirmed_missing`
  transfer). Record its actual API/command and query time; do not report absence
  as completion.

Collect the full pass before reporting changes or required observation refreshes
through the returned pooled `implementer report` commands, retaining each API’s
original dispatch and lease (legacy flows use `report_worker`). Do not re-query the
whole set between those reports or refresh every unchanged running observation
on every wait. For an ended task, consume its result and required inputs before
deciding between `handoff_ready` and `idle`, as described above. Respect explicit
user cancellation; a stopped state alone does not authorize undoing it.

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
The sixty-minute expiry is an engine fallback, not permission to skip the runtime
queries required on every wait cycle.
