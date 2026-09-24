# Coordinator Agent Protocol

Audience: the workflow coordinator. Read for dispatch, resume, worker status
checks, completion events, expert assistance, or binding recovery. The coordinator
executes the workflow mutations in this guide and delegates code operations.
Follow the main loop in
[coordinator.md](coordinator.md#coordinator-loop) throughout these operations.

## Role Language

In this protocol, **API implementer** means the dedicated `api-implementer`
bound to one API work item. The engine may still expose protocol names such as
`implementation worker`, `subagent`, `agent_handle`, or a legacy process-output
worker; those names do not create additional core roles.

The **code integrator** is one retained `code-integrator` task for the workflow
and is never stored or reported as an API-implementer binding. An **API expert** is a
read-only, engine-requested task whose findings are forwarded to the existing
API implementer. The **task runtime** supplies live task state; it is not the engine
and its observations advance workflow state only after the coordinator reports
them through the returned engine command.

## Persistent Assignment

Maintain one exact work item to one dedicated task runtime handle and one worktree:

```text
API method/pattern or process_output:<id> <-> worker handle <-> worker worktree
```

Issue IDs, attempts, and workflow revisions can change without changing this
binding. The engine persists the actual runtime handle and returns `agent_handle`
with its work scope in status and inventory. Match live runtime entries by that
handle; do not keep a separate binding/dispatch ID table. Supply the runtime's
addressable identifier, such as Codex's canonical `agent_name` when its tools
use that as the target; a display label is not an addressable handle. Retain any
additional session/task ID required by the runtime's own status query.
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
the original result and its review report so the engine can validate its turn.
Workers edit and test only their worktrees; they do not initialize a private rewrite workflow or
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
   with the actual `--agent-handle` or `BACKEND_REWRITE_SUBAGENT_HANDLE` and optional
   `BACKEND_REWRITE_SUBAGENT_NAME`. Register the assigned absolute worktree using
   `--worktree` or `BACKEND_REWRITE_WORKER_WORKTREE`; repeat this on resume so the
   engine freezes the new dispatch's base. Confirm accepted queued work as well; report
   `queued` when the task runtime exposes that state.
   If the canonical target is nested below its Git repository root, keep
   `--target-root` on that nested project. The registered worktree may be the
   outer Git worktree or its corresponding target-project child; the engine
   normalizes both forms to the child. The target and configured
   `delivery.managed_paths` are writable delivery scope; managed sibling paths
   are target-relative (for example `../backend-rs`). Do not modify other
   repository directories because review rejects tracked changes outside that
   scope.
4. Confirmation records the accepted binding only. Report `running` or `queued`
   explicitly using the owning action's `commands.report_worker` when that state
   is known, then continue with the returned global action. A confirmation with
   no activity report remains `worker_status_required` in `pending`.

Confirmation gates that work item's evidence and acceptance. It does not block
another work item's dispatch or feedback. Never perform API diagnosis in the
coordinator to bypass missing worker capability. Confirmation is delivery of a
dispatch, not proof that the worker remains running or has completed its work.

A later failed acceptance creates a new dispatch for the same worker. Replacing
an existing owner requires **either one of two equal authorization bases**:

- `user_approved`: the user explicitly authorized the transfer, including an
  earlier authorization that covers this replacement. Use
  `--approve-ownership-transfer`; do not ask again for an already authorized transfer.
- `runtime_api_confirmed_missing`: **actually invoke** a runtime API/tool or
  supported command covering the exact stored worker handle, and obtain a result
  establishing that the worker no longer exists and cannot be resumed. Supply
  `--runtime-query-command` and `--runtime-query-at` together. These parameters
  attest that the query actually ran and confirmed absence; no additional user
  approval or evidence file is required.

For the runtime basis, after the actual query and replacement creation:

```bash
backend-rewrite worker transfer --previous-agent-handle OLD --agent-handle NEW \
  --reason 'runtime query confirmed the original worker no longer exists' \
  --runtime-query-command 'ListAgents' \
  --runtime-query-at '<actual query time in RFC 3339, including timezone>'
```

`--runtime-query-command` identifies the API/tool or command actually invoked:
for example `ListAgents`, its supported `/list-agents` entrypoint, or another
runtime's live agent-list or per-task status API. Record the actual query time
(e.g. `2026-09-12T12:00:00+08:00`), not an invented timestamp. Follow
[mandatory runtime queries](#mandatory-runtime-queries) for query coverage.
Merely naming `/list-agents` does not execute a query. A new session, cached
engine state, an incomplete listing, a timeout, permission error, or other failed
query does not establish absence. An ended but resumable worker retains
ownership. If list scope cannot establish absence of the exact worker, obtain a
per-task result or explicit user approval. Explicit user cancellation still
takes precedence over automatic replacement.

After establishing either basis, preserve the worktree, create the replacement,
then execute `worker transfer` with a single-line `--reason` and exactly one
of the authorization alternatives. The engine checks the command and time
format, records the authorization, verifies the old handle still owns the work
and issues a new dispatch for the replacement. It trusts the coordinator's
attestation; it does not execute the submitted API/command or independently
prove the query ran. Never give two workers simultaneous ownership of one work item.

## API Expert Assistance

Dispatch an expert only when the engine returns `expert_required` with
`details.state=dispatch_required` after reservation. The coordinator must not
initiate expert assistance based on elapsed time, difficulty, or its own judgment.

The engine returns `expert_required` when exactly one API implementer is running and
more than two hours have elapsed since that API's last integrated code delivery
(or its first binding before any such delivery). Handle the returned action;
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

Use completion events from the task runtime as the normal notification path.
Events accelerate result handling; they do not replace the mandatory runtime
queries below.
Use the result's actual worker handle and original review report. The engine
resolves the binding and validates the report's workflow, scope and dispatch.
Never replace a stale result's report with a newer one. Execute the returned
`commands.report_worker`, or `worker report --agent-handle HANDLE --activity ACTIVITY`:

| Activity | Meaning |
| --- | --- |
| `queued` | Task runtime accepted the task and is waiting to run it. |
| `running` | The coordinator reports that this dispatch is running. |
| `idle` | The worker stopped without a usable handoff; resume is required. |
| `handoff_ready` | The coordinator received a reviewable handoff. |
| `integrated` | The identified handoff and required inputs are published with a current passing integration report. |
| `rework_required` | The identified handoff needs worker changes, such as an integration conflict or a failed quality gate. |

For `running`, `queued`, and `idle`, report a fresh runtime observation for the
current assignment. Never relabel a delayed completion as a current observation.
These activities do not accept a review report.

For `handoff_ready`, `integrated`, and `rework_required`, also supply the same stable
`BACKEND_REWRITE_WORKER_HANDOFF_ID`, normally the worker commit or another exact
handoff identity, and `--review-report` from the original delivery. For rework,
use the accepted worker report or that handoff's integration report. Each review
returns a separate file; one batch integration review may list several handoffs
in that same file. Retain its exact path. The engine rejects an integration
report without a matching received handoff. Duplicate handoff events do not create duplicate work. Stale
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
The report must pass the complete shared source, Replay-isolation, domain and
configured repository quality checks against current canonical inputs.

A usable handoff contains the original overview's workflow/recording,
work scope, issue, binding and dispatch identities, proven cause and
supporting evidence, commit/patch identity, changed files and shared-module
impact, local test results, the passing review's absolute `report_path` and any
spawn ownership evidence, necessary coordinator transition inputs, and any
remaining risks. After consuming any non-code result as above, a task ending
with no usable handoff for its still-current dispatch is `idle`. Reporting idle
issues a fresh dispatch identity for the same worker; reject late completion
from the superseded turn and follow the returned resume action.
After `backend-rewrite wait` returns `worker_events_required`, perform the
[mandatory runtime query pass](#mandatory-runtime-queries), reconcile ended
tasks and arrived events, and report actual changes before refreshing global
status. Keep the original review report and handoff identity.

The worker returns the handoff and ends its turn; it does not wait for Replay.
When the engine accepts that handoff and returns `integration_required`, switch
to [coordinator-integration.md](coordinator-integration.md). Do not extend this
agent-lifecycle protocol into candidate preparation or publication.

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
Once bound, further replacement uses the normal explicit-approval or
`runtime_api_confirmed_missing` transfer contract. Other APIs retain their own
first-binding permission.

The captured committed `pr_base` revision is the trusted review baseline. Old
source-review files must not trigger startup review. If the purpose makes no
source/configuration changes, complete after passing verification and publishing
progress without creating an integrator solely for a review receipt. New changes
require delegated integration review before verification; pending worker handoff
and finding admission keep their existing contract.

For `replay`, follow `next` into fresh verification of the selected recording.
For `record`, the engine requests new external live traffic, then proceeds through
publication/case preparation to Replay. It supersedes the old recording pin for
this workflow. Preserve local API selection and Comparison requirements. Do not
request an API implementer or expert before fresh verification needs one.
Actual live/stale engine operations retain their finish/recovery contract; they
are not task-runtime worker cleanup requirements.

## Mandatory Runtime Queries

At session start/resume with retained assignments, after interruption, on
`worker_status_required`, before waiting on outstanding agents, and after every
bounded engine or task-runtime wait, **actually invoke a runtime agent-list or
status tool**. Query all assigned workers still awaiting results in one pass,
including parked API and process-output workers. Also check retained integrator,
route-analysis, and expert tasks before waiting on them, without reporting their
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
- An actual query explicitly establishing that the stored worker no longer
  exists permits the `runtime_api_confirmed_missing` transfer described above.
  Record its actual API/command and query time; do not report absence as completion.

Collect the full pass before reporting changes or required observation refreshes
through the existing per-worker `report_worker` commands. Do not re-query the
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
