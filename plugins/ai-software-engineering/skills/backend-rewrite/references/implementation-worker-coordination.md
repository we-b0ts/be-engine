# Implementation Worker Coordination

Use this guide before the first `implementation_required` action for any API or
process-output work item, and again whenever dispatch, resume, transfer,
integration, or cleanup is required. Worker dispatch is universal; inventory
size changes only what the orchestrator does after dispatch.

## Contents

- Execution model
- Mandatory dispatch gate
- Worktrees and commands
- Post-dispatch scheduler
- Assignment and worker lifecycle

## Execution Model

The main Agent is a thin orchestrator. It owns the canonical coordinator
worktree, worker/worktree assignment, state-mutating coordinator commands,
integration, serialized traffic verification, shared refactoring, repository
checks, and final delivery. The coordinator computes `terminal_allowed`; the
main Agent finishes delivery only when the coordinator returns `true`.

Maintain this invariant for the complete workflow:

```text
one exact work item <-> one dedicated subagent handle <-> one dedicated worktree
```

The assignment identity is either the exact API method/pattern or
`process_output:<id>`, matching `action.details.work_scope`. The issue ID is not
the identity. Attempts, issue IDs, workflow revisions, Replay results, and
comparison results may change without changing that binding.

Each subagent owns one work item's diagnosis-to-tested-change cycle:

- for an API, execute only its assigned read-only evidence commands;
- for a process output, start from its returned `comparison_observation` and
  target startup/output path; an empty evidence-command list is expected;
- inspect source and target code and prove one cause;
- implement the smallest compatible repair;
- run work-item-local unit and component tests; and
- return a reviewable handoff.

A handoff ends only the worker's current turn. It does not complete the work
item or release its worker binding.

Keep recording, focused Replay, and comparison serial. They share one
`traffic_runtime` lease and run only under the orchestrator. Serialization
applies to one live traffic operation, not to a work item's complete lifecycle.

## Mandatory Dispatch Gate

Treat the first `implementation_required` action for every work item, including
the only API in a workflow or a process output, as an immediate dispatch
barrier. The orchestrator may read the action envelope, but before it executes
evidence, opens a case artifact, inspects source or target code, or develops a
work-item hypothesis, it must:

1. preserve the complete action, exact `work_scope`, issue ID, canonical `cwd`,
   and command specs without executing the evidence commands;
2. create the work-item worker worktree from the current integrated target
   revision;
3. invoke the runtime's actual subagent-dispatch tool with that context and the
   required handoff;
4. capture the returned worker handle and optional display name;
5. execute the returned `commands.confirm_worker`, supplying
   `BACKEND_REWRITE_SUBAGENT_HANDLE` and optionally
   `BACKEND_REWRITE_SUBAGENT_NAME`; and
6. execute no later `next`, including same-item acceptance or cross-item
   scheduling, until confirmation returns either `worker.state=confirmed` or
   the exact post-confirmation `advance_required` action.

`TaskCreate`, a TODO, task-status changes, or an announcement of future
dispatch does not satisfy this gate. If no real subagent capability is
available, report the blocker; do not silently fall back to main-Agent
diagnosis or implementation.

The coordinator enforces this barrier at the work-item diagnostic boundary.
Evidence queries and repair routing for a work item are rejected until the
main Agent confirms its worker's current dispatch.
API response/dependency/recorder-capture planning follows the opaque evidence
identity to its owning API rather than using whichever API is currently active.

For a later `implementation_required` on a bound work item, do not dispatch
another subagent. Refresh the same worktree from the integrated revision and
use the runtime's resume/reactivate operation with the stored handle. A fresh
Agent or subagent invocation is a replacement even when given the prior prompt
or worktree; it loses the dedicated worker's accumulated context.
Confirm every reactivation with the same handle through the new action's
`commands.confirm_worker` before any later `next`.

## Worktrees And Commands

Use the absolute canonical coordinator `cwd` returned by the action as
`<coordinator-root>`. The orchestrator stores workers at:

```text
<coordinator-root>/.traffic-e2e/local/rewrite-worktrees/<workflow.id>/<work-item-slug>
```

Use a deterministic filesystem-safe slug prefixed with `api-` or
`process-output-` so the two work-scope namespaces cannot collide. Give the
worker that absolute path. Repository initialization keeps
`/.traffic-e2e/local/` ignored; never commit worktree contents. Workers must not
create, switch, reset, remove, or repurpose worktrees and must not initialize a
private coordinator. Worker edits stay isolated until orchestrator integration.

Every returned coordinator command includes a canonical `cwd` and an absolute
`--target-root`. An API worker may execute its assigned evidence,
case-dependency, returned read-only help, and explicitly handed API-scoped
status commands. A process-output worker executes only read-only commands
present in its handoff; normally it receives no evidence commands.
Run each command in its supplied `cwd`, since artifact arguments may be
relative to that directory. Execute argv exactly and never remove or replace
`--target-root`. Source inspection, edits, and local tests stay in the worker's
own worktree. Inventory and unscoped status remain orchestrator concerns.

Only the orchestrator runs state-mutating transitions: `next` and acceptance,
recording, rule plan/apply, route or repair verification, recover, Replay, and
comparison. A worker returns source-proven proposed inputs for those transitions
and never starts an unreturned coordinator operation.

The canonical `.traffic-e2e/local/target.env` is also orchestrator-owned shared
runtime state. When implementation proves that target logic needs an
application-owned environment variable, the worker follows
[startup.md](startup.md) and returns a `startup_environment` input with its
exact name, effective value, and source evidence. It must not write a separate
`target.env` in its worktree. The orchestrator applies the input to the
canonical target root before integrated quality and acceptance.

## Post-Dispatch Scheduler

After a worker starts, inspect the current inventory instead of waiting for the
worker by default:

1. If confirmation or resumed `status` returns `advance_required`, execute its
   exact `commands.advance` argv before waiting. The coordinator selects a
   bounded pending item and reconstructs this action if the original response
   is lost.
2. Run only the returned serialized Replay/comparison transition and wait for
   that operation when its action requires polling.
3. If the selected API reaches `implementation_required`, dispatch its worker
   immediately and repeat from step 1.
4. If the coordinator returns `wait_required`, wait at least
   `retry_after_seconds` and execute only its returned status argv.
5. After every API work item has been traversed, dispatch returned
   process-output work items before waiting.
6. Wait for worker handoffs only when no pending API or process-output item can
   advance.

Do not call `TaskOutput`, join, or another worker-wait mechanism immediately
after dispatch while a pending inventory item can advance. Do not run an
unscoped `backend-rewrite next` and interpret the already selected API's action
as proof that other pending APIs are blocked.

For a single-API inventory, dispatch remains mandatory; with no other pending
API, the orchestrator may wait for that worker. For multiple APIs, expensive AI
work overlaps while traffic operations remain serial:

```text
Replay API A -> implementation_required -> worker A diagnoses and codes
Replay API B -> implementation_required -> worker B diagnoses and codes
process output -> implementation_required -> process worker diagnoses and codes
batch compatible changes -> freeze content fingerprint -> serialized acceptance
```

## Assignment And Worker Lifecycle

Assign one work item with its exact API method/path pattern or process-output
ID, absolute worktree path, complete action, opaque evidence commands when
present, expected module ownership when known, and required handoff. Do not ask
the worker to rediscover workflow state or enumerate other work items.

The worker handoff is ready after local tests when it returns:

- exact `work_scope` and issue ID;
- proven root cause and supporting evidence;
- changed files and shared-module impact;
- patch or commit identity and test outcomes; and
- required coordinator transition inputs, including every source-proven
  `startup_environment` input, the unchanged acceptance command, and unresolved
  risks.

The worker's current turn becomes idle after handoff and does not wait for
Replay or process-output comparison. Retain the
`work item -> subagent -> worktree` binding through item `complete` and until
workflow `terminal_allowed=true`, unless ownership is explicitly transferred.

If serialized acceptance returns `implementation_required`, update that
worker's worktree from the integrated target revision and resume the stored
subagent handle with the complete new action and raw attempt result. A changed
issue ID or a need for an independent diagnosis does not release the binding.
If the stored handle cannot be resumed, preserve the worktree and request
explicit caller approval. After approval, create one replacement subagent with
the same worktree and complete current action, then execute
`backend-rewrite worker transfer <binding-id>` with its runtime handle, a
single-line `--reason`, and `--approve-ownership-transfer`. The binding ID must
come from current scoped status; stale IDs and handles already bound to another
work item are rejected.
A successful transfer atomically confirms the current dispatch. Never let two
workers own or edit the same work item concurrently.

After handoff, integrate the worker patch or commit into the coordinator
worktree, resolve conflicts, batch compatible handoffs, freeze the target
content fingerprint, and execute that work item's coordinator-issued
acceptance. Follow every returned action unchanged. If it returns
`target_quality_required`, execute its exact command only in the absolute
canonical worktree named by the action, then execute the returned
`advance_required`. Worker-local tests do not satisfy this integrated-revision
gate. Later integrations can make completed APIs or process outputs stale;
after ordinary work drains, the coordinator automatically verifies them
against the final fingerprint. When an API handoff's shared-module impact is
high, the orchestrator may first run
`backend-rewrite verification request --api ... --reason ...` for selected
stale APIs and execute its returned advance command. This optional early check
does not replace final coverage. Release bindings and remove worker worktrees
only after workflow `terminal_allowed=true` and they are no longer needed for
delivery.
