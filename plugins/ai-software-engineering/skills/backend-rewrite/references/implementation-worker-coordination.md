# Implementation Worker Coordination

Use this guide once per orchestrator task: when initialized inventory first
reports `total > 1`, or before the first `implementation_required` action in a
single-API workflow. Worker dispatch is universal; inventory size changes only
what the orchestrator does after dispatch.

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
checks, and the final `terminal_allowed` decision.

Maintain this invariant for the complete workflow:

```text
one exact API <-> one dedicated subagent handle <-> one dedicated worktree
```

The API method/pattern, not its current issue ID, is the assignment identity.
Attempts, issue IDs, workflow revisions, Replay results, and comparison results
may change without changing that binding.

Each subagent owns one API's diagnosis-to-tested-change cycle:

- execute the assigned read-only evidence commands;
- inspect source and target code and prove one cause;
- implement the smallest compatible repair;
- run API-local unit and component tests; and
- return a reviewable handoff.

A handoff ends only the worker's current turn. It does not complete the API or
release the `API -> subagent -> worktree` binding.

Keep recording, focused Replay, and comparison serial. They share one
`traffic_runtime` lease and run only under the orchestrator. Serialization
applies to one live traffic operation, not to an API's complete lifecycle.

## Mandatory Dispatch Gate

Treat the first `implementation_required` action for an API, including the only
API in a workflow, as an immediate dispatch barrier. The orchestrator may read
the action envelope, but before it executes evidence, opens a case artifact,
inspects source or target code, or develops an API-level hypothesis, it must:

1. preserve the complete action, exact API, issue ID, canonical `cwd`, and
   command specs without executing the evidence commands;
2. create the API worker worktree from the current integrated target revision;
3. invoke the runtime's actual subagent-dispatch tool with that context and the
   required handoff;
4. capture the returned worker handle and optional display name;
5. execute the returned `commands.confirm_worker`, supplying
   `BACKEND_REWRITE_SUBAGENT_HANDLE` and optionally
   `BACKEND_REWRITE_SUBAGENT_NAME`; and
6. execute no later `next`, including same-API acceptance or cross-API
   scheduling, until confirmation returns either `worker.state=confirmed` or
   the exact post-confirmation `advance_required` action.

`TaskCreate`, a TODO, task-status changes, or an announcement of future
dispatch does not satisfy this gate. If no real subagent capability is
available, report the blocker; do not silently fall back to main-Agent
diagnosis or implementation.

For a later `implementation_required` on a bound API, do not dispatch another
subagent. Refresh the same worktree from the integrated revision and use the
runtime's resume/reactivate operation with the stored handle. A fresh Agent or
subagent invocation is a replacement even when given the prior prompt or
worktree; it loses the dedicated worker's accumulated context.
Confirm every reactivation with the same handle through the new action's
`commands.confirm_worker` before any later `next`.

## Worktrees And Commands

Use the absolute canonical coordinator `cwd` returned by the action as
`<coordinator-root>`. The orchestrator stores workers at:

```text
<coordinator-root>/.traffic-e2e/local/rewrite-worktrees/<workflow.id>/<api-slug>
```

Give the worker that absolute path. Repository initialization keeps
`/.traffic-e2e/local/` ignored; never commit worktree contents. Workers must not
create, switch, reset, remove, or repurpose worktrees and must not initialize a
private coordinator. Worker edits stay isolated until orchestrator integration.

Every returned coordinator argv includes the absolute canonical
`--target-root`. A worker may therefore execute its assigned evidence,
case-dependency, returned read-only help, and explicitly handed API-scoped
status argv from its own worktree. It must execute the argv exactly and must not
remove or replace `--target-root`. Inventory and unscoped status remain
orchestrator concerns.

Only the orchestrator runs state-mutating transitions: `next` and acceptance,
recording, rule plan/apply, route or repair verification, recover, Replay, and
comparison. A worker returns source-proven proposed inputs for those transitions
and never starts an unreturned coordinator operation.

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
5. Wait for worker handoffs only when no pending API can advance.

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
integrate compatible changes -> freeze revision -> serialized acceptance
```

## Assignment And Worker Lifecycle

Assign one API with its exact method/path pattern, absolute worktree path,
complete action, opaque evidence commands, expected module ownership when
known, and required handoff. Do not ask the worker to rediscover workflow state
or enumerate other APIs.

The worker handoff is ready after local tests when it returns:

- API and issue ID;
- proven root cause and supporting evidence;
- changed files and shared-module impact;
- patch or commit identity and test outcomes; and
- required coordinator transition inputs and unresolved risks.

The worker's current turn becomes idle after handoff and does not wait for
Replay. Retain the `API -> subagent -> worktree` binding through per-API
`complete` and until workflow `terminal_allowed=true`, unless ownership is
explicitly transferred.

If serialized acceptance returns `implementation_required`, update that
worker's worktree from the integrated target revision and resume the stored
subagent handle with the complete new action and raw attempt result. A changed
issue ID or a need for an independent diagnosis does not release the binding.
If the stored handle cannot be resumed, preserve the worktree and report a
capability blocker. Only explicit caller approval may transfer the API to a new
subagent. Never let two workers own or edit the same API concurrently.

After handoff, integrate the worker patch or commit into the coordinator
worktree, resolve conflicts, freeze the target revision, and execute that API's
coordinator-issued acceptance. Later integrations may change the target
fingerprint and requeue completed evidence; rerun affected acceptance instead
of preserving stale results. Release bindings and remove worker worktrees only
after workflow `terminal_allowed=true` and they are no longer needed for
delivery.
