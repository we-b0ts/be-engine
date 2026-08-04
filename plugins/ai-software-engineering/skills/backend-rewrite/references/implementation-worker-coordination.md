# Implementation Worker Coordination

Use this guide once per orchestrator task: when initialized inventory first
reports `total > 1`, or before the first `implementation_required` action in a
single-API workflow. Worker dispatch is universal; inventory size changes only
what the orchestrator does after dispatch.

## Execution Model

The main Agent is a thin orchestrator. It owns the canonical coordinator
worktree, worker/worktree assignment, state-mutating coordinator commands,
integration, serialized traffic verification, shared refactoring, repository
checks, and the final `terminal_allowed` decision.

Each subagent owns one API's diagnosis-to-tested-change cycle:

- execute the assigned read-only evidence commands;
- inspect source and target code and prove one cause;
- implement the smallest compatible repair;
- run API-local unit and component tests; and
- return a reviewable handoff.

Keep recording, focused Replay, and comparison serial. They share one
`traffic_runtime` lease and run only under the orchestrator. Serialization
applies to one live traffic operation, not to an API's complete lifecycle.

## Mandatory Dispatch Gate

Treat every first `implementation_required` action, including the only API in
a workflow, as an immediate dispatch barrier. The orchestrator may read the
action envelope, but before it executes evidence, opens a case artifact,
inspects source or target code, or develops an API-level hypothesis, it must:

1. preserve the complete action, exact API, issue ID, canonical `cwd`, and
   command specs without executing the evidence commands;
2. create the API worker worktree from the current integrated target revision;
3. invoke the runtime's actual subagent-dispatch tool with that context and the
   required handoff; and
4. retain the returned worker handle and resume orchestrator scheduling.

`TaskCreate`, a TODO, task-status changes, or an announcement of future
dispatch does not satisfy this gate. If no real subagent capability is
available, report the blocker; do not silently fall back to main-Agent
diagnosis or implementation.

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
`--target-root`. A worker may therefore execute its assigned read-only status,
inventory, evidence, and case-dependency argv from its own worktree. It must
execute the argv exactly and must not remove or replace `--target-root`.

Only the orchestrator runs state-mutating transitions: `next` and acceptance,
recording, rule plan/apply, route or repair verification, recover, Replay, and
comparison. A worker returns source-proven proposed inputs for those transitions
and never invokes lower-level `traffic-e2e` operations.

## Post-Dispatch Scheduler

After a worker starts, inspect the current inventory instead of waiting for the
worker by default:

1. If the bounded summary has `pending > 0` and no action is `wait_required`,
   run the read-only `backend-rewrite inventory`, select an exact item whose
   `status=pending`, and execute
   `backend-rewrite next --api '<METHOD pattern>'`.
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

The worker's current subagent task is complete after local tests when it
returns:

- API and issue ID;
- proven root cause and supporting evidence;
- changed files and shared-module impact;
- patch or commit identity and test outcomes; and
- required coordinator transition inputs and unresolved risks.

The worker becomes idle after handoff and does not wait for Replay. Retain the
`API -> subagent -> worktree` binding until that API reaches coordinator
`complete` or ownership is explicitly transferred.

If serialized acceptance returns `implementation_required`, update that
worker's worktree from the integrated target revision and reactivate the same
subagent with the new action and attempt result. Replace it only when it is
unavailable, ownership becomes shared/system-scoped, or an independent
diagnosis is required. Never let two workers edit the same API concurrently.

After handoff, integrate the worker patch or commit into the coordinator
worktree, resolve conflicts, freeze the target revision, and execute that API's
coordinator-issued acceptance. Later integrations may change the target
fingerprint and requeue completed evidence; rerun affected acceptance instead
of preserving stale results. Release the binding and remove the worktree after
the API reaches `complete` and the worktree is no longer needed.
