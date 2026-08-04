# Parallel API Coordination

Use this guide once per orchestrator task when an initialized `next` or
`status` first reports `api_inventory.total > 1`. `total` is the stable trigger;
do not reread the guide as APIs complete. If only one API remains later,
continue the same workflow without requiring another worker.

## Execution Model

Parallelize expensive AI work as soon as each API reaches
`implementation_required`:

- evidence and source-code analysis;
- root-cause diagnosis and implementation;
- API-local refactoring, unit tests, and focused component tests.

Keep recording, focused Replay, and comparison serial. They share one
`traffic_runtime` lease and run only from the coordinator worktree. A
`wait_required` action is backpressure from that lane: wait at least
`retry_after_seconds` and execute only its returned status command. Do not run
`recover` while the owner is live.

## Mandatory Dispatch Gate

Treat the first `implementation_required` action for an API as an immediate
dispatch barrier. The orchestrator may read the action envelope, but before it
runs an evidence command, opens a case artifact, inspects source or target code,
or develops an API-level hypothesis, it must:

1. preserve the complete action, API, issue ID, canonical `cwd`, and command
   specs;
2. create the API's worker worktree from the current integrated target
   revision;
3. invoke the runtime's actual subagent-dispatch tool with that context and the
   required handoff;
4. retain the returned worker handle and then select another pending API or do
   other orchestrator work.

Do not wait for two implementation issues before dispatching the first worker.
Creating a task-list item, changing task status, or announcing future dispatch
does not satisfy this gate. If no subagent-dispatch capability is available,
report the blocker; do not silently fall back to main-agent diagnosis or
implementation.

## Ownership And Worktrees

The main Agent is a thin orchestrator. It owns the coordinator worktree,
worker/worktree assignment, state-mutating coordinator commands, integration,
serialized traffic verification, shared or cross-API refactoring, repository
checks, and the final `terminal_allowed` decision. It must not perform or repeat
a worker's API-level diagnosis or implementation unless integration exposes a
shared conflict, invalidates the diagnosis, or proves the issue is
system-scoped.

Each subagent owns one API's diagnosis-to-tested-change cycle. It inspects the
assigned bounded evidence and source behavior, proves one cause, implements the
smallest compatible repair, runs local tests, and returns a reviewable handoff.
It does not select another API or declare the whole rewrite complete.

The orchestrator stores worker worktrees under
`<coordinator-root>/.traffic-e2e/local/rewrite-worktrees/<workflow-id>/<api-slug>`
using the coordinator's `workflow.id`, and gives each worker its absolute path.
Repository initialization ensures
`.gitignore` contains `/.traffic-e2e/local/`; never commit worktree contents.
Workers must not create, switch, reset, remove, or repurpose worktrees. They
also must not initialize a private coordinator: coordinator
state and locks are target-root scoped, so a coordinator in another worktree
would bypass the serialized traffic lane. Returned coordinator commands always
run from their exact canonical coordinator `cwd`.

Worker edits remain isolated until the orchestrator integrates them. Workers
must not edit or merge into the coordinator worktree concurrently.

## Assignment And Worker Lifecycle

Assign one API with its exact method/path pattern, worker-worktree path,
complete `implementation_required` action, opaque evidence commands, expected
module ownership when known, and required handoff. Do not ask the worker to
rediscover workflow state or enumerate other APIs.

The worker's current subagent task is complete when it returns, after local
tests:

- the API and issue ID;
- proven root cause and supporting evidence;
- changed files plus any shared-module impact;
- patch or commit identity and test outcomes;
- required coordinator transition inputs and unresolved risks.

After that handoff the worker becomes idle; it does not wait for Replay. The
orchestrator retains the `API -> subagent -> worktree` binding until that API
reaches coordinator `complete` or ownership is explicitly transferred.

If serialized Replay or comparison returns `implementation_required`, update
that worker's worktree from the integrated target revision and reactivate the
same subagent with the new action, evidence, and attempt result. Replace it only
when the original subagent is unavailable, the issue becomes
shared/system-scoped, or repeated attempts need an independent diagnosis. A
second agent may review read-only, but two workers must not edit the same API
concurrently.

After the API reaches `complete`, release its binding and remove the worker
worktree when it is no longer needed.

## Command Ownership And Integration

Workers may inspect source and run local tests in their worktrees. For
diagnosis they may run only exact read-only coordinator commands from the
returned canonical `cwd`, such as API-scoped status, inventory, evidence, and
case-dependency queries.

Only the orchestrator runs state-mutating coordinator transitions: `next` and
acceptance, recording, rule plan/apply, route or repair verification, recover,
Replay, and comparison. A worker returns evidence-backed proposed inputs when
one is needed and never invokes lower-level `traffic-e2e` operations.

After a worker handoff, the orchestrator integrates its patch or commit into
the coordinator worktree, resolves conflicts, freezes the target revision, and
then executes that API's coordinator-issued acceptance from that worktree.

The orchestrator may overlap the serialized lane with worker activity:

```text
Replay API A -> implementation_required -> worker A diagnoses and codes
Replay API B -> implementation_required -> worker B diagnoses and codes
integrate compatible changes -> freeze revision -> serialized acceptance
```

Resolve overlapping edits and shared design before integration. Later
integration may change the target fingerprint and requeue previously completed
API evidence; rerun the affected acceptance instead of preserving stale
results. Only coordinator `terminal_allowed=true` completes the rewrite.
