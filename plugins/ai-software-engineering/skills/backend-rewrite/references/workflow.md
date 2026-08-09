# Rewrite Coordinator Workflow

Read this core guide in every main-orchestrator session before advancing the
workflow. Load action-specific references only through the direct routing in
`SKILL.md`.

## Contents

- Coordinator phase order
- Core action handling
- API inventory and serialized traffic
- Integrated target quality
- Completion

## Coordinator Phase Order

The coordinator owns the executable phase order:

```text
record configured traffic -> stable API inventory
           -> serialize prepare/focused E2E for API A
           -> API A implementation issue (AI work may run in parallel)
           -> serialize focused E2E for API B
           -> API B implementation issue (AI work may run in parallel)
           -> serialize each Replay/comparison transition
           -> all API slices complete

explicit new traffic / changed recording contract / changed source baseline
           -> fresh standard recording -> prepare -> focused E2E

source-proven bypassed backend -> apply capture rule -> API waits
           -> drain other runnable API work -> one full-scope fresh recording
```

Repeatedly execute `backend-rewrite next` or the opaque command returned by the
current action. Wait only for:

- a returned standard-recording, focused Replay, or comparison operation;
- required caller input or a coordinator-owned mutation;
- a serialized traffic runtime owned by another API;
- worker handoffs after no pending API can advance; or
- terminal completion.

## Core Action Handling

The stable action envelope has `kind`, `summary`, `details`, and `commands`.
Read kind-specific facts only from `details` and execute only command roles
present in `commands`; an empty command object never implies a fallback. Status
does not guarantee an unconditional top-level `next` command. Treat top-level
`source_process_traffic` only as bounded startup, background-refresh, and
local-cache triage context, never as ownership or response-causality proof.

### `wait_required`

Recording, Replay, and comparison share one `traffic_runtime` lease. When
`details.reason=resource_busy`, use its requested API, blocking API, live
operation, and `retry_after_seconds`. Execute only `commands.status` after the
delay. A missing live operation means the blocking API has a non-preemptible
coordinator transition to finish. Do not run `recover`, repeat `next`, or start
a second traffic operation while the owner is live.

### `recording_required`

Read [recording-lifecycle.md](recording-lifecycle.md), execute its exact
recording action, and poll only the status command returned by that execution.
Do not reconstruct a recording command or discover its run by recency.

### `recording_in_progress`

Read [recording-lifecycle.md](recording-lifecycle.md) and execute only
`commands.status`. Do not start another executor or advance before the exact
finalized run becomes `advance_required`.

### `plan_apply_required`

Execute the exact unchanged `commands.apply` once; never rerun planning or
reconstruct selector inputs. For recorder-capture or background-dependency
plans, first read
[coordinator-evidence-actions.md](coordinator-evidence-actions.md). A response
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

When a selected dynamic API pattern lacks a proven source registration route,
provide only the requested `--source-route` through the returned command. Do
not infer additional input or change the shared recording scope.

### `implementation_required`

Stop before evidence, artifact, source, or target analysis. Follow
[implementation-worker-coordination.md](implementation-worker-coordination.md)
to create or resume the API's dedicated worker and confirm the dispatch. The
assigned worker follows [problem-diagnosis.md](problem-diagnosis.md), executes
the opaque evidence queries, proves one cause, runs local tests, and returns the
unchanged acceptance command. The main orchestrator integrates the tested
handoff and executes acceptance only from the canonical worktree.

If the worker returns source-proven recorder-capture or background-rule inputs,
read
[coordinator-evidence-actions.md](coordinator-evidence-actions.md) before the
main orchestrator performs the coordinator-owned mutation.

### `target_quality_required`

Execute only `action.commands.execute` in its absolute canonical `cwd`. Never
run this gate in a worker worktree. A successful run records the integrated
target fingerprint and returns `advance_required`; execute that action to start
focused Replay. A later integration or quality-gate configuration change
creates a new fingerprint and another quality action. On failure, fix the
integrated target and recover the same action with scoped `status`.

The gate list always starts with the built-in `replay-isolation` scan. Relative
to the configured `pr_base`, it checks every added or modified production Rust
file in the integrated worktree, including staged, unstaged, and untracked
files. It excludes comments, documentation, and test-only code, and rejects
direct dependencies on replay-only hostnames, fake-IP ranges, private runtime
paths, and recording artifacts. Repository quality-gate configuration may add
commands but cannot disable this scan; an explicit empty gate list still leaves
`replay-isolation` active.

### `system_repair_required` and `recovery_required`

Read
[recovery-and-system-repair.md](recovery-and-system-repair.md) and execute only
the coordinator-issued repair or recovery command. `wait_required` never
authorizes recovery.

### `recording_refresh_pending`

The scoped API is parked until one consolidated standard recording can replace
the baseline. Read [recording-lifecycle.md](recording-lifecycle.md), execute only
`commands.status` for the waiting API, and never execute its stale acceptance.
Continue other runnable work only through current coordinator-issued commands.

### `complete`

API-scoped `complete` means only that API has current passing focused E2E and
comparison evidence. Finish repository-wide verification and delivery only
when `terminal_allowed=true` proves every API is complete for the same target
content fingerprint. Use `backend-rewrite inventory` when delivery needs the
full per-API list.

## API Inventory And Serialized Traffic

Every initialized action or status includes a bounded `api_inventory` summary:
`total`, `completed`, `pending`, `implementation_required`,
`awaiting_recording_refresh`, `revalidation_pending`, `current_index`, and
`current_api`. The coordinator owns this inventory. Keep `workflow.scope`, the
selector of the shared standard recording, separate from the selected API. An
omitted selector produces `all_configured_apis` and remains stable as selected
workers change.

Every `implementation_required` action uses a worker. Inventory size controls
only whether the orchestrator advances another pending API after dispatch or
waits. The coordinator may park implementation issues while it serializes the
selected API's Replay or comparison. Expensive worker diagnosis, coding, and
tests may overlap; only one traffic operation may be live.

After worker confirmation, execute a returned `advance_required` immediately.
When the original confirmation response is lost, use scoped `status` to
reconstruct it. Wait for a worker only when no pending API can advance or the
coordinator returns `wait_required`.

Keep finalized standard cases immutable through ordinary repair attempts. A
failed focused attempt changes the target and reuses the same cases; it does
not authorize fresh traffic. Read
[recording-lifecycle.md](recording-lifecycle.md) before explicitly requesting a
new standard recording or handling a consolidated capture refresh.

If the target fingerprint changes during focused Replay, discard that result
and return the API to Replay. If later integration changes the fingerprint of a
completed API, move it to deferred `revalidation_pending`. Ordinary pending and
implementation work runs first; once it drains, verify every stale API against
one final content fingerprint. A commit with no effective content change does
not create a new validation epoch.

For a high-impact shared module, global configuration, or startup change, the
main orchestrator may request earlier verification for selected stale APIs:

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
pending APIs and resume existing workers until the coordinator returns one
consolidated full-scope recording action. Follow
[coordinator-evidence-actions.md](coordinator-evidence-actions.md) for the
capture/rule transition and [recording-lifecycle.md](recording-lifecycle.md)
for that recording.

## Completion Invariants

Keep worker handoff, API completion, and workflow completion distinct. A worker
handoff supplies a tested patch and coordinator inputs; only integrated
acceptance can complete the API. Later integrated changes may make that API
`revalidation_pending`. Retain each API's worker binding and worktree until
`terminal_allowed=true` and final delivery no longer needs them.

An evidence-proven unavailable external response-driving value may be blocked
under [problem-diagnosis.md](problem-diagnosis.md). A blocker is not successful
completion and must never be reported as `terminal_allowed=true`.
