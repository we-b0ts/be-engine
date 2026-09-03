# Rewrite Coordinator Workflow

Read this core guide in every main-orchestrator session before advancing the
workflow. Load action-specific references only through the direct routing in
`SKILL.md`.

## Contents

- Session start and resume
- Coordinator phase order
- Core action handling
- API inventory and serialized traffic
- Integrated target quality
- Completion

## Session Start And Resume

Start or resume an initialized workflow from the canonical target repository:

```bash
backend-rewrite next
```

Before the first standard recording, add `--api '<METHOD path-or-pattern>'`
only when the caller explicitly requests a single-API recording. After the
coordinator publishes its stable inventory, select work with the exact
inventory method/pattern. If an action response was lost or the session is
resuming, recover it with scoped read-only `status`; never infer workflow state
from artifact recency.

At the start of every main-orchestrator session, read
`.traffic-e2e/local/block.md` when it exists. Project initialization may create
it with temporary reference evidence about source configuration, Vintage
access, startup/process activity, and local caches. The first rewrite session
after initialization must read that evidence completely. Remove each entry
after the rewrite has fully understood it, implemented the required behavior,
or proved it irrelevant; keep no resolved history and remove the file when it
is empty. When progress is proven blocked and the orchestrator is about to
stop, create or update the same file with useful resume context. Treat it as
AI-owned reference and handoff context, never as coordinator state;
`backend-rewrite status` remains authoritative.

## Coordinator Phase Order

The coordinator owns the executable phase order:

```text
record configured traffic -> stable API inventory + source process outputs
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

Repeatedly execute `backend-rewrite next` or the opaque command returned by the
current action. Wait only for:

- a returned standard-recording, focused Replay, or comparison operation;
- required caller input or a coordinator-owned mutation;
- a serialized traffic runtime owned by another API;
- worker handoffs after no pending API or process-output item can advance; or
- terminal completion.

## Core Action Handling

The stable action envelope has `kind`, `summary`, `details`, and `commands`.
Read kind-specific facts only from `details` and execute only command roles
present in `commands`; an empty command object never implies a fallback. Status
does not guarantee an unconditional top-level `next` command. Source-process
traffic is issue-scoped evidence, not coordinator state. When an
`implementation_required` action returns its evidence command, execute that
exact command only when startup, configured process-owned traffic, background
refresh, or local-cache behavior is relevant.

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
reconstruct selector inputs. For response-rule, recorder-capture, or
process-owned-dependency plans, first read
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

When `details.reason=verification_progress_commit_required`, every API is
verified but terminal delivery is still forbidden. Commit exactly the listed
coordinator-managed delivery files without editing or resetting the generated
`progress.yaml`, then execute `backend-rewrite next` again. The list includes
the dirty `.traffic-e2e/source-traffic-policy.yaml` or
`.traffic-e2e/verification.yaml` when applicable, alongside the final public
progress snapshot. Intermediate failed or passing attempts do not
require progress commits.

### `implementation_required`

Stop before evidence, artifact, source, or target analysis. Follow
[implementation-worker-coordination.md](implementation-worker-coordination.md)
to create or resume the work item's dedicated worker and confirm the dispatch.
An API worker receives its bounded evidence commands. A process-output worker
receives the comparison observation and acceptance command and fixes target
startup/code without inventing traffic operations. The assigned worker follows
[problem-diagnosis.md](problem-diagnosis.md), executes any returned opaque
evidence queries, proves one cause, runs local tests, and returns the unchanged
acceptance command. The main orchestrator integrates the tested handoff and
executes acceptance only from the canonical worktree.

After all API items have been traversed and their implementation workers have
been confirmed, execute each returned `next --process-output <id>` command.
Dispatch and confirm each process-output worker, then keep advancing other
eligible work instead of waiting. If a process-output repair changes target
content, completed APIs become stale; let the coordinator drain their final
revalidation before it performs the process-output comparison again.

If the worker returns source-proven response-rule, recorder-capture,
process-owned-rule, or process-output-rule inputs, read
[coordinator-evidence-actions.md](coordinator-evidence-actions.md) before the
main orchestrator performs the coordinator-owned mutation.

### `target_quality_required`

Execute only `action.commands.execute` in its absolute canonical `cwd`. The
only permitted command extension is one or more exact
`--hardcode-ai-verified` arguments after this built-in gate reports the matching
locations and the required source evidence has been committed. Never run this
gate in a worker worktree. A successful run records the integrated
target fingerprint and returns `advance_required`; execute that action to start
focused Replay. A later integration or quality-gate configuration change
creates a new fingerprint and another quality action. On failure, fix the
integrated target and recover the same action with scoped `status`.

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
main orchestrator proves that the same value is hardcoded in source code and
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
the coordinator-issued repair or recovery command. `wait_required` never
authorizes recovery.

### `recording_refresh_pending`

The scoped API is parked until one consolidated standard recording can replace
the baseline. Read [recording-lifecycle.md](recording-lifecycle.md), execute only
`commands.status` for the waiting API, and never execute its stale acceptance.
Continue other runnable work only through current coordinator-issued commands.

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
`total`, `completed`, `pending`, `implementation_required`,
`awaiting_recording_refresh`, `revalidation_pending`, `current_index`, and
`current_api`. The coordinator owns this inventory. Keep `workflow.scope`, the
selector of the shared standard recording, separate from the selected API. An
omitted selector produces `recorded_api_inventory`: every API that actually
publishes a case in the selected standard recording enters the inventory, while
an API with no observed traffic is not required and does not block completion.
The scope remains stable as selected workers change.

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

Keep worker handoff, work-item completion, and workflow completion distinct. A
worker handoff supplies a tested patch and coordinator inputs; only integrated
acceptance can complete its API or process output. Later integrated changes may
make that item `revalidation_pending`. Retain every work item's worker binding
and worktree until `terminal_allowed=true` and final delivery no longer needs
them.

An evidence-proven unavailable external response-driving value may be blocked
under [problem-diagnosis.md](problem-diagnosis.md). A blocker is not successful
completion and must never be reported as `terminal_allowed=true`.
