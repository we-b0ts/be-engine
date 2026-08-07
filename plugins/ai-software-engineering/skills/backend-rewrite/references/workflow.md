# Rewrite Coordinator Workflow

## Contents

- Coordinator phase order
- Action handling
- API inventory and serialized traffic
- Fresh standard recording
- Implementation and repair actions
- State and recovery

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

The main orchestrator repeatedly executes `backend-rewrite next` or the opaque
command returned by the current action. It waits only for:

- a returned standard, focused Replay, or comparison operation;
- required caller input or a coordinator-owned mutation;
- a serialized traffic runtime owned by another API;
- worker handoffs after no pending API can advance; or
- terminal completion.

## Action Handling

The `action` object in response schema v10 has one stable shape for every kind:

```json
{
  "kind": "implementation_required",
  "summary": "...",
  "details": {},
  "commands": {}
}
```

`details` is the only location for kind-specific facts. `commands` is the only
location for executable argv, keyed by its role. An empty object means the
action has no command of that class; do not infer a fallback. `status` does not
duplicate the issue as `active_issue` or publish an unconditional top-level
`next` command. Response schema v10 is independent of target repository
configuration versions. It retains the mandatory implementation-worker
dispatch confirmation gate and adds recorder-capture refresh state.

### `wait_required`

Recording, Replay, and comparison share one `traffic_runtime` lease. When
another operation owns it, `details.reason=resource_busy` identifies the resource,
requested API, blocking API, live operation when one exists, and
`retry_after_seconds`. Execute only `commands.status` after that delay. A
missing live operation means another API has a non-preemptible coordinator
transition to finish; inspect the blocking API's returned status action. Do not
run `recover`, repeat `next`, or start a second traffic operation while the
owner is live.

### `recording_required`

Execute the exact opaque `action.commands.execute` argv with the named
environment variables. Returned argv already contains the canonical absolute
`--target-root`; `cwd` remains its safe execution default. The command starts a detached
recording executor and returns immediately. Poll the status command returned by
that execution; `recording_in_progress` exposes it as
`action.commands.status`. Run `action.commands.advance` only after
`advance_required`. The allocated recording identity is
`action.details.run_id`; the coordinator owns its recording input mode and
lifecycle, and validates that exact finalized manifest. Never discover a run by recency or add
manual curl, replay, shell pipelines, backgrounding, or driver flags. Duration and case limit
belong to the preceding recording request and are bound into the action ID.
When the action is scoped to explicit APIs, the duration is an upper bound and
the managed runtime may finalize after every selected API reaches its case
limit. An omitted API selector still waits for the complete duration to retain
low-frequency API discovery.
When the workflow was started without `--api`, an empty run-local selector is
intentional: recorder configuration limits traffic and the finalized cases
produce the stable API inventory. Do not add selectors to the returned action.

### `advance_required`

The prerequisite named in `summary` is already available and the coordinator
is ready to advance its state. Execute the exact `commands.advance` argv once.
This action never means rerun the previous recording, Replay, comparison, or
implementation command.

### API inventory and pending items

Every initialized action/status envelope includes a bounded `api_inventory`
summary: `total`, `completed`, `pending`, `implementation_required`,
`awaiting_recording_refresh`, `current_index`, and `current_api`. The coordinator
owns the stable inventory for the shared standard recording. The main
orchestrator reads
[implementation-worker-coordination.md](implementation-worker-coordination.md)
once when `total > 1`, or before the first implementation dispatch when
`total = 1`. Every `implementation_required` action uses a worker; inventory
size only controls whether the orchestrator advances another pending API or
waits after dispatch. The coordinator parks other implementation issues while
it serializes the selected API's Replay or comparison. If the selected pattern
is dynamic and lacks a proven source registration route, the action is
`input_required`; provide only the requested `--source-route` when resuming.
`workflow.scope` is the selector of that shared standard recording, not the
selected API. It is `all_configured_apis` when the selector was omitted and
must remain stable as workers change the selected API.

The assigned worker owns AI diagnosis, code edits, and local tests after every
API reaches `implementation_required`. The orchestrator dispatches before
executing evidence. Its first issue creates the dedicated subagent binding;
every later issue resumes that exact stored handle, even when the issue ID or
attempt changes. With multiple APIs, worker confirmation returns an
`advance_required` action with the exact next pending API command. The
orchestrator executes it instead of waiting; resumed `status` reconstructs the
same action when the confirmation response is lost. It waits for the worker
only when no pending API can advance or the coordinator returns
`wait_required`. An API's evidence and acceptance commands are opaque and
remain bound to that API. If the target fingerprint changes during a focused
Replay, that result is discarded and the API returns to Replay. If later edits
change the fingerprint after an API completed, its prior evidence is requeued
before whole-workflow completion.

Per-API failure retries reuse the same cases for that API. A fresh standard
recording is still allowed only under the explicit conditions below and resets
evidence for the whole inventory because all slices share that baseline.

`awaiting_recording_refresh` means the API has an applied, source-proven capture
rule but cannot be reverified against the old standard baseline. It is parked,
not complete or blocked. Continue pending APIs and resume existing
implementation workers; other APIs may still run comparison against the
current baseline. When no runnable inventory item remains, the coordinator
atomically changes to `recording_required` for one consolidated full-scope
refresh.

Applying or confirming a source-proven background dependency rule is not a
fresh-recording condition. The coordinator treats published capture artifacts
as immutable, recomputes only the effective case/global ownership view in the
latest focused replay report, rebuilds dependency evidence, and revises the
same attempt in the progress ledger. Clean effective evidence advances to
comparison; residual case-scoped dirty evidence stays in the repair loop. The
apply result therefore returns `next`, never a
`recorder-contract-changed` recording request.
On resume, `next` also repairs a finalized attempt whose derived dependency
view is already clean but whose persisted failure still contains the obsolete
strict dirty-finalize result. This recovery removes only dependency-derived
errors, preserves real lifecycle failures, and does not execute another E2E
attempt.

### Fresh standard recording

The ordinary repair loop keeps the finalized standard cases immutable. When a
focused E2E attempt fails, change the target for one proven cause and run
`next`; the coordinator reruns those same cases. After focused E2E passes, the
coordinator allocates fresh comparison evidence without replacing the standard
cases.

After the first focused attempt, every `next` and `status` result includes
`latest_focused_e2e`. `execution_mode=fresh_standard_cases` identifies the
first attempt against the current standard baseline, while
`execution_mode=reused_standard_cases` proves that the latest attempt reused
that baseline. The result also carries the recording run ID, exact case source,
case inventory ID when available, previous/current attempt numbers, and pass
status. It is a description of the latest completed focused attempt; if `next`
returns without a target change, it does not claim that a new attempt ran.

Use `backend-rewrite recording request --kind standard` only for an explicit caller
request, a changed Recorder contract, or a changed source baseline. Supply the
corresponding reason plus positive `--duration-seconds` and
`--per-api-case-limit`
values. Omit `--api` to replace any previous narrowed scope with every API
admitted by recorder configuration; provide it only for an explicitly
single-API recording. An identical pending request is idempotent; a different pending request
requires explicit `--replace-pending`. The coordinator preserves prior
artifacts, clears state derived from that baseline, allocates a new run, and
returns the exact `recording_required` action. Execute that action and resume
with `next`. Historical request input is reusable only when its complete
recording selector exactly equals the requested selector. Omitted API selectors
match only each other, and a single API matches only that exact single API.
Never split or merge recordings because boot and case evidence belong to one
recording lifecycle. When no exact atomic input exists,
`action.details.input_mode=external_live_traffic` opens a fresh recording
window and includes bounded recent candidate scopes and rejection counts in
`action.details.recording_input_diagnosis`. Treat that diagnosis as complete
and do not inspect internal state or invent traffic.

A recorder-capture apply is the exception owned entirely by the coordinator:
do not follow it with `recording request`. The apply result either returns the
next runnable API command or, when the epoch is drained, the exact consolidated
recording command. Multiple applied capture rules accumulate before that one
recording. The new finalized recording atomically replaces the shared baseline
and invalidates old Replay/comparison evidence; it does not create per-API
recording generations.

After a system repair, only the returned coordinator-issued
`backend-rewrite repair verify <repair-id>` action can advance the workflow. Successful
verification chooses whether fresh standard traffic or replaying the same cases
is required; the AI does not choose that transition itself.

### `implementation_required`

`action.details` contains one bounded issue, one representative when available,
possible causes, and the mandatory dedicated-worker gate defined in
[implementation-worker-coordination.md](implementation-worker-coordination.md).
Confirm `dispatch_required` or `resume_required` with the runtime handle before
any later `next`; a refused cross-API selection returns the same structured
confirmation action.
`action.commands.evidence` contains the worker's permitted evidence queries,
while `action.commands.acceptance` is the orchestrator's only acceptance
transition. Traffic facts come from those queries and immutable artifacts.
`representatives` returns the
exact standard or comparison case directory and structured response difference;
inspect that case first and other artifact cases as needed. For dependency
evidence, execute its returned `dependencies_command`; the target summary then
returns an exact `detail_command` for each target, so only the selected target's
bounded exchanges need expansion. Each exchange preserves key/argument/response
association; response previews are capped and length annotated. Source inspection
supplies the final business attribution. The worker applies
[problem-diagnosis.md](problem-diagnosis.md), repairs one proven cause, runs
local target tests, and returns the tested change plus unchanged acceptance
command. The orchestrator integrates it and executes acceptance from the
coordinator worktree.

The `representatives` evidence report advertises a `recorder_capture` planner
for response, dependency, and comparison issues. Use it only after the worker
proves that a response-driving hostname is absent from recorded dependencies
and source code shows that exact backend is consumed. Run:

```text
backend-rewrite recorder-capture plan \
  --evidence-id <returned-evidence-id> \
  --endpoint <source-proven-hostname[:port]> \
  --source-evidence '<single-line source file/symbol proof>'
```

The planner reverse-resolves the hostname through configured Breeze snapshots
and accepts only one canonical resource. A source-proven port can disambiguate
resources sharing one domain; otherwise shared or unknown domains and IP
literals are rejected. The AI never supplies a Breeze descriptor or resource
name.
Execute the exact returned apply argv. Apply is immediate, add-only, atomic,
and stale-safe. If serialized recording, Replay, or comparison is live, wait
and inspect `status` before retrying apply. Its
`recording_refresh_pending=true` report lists waiting APIs and returns either
another API's `next` command or the full recording action. A scoped waiting API
returns `recording_refresh_pending`; poll `status`, not its old acceptance.

For a dependency issue, the `dirty_clusters` evidence report may also contain
`applicable_rule_planners`. Each entry is limited to a supported protocol
actually present in the current clusters and returns a protocol-specific help
argv. The report also returns a `representative_dependencies_command` for the
selected dirty case when available. A background rule is process-scoped, not API-scoped: the coordinator
binds its plan to the active API evidence, case source, and source revision
internally. After `backend-rewrite dependency-rule apply <plan-id>`, execute the exact
`next` returned by the report. The apply result includes bounded
`evidence_reclassification` describing rule coverage, remaining dirty cases,
and the same focused result after reclassification.
Planning persists an evidence-validated preview. Its own workflow revision
change does not invalidate apply. If bounded coverage shows that the selector
is incomplete, rerun the same planner with the same evidence ID and corrected
selector inputs before apply; the newer preview atomically replaces the
pending one and recorder configuration remains unchanged until apply.
For Redis, select the command-specific planner. `get`, `scard`, and `hgetall`
accept only exact keys proven by the selected immutable evidence; do not
generalize them into prefix or wildcard selectors.
If planning returns `reused_existing=true`, an equivalent protocol selector is
already configured under `effective_name`. Execute the returned apply action;
it is a successful no-op config reuse that still refreshes current evidence,
not a duplicate rule. Status reconstructs that same plan-ID transition.

Background ownership and response causality are separate. A background rule
makes the matching asynchronous dependency process-scoped and case-independent;
it carries no response-state classification and does not implement destination
state. The target AI determines causality from source and response evidence. If
the dependency drives state, port the source-compatible initial load, refresh,
cache, fallback, and readiness behavior and prove it through focused cases.
Any `initial_load_timeout_ms` only bounds source recording observation.

The coordinator always evaluates gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Dirty dependencies cannot preempt a response mismatch. A repository change
after a comparison mismatch returns through focused E2E before another fresh
comparison recording.

Dependency cleanliness is evaluated per active case. The coordinator clusters
case-scoped unmatched, unsupported, unsafe, and unused-case events by protocol
and endpoint. Each compact cluster has a stable `cluster_id` and correlated
source pre-readiness count. The complete startup summary is available only from
`pre_readiness_traffic`; startup context, `unused_global`, and target activity
outside a case do not fail the case gate.

For a Response issue with available pre-readiness traffic, that query also
exposes the Redis bootstrap dependency planner. It accepts compact HGET/HMGET
numeric-key patterns plus exact fields, applies a replay-only overlay to the
immutable Global bootstrap evidence, and returns to the same focused cases.

### `system_repair_required`

This action exists only after `backend-rewrite route` accepts current evidence and a
source reference and required system change. The route snapshots a
coordinator-defined system/source revision and returns an opaque repair ID; the
AI never supplies an acceptance command. Apply the required repair, then execute
the exact `action.commands.acceptance` argv. New repairs use
`repair verify <repair-id>`. A legacy Response `external_data_blocker` that is
now expressible by bootstrap replay planning instead receives
`repair resume-replay-planning <repair-id>`; this migration does not require a
runtime-input revision change. `next` and `recording request` cannot bypass the
returned command.
Successful verification reruns the same cases for Replay or external-input
repairs, or allocates fresh standard recording for Recorder or source-baseline
changes.

Use `recorder_capability_gap` only when the recorder binary lacks a required
mechanism and the supported recorder-capture planner cannot express the fix.
A configured Breeze resource that was bypassed and therefore omitted from
evidence is an API-scoped recorder-capture refresh, not system repair.

### `complete`

For API-scoped status, this action may mean only that assigned API has current
passing focused E2E and comparison evidence; `terminal_allowed` remains false
while another inventory item is incomplete. `terminal_allowed=true` means all
APIs are complete for the same target revision. Use `backend-rewrite inventory`
if final delivery needs the full per-API list. Repository-wide regression and
delivery remain under the caller's rewrite objective.

## State And Recovery

Coordinator state is stored under `.traffic-e2e/local/ai-forbidden/`. A target
rewrite AI must never read, search, or list that directory. Use
`backend-rewrite status [--api '<METHOD pattern>']`, which reconstructs the
current or requested API action without advancing state:
it returns the original `action.commands.execute` before recording execution,
an exact `action.commands.apply` for a pending plan,
`action.commands.status` while the detached recording executor is live, or
`action.commands.advance` only after a finalized recording manifest or target
change is ready for `backend-rewrite next`. A running
manifest whose owner exited returns `recovery_required`; recovery removes only
the matching managed run resources and allocates a replacement run. This makes
a lost action response recoverable without rebuilding argv or starting a
second executor. In `system_repair_required`, status also reconstructs the exact
coordinator-issued `action.commands.acceptance` for
`repair verify <repair-id>`. When an action reports `recovery_required`, execute
its exact `action.commands.recover` argv. Recovery rejects a live coordinator,
removes a stale lock, stops an orphaned focused target/Replay attempt or managed
recording, publishes interrupted state, and returns the next coordinator
command.

`wait_required` is not recovery. It proves a live or non-preemptible owner is
blocking the requested transition and always supplies the status command the
AI should poll. Only `recovery_required` authorizes `recover`.

Internal runner publication may retain its own implementation layout. Those
internal paths are not a stable rewrite-interface contract. The interface may
expose immutable artifact paths such as a representative `case_dir` when direct
inspection is useful.

The target repository's `replay-progress.yaml` and
`comparison-progress.yaml` are a separate, versioned coordinator output. Do
not edit or roll them back manually. Preserve coordinator-generated changes,
including consecutive-success evidence, and commit them with the target change
they verify. Continue excluding ignored internal runtime state and traffic
artifacts from delivery.
