# Rewrite Coordinator Workflow

The coordinator owns the executable phase order:

```text
record configured traffic -> stable API inventory
           -> prepare current API -> focused E2E
           -> one active issue -> focused E2E
           -> comparison recording -> compare
           -> next pending API (same standard recording) -> ...
           -> all API slices complete

explicit new traffic / changed recording contract / changed source baseline
           -> fresh standard recording -> prepare -> focused E2E
```

The target AI repeatedly runs `backend-rewrite next`. It pauses only for:

- the exact standard or comparison recording command returned by the action;
- one source/target investigation and implementation issue;
- one evidence-backed rule decision;
- one controlled non-target-code route;
- one explicit fresh-standard-recording request when its preconditions hold;
- completion.

## Action Handling

Action schema v7 has one stable shape for every kind:

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
`next` command.

### `recording_required`

Execute the exact opaque `action.commands.execute` argv from its canonical
`cwd` with the named environment variables. The command starts a detached
coordinator worker and returns immediately. Poll the status command returned by
that execution; `recording_in_progress` exposes it as
`action.commands.status`. Run `action.commands.resume` only after
`resume_required`. The allocated recording identity is
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

### API inventory and `api_pending`

Every initialized action/status envelope includes a bounded `api_inventory`
summary: `total`, `completed`, `pending`, `current_index`, and `current_api`.
The coordinator owns the stable order for the shared standard recording; work
only on `current_api`. Use `backend-rewrite inventory` only when an explicit
scope audit or final delivery check needs the complete ordered list and its
per-API `pending`, `active`, or `complete` status. That read-only report does
not authorize selecting another item. After the current API passes focused E2E
and comparison, the coordinator marks it complete and returns
`resume_required` for the next pending API. Execute the returned `next`; it
prepares and runs that API from the same standard recording. If the current
pattern is dynamic and lacks a proven source registration route, the action is
`input_required`; provide only the requested `--source-route` when resuming.
`workflow.scope` is the selector of that shared standard recording, not the
active API. It is `all_configured_apis` when the selector was omitted and must
remain stable as `current_api` advances.

Per-API failure retries reuse the same cases for that API. A fresh standard
recording is still allowed only under the explicit conditions below and resets
evidence for the whole inventory because all slices share that baseline.

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

After a system repair, only the returned coordinator-issued
`backend-rewrite repair verify <repair-id>` action can advance the workflow. Successful
verification chooses whether fresh standard traffic or replaying the same cases
is required; the AI does not choose that transition itself.

### `implementation_required`

`action.details` contains one bounded issue, one representative when available,
and possible causes. `action.commands.evidence` contains the permitted evidence
queries, while `action.commands.acceptance` is the only acceptance transition.
Traffic facts come from those queries and immutable artifacts. `representatives` returns the
exact standard or comparison case directory and structured response difference;
inspect that case first and other artifact cases as needed. For dependency
evidence, execute its returned `dependencies_command`; the target summary then
returns an exact `detail_command` for each target, so only the selected target's
bounded exchanges need expansion. Each exchange preserves key/argument/response
association; response previews are capped and length annotated. Source inspection
supplies the final business attribution. Apply
[problem-diagnosis.md](problem-diagnosis.md), repair one proven cause, run local
target tests, then execute `action.commands.acceptance`.

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

### `system_repair_required`

This action exists only after `backend-rewrite route` accepts current evidence and a
source reference and required system change. The route snapshots a
coordinator-defined system/source revision and returns an opaque repair ID; the
AI never supplies an acceptance command. Apply the required repair, then execute
the exact `action.commands.acceptance` argv for
`repair verify <repair-id>`. `next` and `recording request` cannot bypass it.
Successful verification reruns the same cases for Replay or external-input
repairs, or allocates fresh standard recording for Recorder or source-baseline
changes.

### `complete`

All APIs represented by the inventory summary have current passing focused E2E
and comparison evidence. `terminal_allowed` is true only here. Use
`backend-rewrite inventory` if final delivery needs the full per-API list.
Repository-wide regression and delivery remain under the caller's rewrite
objective.

## State And Recovery

Coordinator state is stored under `.traffic-e2e/.ai-forbidden/`. A target
rewrite AI must never read, search, or list that directory. Use
`backend-rewrite status`, which reconstructs the current action without advancing state:
it returns the original `action.commands.execute` before recording execution,
an exact `action.commands.apply` for a pending plan,
`action.commands.status` while the detached worker is live, or
`action.commands.resume` only after a finalized recording manifest or target
change is ready for `backend-rewrite next`. A running
manifest whose owner exited returns `recovery_required`; recovery removes only
the matching managed run resources and allocates a replacement run. This makes
a lost action response recoverable without rebuilding argv or starting a
second worker. In `system_repair_required`, status also reconstructs the exact
coordinator-issued `action.commands.acceptance` for
`repair verify <repair-id>`. When an action reports `recovery_required`, execute
its exact `action.commands.recover` argv. Recovery rejects a live coordinator,
removes a stale lock, stops an orphaned focused target/Replay attempt or managed
recording, publishes interrupted state, and returns the next coordinator
command.

Traffic-e2e's internal runner publication may retain its own implementation
layout. Those internal paths are not a stable rewrite-interface contract. The
interface may expose immutable artifact paths such as a representative
`case_dir` when direct inspection is useful.

The target repository's `replay-progress.yaml` and
`comparison-progress.yaml` are a separate, versioned coordinator output. Do
not edit or roll them back manually. Preserve coordinator-generated changes,
including consecutive-success evidence, and commit them with the target change
they verify. Continue excluding ignored internal runtime state and traffic
artifacts from delivery.
