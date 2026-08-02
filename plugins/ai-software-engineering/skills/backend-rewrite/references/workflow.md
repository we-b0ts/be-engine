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

The target AI repeatedly runs `traffic-e2e rewrite next`. It pauses only for:

- the exact standard or comparison recording command returned by the action;
- one source/target investigation and implementation issue;
- one evidence-backed rule decision;
- one controlled non-target-code route;
- one explicit fresh-standard-recording request when its preconditions hold;
- completion.

## Action Handling

### `recording_required`

Execute the exact opaque `rewrite recording execute <action-id>` argv from its
canonical `cwd` with the named environment variables, then run `next`. The
coordinator preallocates the run ID, owns the real-traffic request driver, and
validates that exact finalized manifest. Never discover a run by recency or add
manual curl, replay, backgrounding, or driver flags. Duration and case limit
belong to the preceding recording request and are bound into the action ID.
When the workflow was started without `--api`, an empty run-local selector is
intentional: recorder configuration limits traffic and the finalized cases
produce the stable API inventory. Do not add selectors to the returned action.

### API inventory and `api_pending`

Every initialized action/status envelope includes `api_inventory`. Its order
is coordinator-owned and stable for the shared standard recording. Work only
on `current_api`. After that API passes focused E2E and comparison, the
coordinator marks it complete and returns `resume_required` for the next
pending API. Execute the returned `next`; it prepares and runs that API from
the same standard recording. If the current pattern is dynamic and lacks a
proven source registration route, the action is `input_required`; provide only
the requested `--source-route` when resuming.

Per-API failure retries reuse the same cases for that API. A fresh standard
recording is still allowed only under the explicit conditions below and resets
evidence for the whole inventory because all slices share that baseline.

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

Use `rewrite recording request --kind standard` only for an explicit caller
request, a changed Recorder contract, or a changed source baseline. Supply the
corresponding reason plus positive `--duration-seconds` and
`--per-api-case-limit`
values. An identical pending request is idempotent; a different pending request
requires explicit `--replace-pending`. The coordinator preserves prior
artifacts, clears state derived from that baseline, allocates a new run, and
returns the exact `recording_required` action. Execute that action and resume
with `next`. If no finalized real-traffic request corpus is available, retain
the `input_required` state and request that external input rather than inventing
traffic.

After a system repair, only the returned coordinator-issued
`rewrite repair verify <repair-id>` action can advance the workflow. Successful
verification chooses whether fresh standard traffic or replaying the same cases
is required; the AI does not choose that transition itself.

### `implementation_required`

The action contains one bounded issue, one representative when available,
possible causes, evidence query IDs, and the acceptance command. Traffic facts
come from those queries and immutable artifacts. `representatives` returns the
exact standard or comparison case directory and structured response difference;
inspect that case first and other artifact cases as needed. Source inspection
supplies the final business attribution. Apply
[problem-diagnosis.md](problem-diagnosis.md), repair one proven cause, run local
target tests, then execute the acceptance command.

For a dependency issue, the `dirty_clusters` evidence report may also contain
`applicable_rule_planners`. Each entry is limited to a supported protocol
actually present in the current clusters and returns a protocol-specific help
argv. A background rule is process-scoped, not API-scoped: the coordinator
binds its plan to the active API evidence, case source, and source revision
internally. After `rewrite dependency-rule apply <plan-id>`, execute the exact
fresh-standard-recording request returned by the report.
If planning returns `reused_existing=true`, an equivalent protocol selector is
already configured under `effective_name`. Skip apply and execute the returned
fresh-recording request directly. Status reconstructs that same transition;
calling apply anyway is a successful no-op reuse rather than a duplicate rule.

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

This action exists only after `rewrite route` accepts current evidence and a
source reference and required system change. The route snapshots a
coordinator-defined system/source revision and returns an opaque repair ID; the
AI never supplies an acceptance command. Apply the required repair, then execute
the exact `repair verify <repair-id>` action. `next` and `recording request`
cannot bypass it. Successful verification reruns the same cases for Replay or
external-input repairs, or allocates fresh standard recording for Recorder or
source-baseline changes.

### `complete`

Every API in `api_inventory` has current passing focused E2E and comparison
evidence. `terminal_allowed` is true only here. Repository-wide regression and
delivery remain under the caller's rewrite objective.

## State And Recovery

Coordinator state is one atomically replaced file under the ignored local
root. Prefer `rewrite status` to reading this noisy internal representation and
never edit it. Status reconstructs the current action without advancing state:
it returns the original recording action while no result exists, an exact
`plan_apply_required` command for a pending plan, or `resume_required` when a
recording manifest or target change is ready for `rewrite next`. This makes a
lost action response recoverable without rebuilding argv. Do not execute a
reconstructed action concurrently with a previously launched copy that is
still running. In `system_repair_required`, status also reconstructs the exact
coordinator-issued `repair verify <repair-id>` acceptance. When an action
reports `recovery_required`, execute its exact
`rewrite recover` argv. Recovery rejects a live coordinator, removes a stale
lock, stops an orphaned focused target/Replay attempt, and publishes that
attempt as interrupted before returning the next coordinator command.

Traffic-e2e's internal runner publication may retain its own implementation
layout. Those local paths are not a stable rewrite-interface contract. The
interface may expose immutable artifact paths such as a representative
`case_dir` when direct inspection is useful.

The target repository's `replay-progress.yaml` and
`comparison-progress.yaml` are a separate, versioned coordinator output. Do
not edit or roll them back manually. Preserve coordinator-generated changes,
including consecutive-success evidence, and commit them with the target change
they verify. Continue excluding ignored local runtime state and traffic
artifacts from delivery.
