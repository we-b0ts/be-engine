# Coordinator Evidence Actions

Read this guide only after the API worker is confirmed and returns source-proven
inputs for recorder capture or a process-owned dependency rule, or when the
current action exposes one of those planners. Workers may run returned
read-only help commands but never execute the state-mutating commands here.

## Contents

- Recorder-capture planning and refresh
- Process-owned dependency-rule planning and reclassification
- Evidence gate and ownership invariants
- Bootstrap dependency overlays

## Recorder Capture

The `representatives` evidence report may advertise a `recorder_capture`
planner for response, dependency, or comparison issues. Planner availability
does not prove that traffic was omitted. Use it only after the worker proves
that source code consumes one exact response-driving endpoint absent from
recorded dependencies and returns one source file/symbol proof.

Run:

```text
backend-rewrite recorder-capture plan \
  --evidence-id <returned-evidence-id> \
  --endpoint <source-proven-hostname[:port]> \
  --source-evidence '<single-line source file/symbol proof>'
```

The planner reverse-resolves the hostname through configured Breeze snapshots
and accepts only one canonical resource. A source-proven port may disambiguate
resources sharing a domain. Shared or unknown domains and IP literals are
rejected; never supply a guessed Breeze descriptor or resource name.

Execute the exact returned apply argv. Apply is immediate, add-only, atomic,
and stale-safe. If serialized recording, Replay, or comparison is live, inspect
`status` and wait before retrying. A successful apply reports
`recording_refresh_pending=true`, lists waiting APIs, and returns either another
API's next command or the consolidated full-scope recording action. For a
scoped waiting API, poll current `status`; never execute its stale acceptance.

Do not follow capture apply with `recording request`. Continue runnable work and
read [recording-lifecycle.md](recording-lifecycle.md) when the coordinator
returns the consolidated refresh.

## Process-Owned Dependency Rules

For a dependency issue, `dirty_clusters.applicable_rule_planners` contains only
supported protocols present in the current clusters. Use the selected dirty
case's `representative_dependencies_command` when available. Planner exposure
does not establish ownership. Asynchronous execution, fire-and-forget calls,
post-response timing, scheduler names, and the 100 ms attribution window do not
make a dependency process-owned.

Every `dependency-rule plan` invocation requires exactly one ownership decision:

- `--ownership request-owned`: the report sets
  `target_implementation_required=true`, does not create a recorder rule plan,
  preserves dirty evidence, and requires the target to implement the recorded
  dependency call;
- `--ownership process-owned`: the coordinator may create the process-owned
  recorder rule preview described below;
- `--ownership unresolved`: no recorder rule is created and source ownership
  investigation remains required.

A process-owned dependency rule is process-scoped, not API-scoped; the
coordinator binds its plan internally to the active API evidence, case source,
and source revision. Never use `process-owned` merely because a call runs
asynchronously or does not affect the current response.

Run only the protocol-specific planner returned by the evidence and use only
source-proven selector inputs. Planning persists an evidence-validated preview.
Its own workflow revision change does not invalidate apply. If bounded coverage
shows an incomplete selector, rerun the same planner with the same evidence ID
and corrected inputs; the newer preview replaces the pending one atomically.
Recorder configuration remains unchanged until apply.

For Redis, select the command-specific planner. `get`, `scard`, and `hgetall`
accept only exact keys proven by immutable evidence; never generalize them to a
prefix or wildcard. If planning returns `reused_existing=true`, execute the
returned apply action. It is a successful no-op reuse under `effective_name`
that still refreshes current evidence, not a duplicate rule. Status
reconstructs the same plan-ID transition.

Only a `process-owned` result returns a `plan_id`. After
`backend-rewrite dependency-rule apply <plan-id>`, execute only the exact
`next` returned by the report. The result includes bounded
`evidence_reclassification` with rule coverage, remaining dirty cases, and the
revised focused result.

Applying or confirming a process-owned dependency rule is not a fresh-recording
condition. The coordinator keeps capture artifacts immutable, recomputes the
effective case/global ownership view, rebuilds dependency evidence, and revises
the same progress-ledger attempt. Clean evidence advances to comparison;
residual case-scoped dirty evidence remains in repair. Apply therefore returns
`next`, never a recorder-contract recording request.

On resume, `next` may repair a finalized attempt whose derived dependency view
is already clean but whose persisted failure retains an obsolete strict
dirty-finalize result. This removes only dependency-derived errors, preserves
real lifecycle failures, and does not execute another E2E attempt.

## Evidence And Ownership Invariants

Evaluate gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Dirty dependencies cannot preempt a response mismatch. A repository change
after a comparison mismatch returns through focused E2E before another
comparison recording.

Dependency cleanliness is evaluated per active case. Clusters contain
case-scoped unmatched, unsupported, unsafe, and unused-case events grouped by
protocol and endpoint. Each has a stable `cluster_id`, bounded operations, a
representative case, and correlated source pre-readiness count. The complete
startup summary is available only from `pre_readiness_traffic`;
`unused_global`, startup context, and case-external target activity do not fail
the case gate.

Process ownership and response causality are independent. A matching
process-owned rule carries no response-state classification and does not
implement destination state. If source and response evidence prove that the
dependency drives state, port source-compatible initial load, refresh, cache,
fallback, and readiness behavior. `initial_load_timeout_ms` only bounds source
recording observation.

## Bootstrap Dependency Overlay

For a Response issue with pre-readiness traffic, the returned query may expose
the Redis bootstrap dependency planner. It accepts compact HGET/HMGET
numeric-key patterns plus exact fields, applies a replay-only overlay to
immutable Global bootstrap evidence, and returns to the same focused cases.
