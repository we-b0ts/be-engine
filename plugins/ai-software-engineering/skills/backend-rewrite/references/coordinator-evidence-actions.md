# Coordinator Evidence Actions

Read this guide only after the assigned worker is confirmed and returns
source-proven inputs for a response rule, recorder capture, process-owned
dependency rule, or process-output rule, or when the current action exposes one
of those planners. Workers may run returned read-only help commands but never
execute the state-mutating commands here.

## Contents

- Recorder-capture planning and refresh
- Typed response-rule planning
- Process-owned dependency-rule planning and reclassification
- Process-output target-missing planning
- Evidence gate and ownership invariants
- Bootstrap dependency overlays

## Typed Response Rules

The target never receives a response-rule selector. A worker returns the
codec-specific path plus source proof; the main orchestrator plans and applies
the rule. Replay and comparison load the applied selector from
`.traffic-e2e/verification.yaml` and normalize source and target observations
without changing target code, configuration, or RPC signatures.

JSON rules use `--kind`, `--json-pointer`, and their top-level justification
arguments. Protobuf and Hessian2 rules instead use typed path JSON and MUST NOT
carry any of those JSON arguments. For a protobuf repeated field:

```text
backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec protobuf \
  --unordered-path '{"field_path":[3,1,6,3],"display_path":"rule_collection.experiments.groups.white_list","element_type":"string","source_evidence":"src/rule.rs:142-149 RuleConfig::white_list: collected from a HashSet, so iteration order is not contractual"}'
```

For a Hessian2 unordered collection:

```text
backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec hessian2 \
  --unordered-path '{"value_path":["result","groups","*","whiteList"],"display_path":"$.result.groups[*].whiteList","source_evidence":"src/rule.rs:142-149 RuleConfig::white_list: collected from a HashSet, so iteration order is not contractual"}'
```

Protobuf paths use numeric schema field numbers in `field_path` plus a semantic
`display_path`. Repeated fields require `element_type`; supported values are
`string`, `message`, the protobuf integer and fixed-width scalar types, `bool`,
`enum`, `float`, and `double`. Raw `bytes` is intentionally unsupported because
its element boundaries and semantics cannot be inferred safely.

Use `--unordered-joined-string-path` for a joined string; its typed JSON also
contains `separator`. Protobuf joined strings additionally require
`"field_type":"string"`.

`source_evidence` is an auditable source citation, not a restatement of the
field name or a diagnostic candidate. For ordinary source files it MUST use
the form `<repository-relative-path>:<line-or-narrow-range> <symbol>: <proven
contract fact>`. The fact must explain why order is non-contractual, for
example that the selected response field is collected from a Set. If the proof
comes from a generated schema or another immutable artifact, cite that exact
artifact location and symbol instead. Keep the citation on one line and bind
it to the source revision represented by the current evidence.

Execute the exact returned apply command once.

Rules are authorized per selected location. A plan may apply one independently
source-proven JSON Pointer, protobuf field path, or Hessian2 value path while
other response differences, dirty dependencies, or unreviewed mechanical
candidates remain. The selected location itself MUST be order-only in every
case where it differs; content, type, presence, length, or duplicate-count
differences at that location fail closed. Plan and apply reports expose the
residual case count or unselected JSON Pointers, and those residuals continue
to block API completion.

Planning requires complete current comparison or focused-E2E evidence. An
`unevaluable` comparison is a verification-system issue, not authorization to
apply a selector or change the target. Preserve its bounded error, route the
reported issue with `--cause replay-capability-gap`, repair traffic-e2e, and
regenerate the comparison result before planning.

## Recorder Capture

Use this route only after the worker proves that source code consumes one exact
response-driving endpoint absent from recorded dependencies and returns one
source file/symbol proof. The hostname is required; the port is optional and
should be included when source evidence proves it.

Run:

```text
backend-rewrite route \
  --cause missing-recorded-resource \
  --evidence-id <returned-evidence-id> \
  --endpoint <source-proven-hostname[:port]> \
  --source-ref '<single-line source file/symbol proof>'
```

The route reverse-resolves the hostname through configured Breeze snapshots,
accepts only one canonical resource, and verifies that the resource is not
already captured. A source-proven port may disambiguate resources sharing a
domain. Shared or unknown domains, already captured resources, and IP literals
are rejected; never supply a guessed Breeze descriptor or resource name. A
successful route returns the ordinary recorder-capture plan report and does not
enter `system_repair_required`.

Execute the exact returned apply argv. Apply is immediate, add-only, atomic,
and stale-safe. If serialized recording, Replay, or comparison is live, inspect
`status` and wait before retrying. A successful apply reports
`recording_refresh_pending=true`, lists waiting APIs, and returns either another
API's next command or the consolidated full-scope recording action. For a
scoped waiting API, poll current `status`; never execute its stale acceptance.

Do not follow capture apply with `recording request`. Continue runnable work and
read [recording-lifecycle.md](recording-lifecycle.md) when the coordinator
returns the consolidated refresh.

## Process-Output Target-Missing Rules

Use this route only when a confirmed process-output worker returns the exact
`metric`, `dependency_path`, and structured `emitter_evidence` requested by
`comparison_observation.rule_candidate`. The worker must have inspected the
listed source paths and proved both that source code does not start the
interaction and that the interaction does not affect source behavior. Either
contrary finding requires target implementation and forbids this rule.

The main orchestrator supplies the current process-output ID, source revision,
and finalized comparison run to `traffic-e2e config comparison plan
allow-target-missing`, then reviews the preview and repeats the same arguments
with `apply`. Do not hand-edit `.traffic-e2e/verification.yaml`. The structured
emitter evidence is JSON with exactly `inspected_paths` and `description`.
Applying the policy changes the repository fingerprint; resume only through the
coordinator, which reruns the normal quality, Replay, and comparison flow. One
passing post-apply workflow is sufficient.

## Process-Owned Dependency Rules

For a dependency issue, the `dirty_clusters` evidence response's top-level
`applicable_rule_planners` contains only supported protocols present in the
current clusters. Use the selected dirty case's
`representative_dependencies_command`, then the selected target's returned
`detail_command` when available. These commands read the recording internally
and return structured protocol facts; manual JSONL parsing is unnecessary for
ordinary diagnosis. Planner exposure
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

For MySQL, use the returned `dependency-rule plan mysql` planner. The worker
supplies exact host/port, database, username, a source-proven read-only SELECT
template, and table selectors. `--table` selects exact names; `--table-prefix`
with `--table-start`, `--table-end`, and `--table-width` selects bounded numeric
shards; repeatable `--table-pattern 'subtasks_*'` selects an identifier pattern
with one `*`. Prefix, suffix, and middle patterns are supported; a bare `*` is
rejected. Source proof must justify the complete selected table family.
`{{table}}` in the SQL binds every table reference and `AS {{table}}_id` alias
to the same physical table. `?` permits a variable literal position; other
projection and predicate facts remain exact. Successful, complete unused
exchanges can be reclassified on the current recording; unmatched target queries
and incomplete evidence remain blocking. Follow the same returned plan/apply/next
sequence as for the other dependency protocols.

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

An ownership change alone is not a fresh-recording condition. The coordinator
keeps capture artifacts immutable, recomputes the effective case/global ownership
view, rebuilds dependency evidence, and revises the same progress-ledger attempt.
Clean evidence advances to comparison;
residual case-scoped dirty evidence remains in repair. Apply returns `next`.
Redis rules that additionally require reusable snapshot seeds first try to
derive them from complete, consistent immutable bootstrap evidence. If that
derivation fails, `cache_snapshot_overlay` explicitly reports
`recording_required=true` with the reason, and the coordinator schedules its
recording refresh to obtain snapshot evidence that the existing recording cannot
safely provide. MySQL ownership reclassification does not require Redis snapshot
seeds. Follow the returned action in either case, without manually requesting a
recording.

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
recording-global bootstrap and configured process-owned summary is available
only from `source_process_traffic`;
`unused_global`, startup context, and case-external target activity do not fail
the case gate.

Process ownership and response causality are independent. A matching
process-owned rule carries no response-state classification and does not
implement destination state. If source and response evidence prove that the
dependency drives state, port source-compatible initial load, refresh, cache,
fallback, and readiness behavior. `initial_load_timeout_ms` only bounds source
recording observation.

## Bootstrap Dependency Overlay

For a Response issue with Redis bootstrap observations, the returned
`source_process_traffic` query may expose the Redis bootstrap dependency
planner. It accepts compact HGET/HMGET
numeric-key patterns plus exact fields, applies a replay-only overlay to
immutable Global bootstrap evidence, and returns to the same focused cases.
