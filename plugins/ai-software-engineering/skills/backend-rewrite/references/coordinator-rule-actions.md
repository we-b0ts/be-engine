# Coordinator Rule Actions

Audience: the workflow coordinator. Read only after the assigned worker is
confirmed and returns source-proven inputs for a response rule, recorder capture, process-owned
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
codec-specific path plus source proof; the workflow coordinator plans and applies
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
read [recording-lifecycle.md](recording-lifecycle.md) when the engine
returns the consolidated refresh.

## HTTP Response URL Capture

For a source-proven IP omission, run the defect preflight using current issue
evidence and the source call location:

```text
backend-rewrite route --cause unrecorded-ip \
  --evidence-id <returned-evidence-id> --case-id <case-id> \
  --endpoint <IP:port> --ip-origin http-response \
  --source-ref '<source file:line symbol: address acquisition and missing-call proof>'
```

The preflight returns `accepted: false` and stays outside system repair. With an
unknown origin it requests investigation; static/hardcoded endpoints receive
source configuration/mock guidance. The `ip_capture` evidence correlates the
reported endpoint with recorded response IDs and JSON pointers. This is source
response evidence, not firewall packet evidence. It includes no full URL query,
credentials or unrelated response body.

Execute the returned `applicable_rule_planners[].command` after reviewing the
pointer and source consumption. Set its required
`BACKEND_REWRITE_SOURCE_EVIDENCE` input to a one-line source file/line/symbol
proof; a field name alone is insufficient. The plan previews the acquisition
rule and returns the exact apply command. Apply persists rules in
`source-traffic-policy.yaml`, then follows the same consolidated refresh as
Breeze capture. `status` restores pending apply commands. Workers return the
source inputs; the coordinator performs the state mutations.

The preflight does not apply an assertion selector or ignore differences.
Pending capture plans and unresolved supported candidates block capability-gap
submission. If a matching rule already exists, inspect its activation and fresh
recording evidence before reporting the exact remaining engine defect; do not
keep creating duplicate rules or modify historical recordings.

## Process-Output Target-Missing Rules

Use this route only when a confirmed process-output worker returns the exact
`metric`, `dependency_path`, and structured `emitter_evidence` requested by
`comparison_observation.rule_candidate`. The worker must have inspected the
listed source paths and proved both that source code does not start the
interaction and that the interaction does not affect source behavior. Either
contrary finding requires target implementation and forbids this rule.

The workflow coordinator supplies the current process-output ID, source revision,
and finalized comparison run to `traffic-e2e config comparison plan
allow-target-missing`, then reviews the preview and repeats the same arguments
with `apply`. Do not hand-edit `.traffic-e2e/verification.yaml`. The structured
emitter evidence is JSON with exactly `inspected_paths` and `description`.
Applying the policy changes the repository fingerprint; resume only through the
coordinator, which reruns the normal quality, Replay, and comparison flow. One
passing post-apply workflow is sufficient.

## Unordered HTTP Dependency JSON

For HTTP unmatched requests, inspect `dirty_clusters.facts.http_unordered_candidates`
and the `unordered` rule hint. Verified array reorderings expose
`kind=dependency_value`, `capability=http_json_unordered` and the
`dependency-rule plan http unordered` help command. Discovery is available
during response, dependency and Replay issues. Response unordered rules do not
change dependency matching. Old reports require fresh Replay to capture the
request comparison witness.

The worker returns the exact host, port, method, path, JSON Pointer and source
proof that array order is non-contractual. The coordinator plans with the
current evidence ID and reviews `http.json.unordered` in the policy diff.
Execute the returned apply and next commands. Actual Replay is required;
changing this policy cannot reclassify an earlier unmatched request as passed.
Keep query, element contents, duplicate counts and unselected fields exact.
See [HTTP unordered rules](../../../../../docs/http-unordered-rules.md).

## Cross-Case HTTP Dependency Scope

For HTTP unmatched requests, inspect `dirty_clusters.facts.cross_case_candidates`
and the top-level `rule_hints`. Verified same-run candidates expose
`kind=dependency_scope`, `capability=http_cross_case` and the
`dependency-rule plan http cross-case` help command in `applicable_rule_planners`.
This entry is available during response, dependency and Replay issues. Old
reports without request identity require fresh Replay; a URL-only candidate
cannot authorize a rule. Source and target inspection must prove shared cache
initialization, refresh and side-effect semantics. Do not add target prewarming,
classify a lazy business request as background traffic, or ignore unmatched calls.

The worker returns the exact host, port, method, path and source evidence; the
coordinator plans and applies with the current evidence ID. The rule persists
`replay_scope: recording_run` in verification.yaml, without query relaxations,
secrets, case IDs or fixture paths. Follow apply's `next`: real Replay is
mandatory to let the target consume the response and build its own state.
The old failure cannot be reclassified as a pass. Existing complete exchanges
need no new recording. Resolve this supported rule path before reporting a
remaining engine capability gap. See
[HTTP cross-case replay](../../../../../docs/http-cross-case-replay.md).

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

Every ownership-classification `dependency-rule plan` invocation requires exactly one ownership decision:

- `--ownership request-owned`: the report sets
  `target_implementation_required=true`, does not create a recorder rule plan,
  preserves dirty evidence, and requires the target to implement the recorded
  dependency call;
- `--ownership process-owned`: the coordinator may create the process-owned
  recorder rule preview described below;
- `--ownership unresolved`: no recorder rule is created and source ownership
  investigation remains required.

A process-owned dependency rule is process-scoped, not API-scoped; the
engine binds its plan internally to the active API evidence, case source,
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

For ownership classification, only a `process-owned` result returns a `plan_id`. After
`backend-rewrite dependency-rule apply <plan-id>`, execute only the exact
`next` returned by the report. The result includes bounded
`evidence_reclassification` with rule coverage, remaining dirty cases, and the
revised focused result.

An ownership change alone is not a fresh-recording condition. The engine
keeps capture artifacts immutable, recomputes the effective case/global ownership
view, rebuilds dependency evidence, and revises the same progress-ledger attempt.
Clean evidence advances to comparison;
residual case-scoped dirty evidence remains in repair. Apply returns `next`.
Redis rules that additionally require reusable snapshot seeds first try to
derive them from complete, consistent immutable bootstrap evidence. If that
derivation fails, `cache_snapshot_overlay` explicitly reports
`recording_required=true` with the reason, and the engine schedules its
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

## JWT expiration during Replay

For a status mismatch with target HTTP 401, use the engine-issued
`jwt-time-validity` query. It reports recorded/replay time and unverified JWT
expiration candidates without credentials. Trace the source and target JWT
verification path, key source, and actual expiration leeway; 401 or zero
observed dependencies alone does not establish the cause.

Read `signing_key_discovery` in that evidence for effective target variable
names, startup mount paths and `writable` modes, and existing key references.
Use the returned `startup env list` and `startup mount list` commands when
needed; do not guess mounts or dump dotenv contents. Select a file within a
mount with `writable: false` only after source/target code proves the dotenv
path, key field and loading precedence. Discovery needs no running target.

Use the returned `rule plan --request-kind jwt` planner with
`--signing-key-ref`, either `--target-env` or
`--target-key-file` plus `--target-key-field`, `--jwt-leeway-seconds`, and
`--source-evidence`. Plan/apply must verify the original JWT signature and
reject stale evidence or changed keys. Existing bindings require no repeated
key-source declaration. Never pass raw keys on the command line or expose
raw tokens in evidence notes.

The resulting global `verification.yaml` `request_rules.jwt` rule changes
only engine-sent request copies. Apply returns `next` and invalidates API
acceptance across the service. Reexecute the existing recorded cases; this
request rule does not require new standard recording and cannot be verified
by reclassifying old actual responses. Preserve normal JWT expiry checks in
target code and keep dependency verification strict.

For Redis string-write value mismatches, inspect
`dirty_clusters.facts.redis_unordered_candidates`. The normal planner is
`kind=dependency_value`, `capability=redis_value_unordered`, with
`dependency-rule plan redis unordered` followed by `dependency-rule apply` and
fresh Replay. JSON object key order is handled automatically; JSON arrays and
Protobuf repeated fields require source proof. Confirm exact host/port, key or
key affixes, field selector, and Protobuf schema type. These rules do not change
process ownership. See [Redis value rules](../../../../../docs/redis-value-rules.md).
