# Rewrite Problem Diagnosis

Use this reference for every `implementation_required` action. Problem
diagnosis is a required rewrite phase, not optional troubleshooting. Its result
chooses the only repair attempted before the next focused E2E run.

## Contract

The coordinator supplies one active issue, bounded possible causes, one
representative when available, exact evidence-query argv, and one acceptance
command. Treat possible causes as hypotheses. Traffic facts come only from the
returned queries and immutable artifacts; business causality comes from source
and target code.

Standard and comparison artifacts are readable, read-only diagnostic evidence.
Start from the representative `case_dir` returned by the coordinator and
inspect its complete contents. Inspect other cases under
`.traffic-e2e/artifacts/` when they help distinguish hypotheses. Prefer bounded
coordinator queries over scanning generated local state or large reports; do
not edit internal state, infer the active run by recency, or use ad-hoc scripts
to recreate a coordinator query. Never patch multiple speculative categories
in one iteration.

Evaluate gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Select the active issue's largest bounded cluster and representative. Preserve
the distinction between a present JSON `null`, a missing Pointer, unavailable
evidence, and a non-JSON body. Map key order and JSON formatting are already
ignored. Array order, type, presence, empty string, and scalar value remain
real differences until source evidence proves otherwise.

## Evidence Queries

Run only query IDs returned by the active action:

- `representatives`: the representative case ID, exact immutable standard or
  comparison `case_dir`, and bounded structured response or dependency
  difference; it does not prove the cause;
- `source_variation`: source values across recorded cases; variation alone
  does not prove nondeterminism or cache ownership;
- `collection_equivalence`: array multiset equality; equality does not prove
  that source order is irrelevant;
- `dependency_correlation`: response outcomes against dependency cleanliness;
  correlation does not prove response causality;
- `pre_readiness_traffic`: bounded source data-interaction counts by endpoint
  before readiness; connection lifecycle, known ping/heartbeat, and setup
  traffic are excluded, but frequency does not prove background ownership,
  local-cache lifecycle, or response causality;
- `dirty_clusters`: case-scoped dirty events grouped by protocol and endpoint,
  with a stable `cluster_id`, bounded operation counts, an exact representative
  case, and a correlated source pre-readiness count. The complete startup
  summary remains in `pre_readiness_traffic`. It excludes `unused_global` and
  case-external target activity, and does not prove request or process
  ownership. For a dependency issue it also returns
  `applicable_rule_planners` only for supported protocols present in those
  clusters;
- `policy_applicability`: structural rule eligibility; eligibility does not
  authorize a rule;
- `attempt_delta`: convergence against the previous attempt; improvement does
  not identify the cause.

Use the smallest query set that can distinguish the current hypotheses. Then
inspect the representative case and trace the corresponding source and target
path. Read other artifact cases only when the representative is insufficient.
Do not run every query merely because it is available.

Only a dependency event attributed to an active case participates in that
case's cleanliness gate. Treat source pre-readiness traffic as reference for
startup jobs, warmup, and local-cache hypotheses. Do not repair, suppress, or
re-record traffic merely because the same endpoint appears during startup.

## Response Issues

Use the recorded request, expected response, dependencies, and structured
response difference from the representative case to trace response
construction backwards:

```text
response field/status -> target construction -> local state/cache -> client
call -> framework wiring -> configuration -> external dependency
```

Classify exactly one cause:

- `target_behavior`: source and target construct stable behavior differently;
- `target_environment`: authentication, startup input, request context,
  readiness, CA, port, or client wiring differs;
- `local_cache/runtime_state`: cache lifecycle or process-local state differs;
- `dependency_behavior`: the target calls, selects, or consumes a dependency
  differently;
- `intentional_nondeterminism`: source code proves current time, duration,
  UUID, random, nonce, random salt, or a derived scalar;
- `unordered_contract`: source collection type and API contract prove order is
  irrelevant and bounded evidence proves equal contents;
- `comparison_counter`: source ownership and type prove a live counter that is
  valid only for comparison policy;
- `missing_external_evidence`: one exact required external value or exchange is
  absent and cannot be derived without invention.

For a status mismatch, inspect authentication/preconditions, source error
mapping, boot/request context, and dependency-driven branches before inspecting
body-field policy. For array order, prove both equal contents and a source
ordering contract; map/set iteration is a hypothesis, not proof.

## Local Cache And Runtime State

A response-affecting local cache is target behavior. Preserve source cache:

- key construction and namespace;
- miss and negative-cache behavior;
- warmup and readiness relationship;
- expiry, refresh, and stale-value behavior;
- bounds and eviction;
- concurrent load/coalescing behavior;
- fallback when the backing dependency fails;
- process restart and snapshot semantics.

Prove the complete path:

```text
response -> cache read -> key -> hit/miss branch -> loader dependency ->
write/refresh -> readiness or request lifecycle
```

Use `pre_readiness_traffic` only to prioritize source startup schedulers and
cache loaders for the returned endpoints. An absent endpoint is not proof that
no process-local cache exists, and a high interaction count is not proof that
the traffic populates a cache.

Do not apply a dynamic rule for a cold, missing, stale, differently keyed,
partially loaded, or differently refreshed cache. Do not materialize recorded
cache results as target fixtures or boot configuration. Repair the target cache
or its genuine dependency path and rerun the same immutable group.

## Target Runtime Issues

When no response assertion completed, inspect the bounded lifecycle error and
then the normal target boundary:

1. compile and launch path;
2. supplied boot/config roots and source-compatible loader;
3. configured port and readiness endpoint/status;
4. Replay CA trust and dependency client construction;
5. process ownership and idempotent stop behavior.

Repair product startup, composition, configuration loading, or the conventional
project CLI. Do not add case execution, report parsing, Replay control, or
expected-response access to the target repository.

## Replay Issues

`replay=incomplete` means the engine did not publish complete lifecycle
evidence. Use the returned issue and dirty-cluster query to distinguish:

- target never emitted the expected genuine dependency call;
- semantic dependency evidence exists but Replay cannot match or reproduce it;
- interception, readiness, begin/end, finalize, or cleanup failed;
- the recording lacks required semantic evidence.

If target topology differs, repair target behavior. If semantic evidence exists
but the engine lacks support, submit `rewrite route` with a current evidence ID,
source reference, and exact system change. Then apply the repair and use only
the coordinator-issued `repair verify <repair-id>` acceptance. Never implement
a target workaround for a Replay capability gap or supply an arbitrary
acceptance command.

## Dirty Dependency Issues

Diagnose dirty dependencies only after responses pass and Replay is complete.
Classify the representative protocol cluster by source ownership:

- request-owned and required: repair target call topology or Replay support;
- process-owned and case-independent: use a supported background recording
  rule; separately repair target state behavior when source and response
  evidence prove the dependency is response-driving;
- unresolved: retain the dirty evidence and name the missing proof.

Timing overlap, high volume, scheduler names, unused exchanges, and passing
responses do not prove background ownership. A recording-rule change must use
the current dirty-cluster evidence ID and one protocol-specific planner returned
in `applicable_rule_planners`. Run its exact help argv, supply only the
source-proven selector inputs to `rewrite dependency-rule plan <protocol>`, and
apply the returned plan ID. Replay evidence, case source, and source revision
come from coordinator state and are not background-rule inputs. Execute the apply
report's exact fresh-recording request. Never call the lower-level Recorder
config planner, reclassify existing evidence, trim traffic, or edit an existing
recording.

## Comparison Issues

For one representative comparison difference, distinguish:

- candidate-only stable difference: target behavior;
- source-before/source-after change at the same Pointer: source change or
  possible nondeterminism requiring source proof;
- proven generated scalar: supported dynamic rule candidate;
- proven equal-content unordered array: unordered rule candidate;
- proven live numeric counter: comparison-only counter candidate;
- cache hit/miss/staleness/warmup: target behavior, never policy.

A target or response-policy change invalidates comparison evidence. The
coordinator must rerun focused E2E before requesting a fresh comparison.

## Repair Routing

Route the proven cause to exactly one action:

- target implementation or cache defect: change target code with
  `backend-engineering`, run focused target tests, then the implementation
  action's acceptance command;
- startup/configuration defect: repair source-compatible loading or the fixed
  start/stop boundary, then run the implementation action's acceptance command;
- supported nondeterminism/order/counter: run exact `rewrite rule plan`, review
  the evidence, then `apply` and rerun;
- Recorder/Replay capability gap, source change, or external-data issue: submit
  exact `rewrite route` evidence, apply the routed change, then execute the
  returned `repair verify <repair-id>` action; do not patch the target;
- unresolved: gather the named missing source/runtime proof before changing
  code or policy.

Use `blocked` only when source construction, target implementation, wiring, and
available runtime evidence prove that one required external response-driving
value is unavailable and completion would require invention. Repeated failed
attempts, dirty evidence, an empty dependency stream, or a tool failure do not
prove a blocker.

After one repair, rerun the entire immutable API group. If two repairs do not
improve the active cluster, stop adding field patches and produce a bounded
structural replan from the current issue and attempt delta.
