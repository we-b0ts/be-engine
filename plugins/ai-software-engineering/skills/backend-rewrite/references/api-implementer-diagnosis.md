# API Implementer Diagnosis

Audience: API implementers assigned an `implementation_required` work item. Read before work-item diagnosis
or code changes. Before edits, read
[target-code-rules.md](target-code-rules.md).
For a proven environment override, mount, or writable-directory requirement,
read [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md).
Use the engine's current
work-item facts to identify one repair before the engine-issued acceptance.
Select the diagnosis path from the assigned work scope and confirm it against
the evidence overview.

## Diagnosis Routing

Query the assigned API scope, then select the diagnosis path from the current
issue and evidence. Read only the relevant specialty document when its signal appears:

| Current issue or evidence | Specialty diagnosis |
| --- | --- |
| Missing recorded dependency, dirty dependency, MySQL or Redis compatibility | [Dependency diagnosis](api-implementer-dependency-diagnosis.md) |
| Rejected egress, local cache, target runtime or incomplete Replay | [Runtime and Replay diagnosis](api-implementer-runtime-diagnosis.md) |
| Source-generated time/random values, non-contractual order, a rule hint, or a possible rule capability gap | [Rule diagnosis](api-implementer-rule-diagnosis.md) |
| Unused dependencies may come from a source-detached API task | [API-triggered asynchronous process traffic](api-implementer-dependency-diagnosis.md#api-triggered-asynchronous-process-traffic) |

An issue may require more than one specialty document to distinguish causes. Follow
the response, Replay, and dependency gate order below when choosing a repair.

## Work-Scope Contract

Start each worker turn by querying the exact assigned scope against the canonical
target root, even while editing a separate worktree:

```text
backend-rewrite --target-root <canonical-root> evidence --api '<assigned path-or-pattern>'
```

Choose the entrypoint matching the assigned scope. Do not query a worker-local rewrite
workflow. The coordinator supplies your role, exact scope, canonical target root,
absolute worktree, and source repository locations; the engine supplies current facts. Missing information
never changes a worker's role. Report an unresolvable identity or API gap without
assuming coordinator authority or guessing another work item.

If the engine reports an unconfirmed dispatch, wait for the coordinator's
confirmation and retry this same read-only entrypoint; a worker can start before
the coordinator has completed confirmation. Do not confirm or report yourself.
An unknown scope or a scope with no current issue is an explicit error; report it
to the coordinator instead of implementing from a previous issue.

The overview's `context` contains `target_root`, `workflow_id`, `revision`,
`recording_run_id` and `worker` with exact scope, binding
and dispatch identity. Read the complete bounded issue in `facts.issue`,
including its ID, attempt, observed target fingerprint, possible causes, and
representative when available. HTTP route overviews also return `facts.method_apis`
for the complete method contract set and `facts.method_issues` with per-method
issues and queries. Check each included method, including siblings whose response
evidence already passed; use the method's returned query IDs for diagnosis and
retain its recorded method. Do not select only the first directory case or merge
expected responses between methods. Treat possible causes as hypotheses.
Use a legacy `METHOD API` entrypoint only when that is the exact returned assignment.

The same context includes `review` with the registered worktree/base and the
local check command. For a `target_quality` issue, read the assigned findings
in `context.review.rework.findings` and the supplied review report, then follow
[api-implementer-review.md](api-implementer-review.md); no traffic mismatch is implied. An
unpublished candidate's findings need not appear in canonical `review show`.
For a quality rework alongside an existing behavioral issue, read the assigned
findings in `context.review.rework.findings` and address them as well. These
retain the routing evidence if a later integration makes `review show` stale.
Every changed-code handoff requires a `passed` review after the final edit and
commit. Follow [api-implementer-review.md](api-implementer-review.md) for the
complete delivery and evidence contract.
Do not run integration-candidate checks or report your own handoff.

Retain the initial overview's workflow/recording, scope, issue, binding and
dispatch identities for this turn and include them in the return handoff. If a
later query is stale, fetch the same scoped entrypoint to check its identity. A
changed issue or dispatch requires coordinator reconciliation; never relabel old
work with the new identity. A workflow revision change alone does not replace
this assignment. Opaque detail-query IDs remain valid only for their original
evidence; use newly returned IDs when evidence changes within the same assignment.

Prove one cause from source and target code, then follow
[Return The Proven Cause](#return-the-proven-cause). A post-input resume still
requiring implementation delivery follows
[api-implementer-review.md](api-implementer-review.md), even when no code repair
remains; retain the existing commit rather than creating an artificial patch.

For `work_scope.kind=api`, exact further evidence-query argv are under the
overview's `queries`. Traffic facts come only from the overview, returned queries
and immutable artifacts. Standard artifacts are readable,
read-only diagnostic evidence. Start from the representative `case_dir`
returned by the engine and inspect its complete contents. Inspect other
cases under `.traffic-e2e/local/artifacts/` only when they help distinguish
hypotheses. Use bounded engine queries before inspecting
`.traffic-e2e/local/runtime/`.
Runtime inspection is read-only and diagnostic: do not infer the active run by
recency, edit state, or use ad-hoc scripts to recreate an engine query.
Never patch multiple speculative categories in one iteration.

For an API work item, evaluate gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Select the active issue's largest bounded cluster and representative. Preserve
the distinction between a present JSON `null`, a missing Pointer, unavailable
evidence, and a non-JSON body. Map key order and JSON formatting are already
ignored. Array order, type, presence, empty string, and scalar value remain
real differences until source evidence proves otherwise.

When a difference traces to iteration over a Set, HashSet, or another collection
with non-contractual order, do not make target code reproduce the order seen in
one recording. Prove from source construction and downstream use that only order
differs, with element values and duplicate counts preserved. Check the current
verification policy and the relevant response or dependency `unordered` rule
before proposing target changes; return exact selectors and source proof to the
coordinator to reuse or plan a supported rule. If order is contractual or the
contents differ, repair the target behavior instead.

## Rule Discovery From Source Diagnosis

Before recommending any rule plan, check `facts.policy_freshness`. If it requires
fresh Replay, retain the diagnosis and return its `refresh_command` to the
coordinator. A stale policy does not establish a recording or capability gap.

After tracing source and target behavior, read
[Rule diagnosis](api-implementer-rule-diagnosis.md) for generated identities,
JWT expiry, DOCX/header dates, Redis locks or time values, MySQL result time
shifts, cross-case HTTP initialization, unordered collections, and protocol
value rules. Source proof determines applicability; engine hints are additional
evidence, and their absence does not mean a documented capability is unavailable.

In particular, Redis `time-shift` has no automatic hint. When an earlier matched
Redis timestamp may cause expiry, extra reads, or an error branch, read its
[proof contract](api-implementer-rule-diagnosis.md#rule-discovery-from-source-diagnosis)
and inspect the shared `dependency.response` time contract and explicit delivery
permission. Check `backend-rewrite rule plan --help` and the typed capabilities
before declaring a gap. Only the
coordinator plans/applies rules and runs fresh verification.

## API Evidence Queries

Execute only the exact opaque argv returned by the current overview's `queries`
or a subsequent evidence report. Select by the current problem and returned
purpose; never reconstruct a query ID or cursor.

| Problem signal | Evidence |
| --- | --- |
| Response differences need complete case context | `case_response_differences` |
| Case-scoped dependency evidence is dirty | `dirty_clusters` |
| Startup, background refresh, or local-cache state may affect behavior | `source_process_traffic` |
| Target startup or lifecycle failed | `target_runtime_diagnostics` |

For a response issue, execute the returned `case_response_differences` first
page before changing target code. It distinguishes expected/actual value
presence. `response_unavailable` at `$response` means no usable target response
assertion evidence, not zero differences. An `unavailable_reason` describes
observed transport behavior: `target_connection_closed` does not distinguish a
panic from another target abort. When more differences are needed to identify
one coherent cause, execute only the current `facts.next_page.command`.

Interpret diagnostic evidence within these limits:

- `representatives` selects immutable case evidence; it does not prove cause.
- `source_variation` alone proves neither nondeterminism nor cache ownership.
- `collection_equivalence` establishes array multiset equality, not that source
  order is irrelevant.
- `dependency_correlation` does not prove response causality.
- `source_process_traffic` covers recording-global bootstrap and configured
  process-owned traffic. Timing, frequency, and configured rule matches do not
  prove response causality or replace request-owned target behavior.
- `dirty_clusters` covers case-scoped dirty events, excluding `unused_global`
  and case-external target activity. It does not prove request/process ownership.
  Inspect returned `applicable_rule_planners` and `rule_hints` using their exact
  read-only help commands; availability does not prove applicability. For value
  mechanisms and capabilities without hints, follow [Rule diagnosis](api-implementer-rule-diagnosis.md).
- `policy_applicability` establishes structural eligibility, not authorization.
- `attempt_delta` measures convergence, not cause.

Use the smallest query set that can distinguish the current hypotheses. Then
inspect the representative case and trace the corresponding source and target
path. Read other artifact cases only when the representative is insufficient.
Do not run every query merely because it is available.

### Dependency Topology

Execute the representative result's `dependencies_command`, or the
dirty-cluster result's `representative_dependencies_command`. From the
target-grouped summary, execute only the relevant returned `detail_command`
before reading raw `dependencies.jsonl`. Do not recreate this projection with
Python or shell parsing; inspect raw immutable evidence only when omitted or
truncated facts block diagnosis.

Preserve each MySQL exchange's SQL/parameter/session context, Redis
key/argument/response association, and Memcached key/outcome association.
Respect omitted payloads and marked preview encodings/truncation; a preview is
not a complete response. Memcached flags are neither interpreted nor returned.

Only a dependency event attributed to an active case participates in that
case's cleanliness gate. Treat source pre-readiness traffic as reference for
startup jobs, warmup, and local-cache hypotheses. Do not repair, suppress, or
re-record traffic merely because the same endpoint appears during startup.

## Response Issues

Execute the returned `case_response_differences` first page before changing
target code. Use the API-level `response_diagnosis.failure_clusters` to select
the largest coherent cluster, and inspect additional returned pages only when
the first page does not distinguish its cause. Do not interpret matching
Pointer patterns alone as proof that the differences share one implementation
cause.

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
  UUID, or random generation; nonce and random salt are uses of `random`, and a
  derived scalar uses its root mechanism with the derivation in source evidence;
- `unordered_contract`: source collection type and API contract prove order is
  irrelevant and bounded evidence proves equal contents;
- `missing_external_evidence`: one exact required external value or exchange is
  absent and cannot be derived without invention.

Environment handling is not limited to this failure classification. If source
analysis proves during implementation that target logic requires an
application-owned environment variable, follow [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md)
immediately and return the startup input without waiting for a runtime failure.

For a status mismatch, inspect authentication/preconditions, source error
mapping, boot/request context, and dependency-driven branches before inspecting
body-field policy. For array order, prove both equal contents and a source
ordering contract; map/set iteration is a hypothesis, not proof.

## Return The Proven Cause

Return one supported result with the original evidence/dispatch identity,
source proof, shared impact, necessary coordinator inputs, and unresolved risks:

- Target API, cache, or startup defect: make one
  coherent repair, run focused tests, and complete [api-implementer-review.md](api-implementer-review.md).
- Supported nondeterminism/order: return source proof and exact typed
  rule inputs. Do not apply the rule.
- Source-proven omitted dependency: return evidence ID, `hostname[:port]`,
  source reference, and the missing resource proof.
- Recorder/Replay capability gap: after checking supported mechanisms, return
  the exact unsupported behavior, evidence, source reference, and required
  system change. Do not compensate in target code.
- Source change or external-data issue: return exact evidence and the required
  external change without inventing a target replacement.
- Unresolved: return the named missing source/runtime proof and completed
  investigation; do not add speculative code or policy.

Use `blocked` only when source construction, target implementation, wiring, and
available runtime evidence prove that a required external response-driving value
is unavailable and completion would require invention. Repeated failures, empty
dependency streams, or tool errors do not prove that blocker.

Do not return or execute an acceptance command. End the turn after the result;
do not wait for acceptance. If two repairs do not
improve the active issue, stop adding local patches and return a bounded
structural replan from the current issue and attempt delta.

## API-triggered asynchronous process traffic

When unused dependencies may come from a source-detached API task, read
[the dependency diagnosis](api-implementer-dependency-diagnosis.md#api-triggered-asynchronous-process-traffic)
for source ownership proof, supported protocol selectors, and strict boundaries.
