# API Implementer Diagnosis

Audience: API implementers assigned an `implementation_required` work item,
including legacy process-output assignments. Read before work-item diagnosis
or code changes. Before edits, read
[target-code-rules.md](target-code-rules.md).
For a proven environment override, mount, or writable-directory requirement,
read [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md).
Use the engine's current
work-item facts to identify one repair before the engine-issued acceptance.
Select the diagnosis path from the assigned work scope and confirm it against
the evidence overview.

## Diagnosis Routing

Read the work-scope contract below, query the assigned scope, and then select
the relevant diagnosis path from the current issue and evidence. For
`work_scope.kind=process_output`, read
[process-output diagnosis](api-implementer-process-output.md) and return through
the common handoff contract below. For `work_scope.kind=api`, use the API
evidence queries, rule discovery, response and comparison sections below. Read
only the relevant specialty document when its signal appears:

| Current issue or evidence | Specialty diagnosis |
| --- | --- |
| Missing recorded dependency, dirty dependency, MySQL or Redis compatibility | [Dependency diagnosis](api-implementer-dependency-diagnosis.md) |
| Rejected egress, local cache, target runtime or incomplete Replay | [Runtime and Replay diagnosis](api-implementer-runtime-diagnosis.md) |

An issue may require both specialty documents to distinguish causes. Follow
the response, Replay, and dependency gate order below when choosing a repair.

## Work-Scope Contract

Start each worker turn by querying the exact assigned scope against the canonical
target root, even while editing a separate worktree:

```text
backend-rewrite --target-root <canonical-root> evidence --api '<assigned path-or-pattern>'
backend-rewrite --target-root <canonical-root> evidence --process-output <id>
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
`recording_run_id`, `require_comparison`, and `worker` with exact scope, binding
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
Every changed-code handoff requires a `passed` review after the final
edit and commit; include its absolute `report_path` and any spawn ownership
evidence. Follow the delivery steps in
[api-implementer-review.md](api-implementer-review.md).
Do not run integration-candidate checks or report your own handoff.

Retain the initial overview's workflow/recording, scope, issue, binding and
dispatch identities for this turn and include them in the return handoff. If a
later query is stale, fetch the same scoped entrypoint to check its identity. A
changed issue or dispatch requires coordinator reconciliation; never relabel old
work with the new identity. A workflow revision change alone does not replace
this assignment. Opaque detail-query IDs remain valid only for their original
evidence; use newly returned IDs when evidence changes within the same assignment.

For either scope, prove one cause from source and target code. When it requires
code changes, make one coherent repair and run focused local tests; return the
commit, passing review, and local results. For a rule, startup input, or external
repair without code changes, return proof and exact inputs without a code handoff.
Both results include the original identity, cause, evidence, shared impact,
necessary coordinator inputs, and unresolved risks. Do not return or execute an
acceptance command. End your turn after returning the result.

If resumed after input application while an implementation handoff is still
required, review the current target even when no code repair remains. Follow
[api-implementer-review.md](api-implementer-review.md) and return the existing commit and passing
report; no artificial patch or new commit is needed.

For `work_scope.kind=api`, exact further evidence-query argv are under the
overview's `queries`. Traffic facts come only from the overview, returned queries
and immutable artifacts. Standard and comparison artifacts are readable,
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

The API evidence, rule discovery, response, and comparison sections below apply
only to API work items. A process-output worker follows the routed specialty
document and returns after completing that diagnosis path.

## Rule Discovery From Source Diagnosis

For a random identity shared across protocols, return one capture (MySQL SQL
template/value index, Redis SET/HSET value, or HTTP dependency JSON pointer),
exact allowed host/port
endpoints and source generator/lifetime proof. `rule plan --dynamic-value`
correlates later decoded references without enumerating every decoded request reference;
format is optional. See [dynamic value rules](../../../../../docs/dynamic-value-rules.md).
For a current-date filename in `Content-Disposition`, return the header parameter,
calendar format, timezone and exporter proof for `rule plan --header-date`.
It checks `filename*` too and retains static filename/header/body assertions;
see [header date rules](../../../../../docs/response-header-date-rules.md).
Only the coordinator plans/applies these rules, followed by fresh verification.

Check `facts.policy_freshness` before recommending a plan. If it requires fresh
Replay, keep the source diagnosis and return the structured `refresh_command`
to the coordinator. Any policy edit can stale earlier evidence, including a
rule for another API. The coordinator follows normal review/scheduling gates,
reuses the recording run, and obtains new evidence. Changing evidence IDs or
selectors cannot fix this mismatch; it does not prove an engine capability gap.

For API issues, consult these capabilities after tracing source and target
behavior. Engine hints and mechanical candidates are additional evidence;
their absence does not mean a documented capability is unavailable.

| Proven scenario | Capability and next investigation |
| --- | --- |
| An inbound JWT in a Bearer header or named URL query parameter expired between capture and Replay | JWT `preserve_relative`; inspect the returned `jwt-time-validity` query and prove the exact token location, authentication path, expiry leeway, and signing-key source. |
| A DOCX download differs because OPC ZIP metadata and `docProps/core.xml` creation time are generated per request | DOCX response-body rule; prove the generated XML timestamp in source, select it explicitly, verify that its source-to-target delta tracks elapsed request time, and keep every other decompressed package part exact. |
| Random SET NX ownership tokens differ from recordings, or a script/DELEX references that token | Redis `lock`; inspect `redis_lock_candidates`, prove random tokens and conditional release from source, and return host, port, key selector plus source evidence. One rule correlates all supported references; never remove the lock or independently ignore token arguments. |
| A recorded Redis response timestamp makes an otherwise correct cache expire during Replay, causing extra reads or an error branch | Redis `time-shift`; inspect earlier successfully matched GET/HGET responses, including previous cases, and prove their time semantics. |
| Shared HTTP initialization was recorded in another case | HTTP `cross-case`; verify same-run request identity and source sharing semantics. |
| An outbound HTTP array or Redis write collection differs only in order | Protocol-specific `unordered`; prove collection semantics and inspect exact order witnesses. |

Redis `time-shift` has no automatic hint: a numeric value, field name, elapsed
time, extra read, or missing exchange cannot establish business time semantics.
Its documented read-only entrypoint is
`backend-rewrite dependency-rule plan redis time-shift --help`. Return the current
dirty-cluster evidence ID, source-selected endpoint/key/hash-field, response JSON
Pointer, timestamp format, and source proof to the coordinator. Proof establishes
the expiry/cache calculation, units, and downstream uses, including signatures.
An absent `applicable_rule_planners` hint does not rule out this documented
capability. Supply the expiry proof and exact inputs; immutable response matching
alone does not establish expiry causality. Use exact JSON Pointers and explicit
Unix seconds or milliseconds; prove any broader key/field selector shares those
semantics. A signed timestamp or downstream dependency argument needs additional
compatibility proof; this rule neither re-signs Redis tokens nor relaxes matching.

JWT diagnosis uses the failed attempt's time and `signing_key_discovery`, never
the current clock or raw tokens in notes. A 401, missing key, or unverified
signature is insufficient proof. Trace authentication and configuration
precedence; return current evidence, header, supported HMAC algorithm, key alias,
expiry leeway, source proof, and either the effective environment variable name
or read-only mounted dotenv path and field. Existing bindings may be reused.
The capability supports Bearer HS256/HS384/HS512 with integer NumericDate claims;
it preserves relative validity and does not justify weakening authentication.
Do not apply rules or run Replay.

## API Evidence Queries

Run only query IDs returned by the overview's `queries` or a subsequent
evidence report:

| Problem signal | Evidence | Command |
| --- | --- | --- |
| Response differences need complete case context | `case_response_differences` | Execute the returned evidence command whose query ID ends with `case-response-differences-...-page-0`. |
| Case-scoped dependency evidence is dirty | `dirty_clusters` | Execute the returned evidence command whose query ID ends with `dirty-clusters`. |
| Startup, background refresh, or local-cache state may affect behavior | `source_process_traffic` | Execute the returned evidence command whose query ID ends with `source-process-traffic`. |
| Target startup or lifecycle failed | `target_runtime_diagnostics` | Execute the returned evidence command whose query ID ends with `target-runtime-diagnostics`. |

Always execute the exact opaque command returned by the current action or
evidence report. The suffixes above are discovery labels; never reconstruct a
query ID.

- `case_response_differences`: for a response issue, the first entry in the
  overview's `queries` returns one fixed-size page of every structured response difference in the
  representative case, including normalized Pointer patterns and explicit
  expected/actual value presence. A case that produced no usable target
  response assertion evidence appears as one `response_unavailable` difference
  at `$response`, not as zero response differences. Its optional
  `unavailable_reason` is an observed transport classification: for example,
  `target_connection_closed` proves that the target-side HTTP connection ended
  before a complete response, but does not by itself distinguish a panic from
  another target abort. Execute the first page before changing target code.
  When more differences are needed to distinguish a coherent cause, execute
  only the exact `facts.next_page.command`; never construct a cursor;
- `representatives`: the representative case ID, exact immutable standard or
  comparison `case_dir`, and bounded structured response or dependency
  difference; it does not prove the cause;
- `source_variation`: source values across recorded cases; variation alone
  does not prove nondeterminism or cache ownership;
- `collection_equivalence`: array multiset equality; equality does not prove
  that source order is irrelevant;
- `dependency_correlation`: response outcomes against dependency cleanliness;
  correlation does not prove response causality;
- `source_process_traffic`: recording-global, bounded source bootstrap and
  configured process-owned traffic grouped by protocol, endpoint, and
  operation, including Redis snapshot counts. Timing, frequency, and configured
  rule matches do not prove response causality or replace request-owned target
  behavior;
- `dirty_clusters`: case-scoped dirty events grouped by protocol and endpoint,
  with a stable `cluster_id`, bounded operation counts, an exact representative
  case, and a correlated source pre-readiness count. The complete
  recording-global source-process summary remains in `source_process_traffic`.
  It excludes `unused_global` and case-external target activity, and does not
  prove request or process ownership. For a dependency issue it also returns
  `applicable_rule_planners` only for supported protocols present in those
  clusters. Whenever a supported dependency-value rule exists for a protocol
  present in the clusters, it separately returns `rule_hints` with a short
  applicability hint and an exact read-only help command. Rule availability
  does not prove applicability. It also returns the selected case's exact
  `representative_dependencies_command` when available;
  MySQL supports source-proven process-owned SELECT templates with exact
  connection identity and exact, numeric-series, or patterned physical tables,
  including `AS {{table}}_id` aliases tied to the selected table. Return the
  source-proven selector inputs. Such rules can reclassify existing unused
  evidence without a new recording; target unmatched queries and incomplete
  evidence remain dirty.
- `policy_applicability`: structural rule eligibility; eligibility does not
  authorize a rule;
- `attempt_delta`: convergence against the previous attempt; improvement does
  not identify the cause.

Use the smallest query set that can distinguish the current hypotheses. Then
inspect the representative case and trace the corresponding source and target
path. Read other artifact cases only when the representative is insufficient.
Do not run every query merely because it is available.

### Supported Protocol Rules

Use this table only to discover a rule worth investigating. A listed rule does
not prove that the observed difference is safe to ignore.

| Problem stage | Protocol | Rule | Repairs |
| --- | --- | --- | --- |
| `dirty_clusters` with positive rejection-count evidence; source-proven `ip_capture` preflight | HTTP JSON | Response URL pointers | Capture later HTTP(S) calls to an IP obtained from an upstream JSON URL; requires source proof and fresh recording. |
| `dirty_clusters` during a response, Replay, or dependency issue | Memcached | `protobuf-timestamp` | A `SET` value mismatch where source proves that one selected top-level protobuf varint field is current Unix seconds; all other protobuf fields must remain equal, and each timestamp must be within the engine-owned fixed five-second window around its own `SET`. |

Run the exact `help` command returned with the rule before planning it. Add a
row only when the corresponding evidence hint, help command, planner, and
runtime behavior are all implemented.

Memcached `SET` exptime is not a protocol rule. Replay already keeps `0` and
relative expirations exact and compares absolute expirations by the remaining
TTL at each `SET`, with a fixed five-second tolerance. Do not plan a rule for an
exptime-only mismatch.

For dependency topology, execute the representative result's
`dependencies_command`, or the dirty-cluster result's
`representative_dependencies_command`. The compact summary groups by target and
returns one exact `detail_command` per target. Execute only the relevant target
detail before reading raw `dependencies.jsonl`; do not recreate this projection
with Python or shell parsing. The tool reads the recording internally; raw-file
inspection is only needed when omitted or truncated facts block the diagnosis.
The detail contains bounded representative MySQL
exchanges with SQL (up to 8192 bytes), typed parameters, database, username,
attribution, result status, row counts, column names, warnings, and an original
record locator. It omits row payloads and explicitly marks truncated previews
and omitted examples. Redis details preserve each key/argument/response
association, and Memcached details preserve key/outcome associations. A dependency response preview is at most 256 bytes
and carries its encoding, original length, and truncation state. Memcached flags
are intentionally neither interpreted nor returned. Complete small Redis scalar
responses also carry a decoded `response_value`; larger or structured responses
retain only their bounded frame preview.

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
- `comparison_counter`: source ownership and type prove a live counter that is
  valid only for comparison policy;
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

## Comparison Issues

For one representative comparison difference, distinguish:

- candidate-only stable difference: target behavior;
- source-before/source-after change at the same Pointer: source change or
  possible nondeterminism requiring source proof;
- proven generated scalar: concrete `timestamp`, `duration`, `uuid`, or
  `random` rule candidate;
- proven equal-content unordered array: unordered rule candidate;
- proven live numeric counter: comparison-only counter candidate;
- cache hit/miss/staleness/warmup: prove whether target behavior differs;
  response assertion rules cannot hide these differences. Recording-to-Replay
  time drift follows the explicit input/Redis response transformation path above.

JSON time rules support array Pointers such as `/data/*/generated_at`.
Timestamp plans require `--timestamp-format unix-seconds`, `unix-milliseconds`,
or `rfc3339`; each value must fall within five seconds of its own captured
request start. Duration plans require `--unit milliseconds`, `seconds`,
`minutes`, or `hours`; the duration increase must equal the request-start time
increase within five seconds. These rules validate parsed values, not just
JSON types, and cannot exempt complete time-derived signatures or URLs.

A target or response-policy change invalidates comparison evidence. Return your
result and end the turn; do not run replacement acceptance.

## Return The Proven Cause

Return one supported result with the original evidence/dispatch identity:

- Target API, cache, startup, or process-output generation defect: make one
  coherent repair, run focused tests, and complete [api-implementer-review.md](api-implementer-review.md).
- Supported nondeterminism/order/counter: return source proof and exact typed
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

End the turn after the result; do not wait for acceptance. If two repairs do not
improve the active issue, stop adding local patches and return a bounded
structural replan from the current issue and attempt delta.
