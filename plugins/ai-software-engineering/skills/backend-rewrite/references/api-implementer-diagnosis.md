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

## Contents

- Work-scope contract
- Process-output issues
- API evidence queries
- Rule discovery from source diagnosis
- Response, missing-recording, cache, runtime, and Replay issues
- MySQL driver and Redis connection compatibility
- Dirty dependency and comparison issues
- Return the proven cause and blocker criteria

## Work-Scope Contract

Start each worker turn by querying the exact assigned scope against the canonical
target root, even while editing a separate worktree:

```text
backend-rewrite --target-root <canonical-root> evidence --api '<METHOD pattern>'
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
representative when available. Treat possible causes as hypotheses.

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

The response, dependency, Replay, and comparison sections below apply only to
API work items. A process-output worker follows the next section and returns
after completing that diagnosis path.

## Rule Discovery From Source Diagnosis

For API issues, consult these capabilities after tracing source and target
behavior. Engine hints and mechanical candidates are additional evidence;
their absence does not mean a documented capability is unavailable.

| Proven scenario | Capability and next investigation |
| --- | --- |
| An inbound JWT in a Bearer header or named URL query parameter expired between capture and Replay | JWT `preserve_relative`; inspect the returned `jwt-time-validity` query and prove the exact token location, authentication path, expiry leeway, and signing-key source. |
| A DOCX download differs because OPC ZIP metadata and `docProps/core.xml` creation time are generated per request | DOCX response-body rule; prove the generated XML timestamp in source, select it explicitly, verify that its source-to-target delta tracks elapsed request time, and keep every other decompressed package part exact. |
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

## Process-Output Issues

For `work_scope.kind=process_output`, query `evidence --process-output <id>`
against the assigned canonical root after dispatch confirmation. The overview
has no API `queries`. Start from `facts.issue.comparison_observation`, which
identifies the process-output ID, configured path, classification, comparison contract, and source/target
presence. Do not look for an API representative or `case_dir`, execute API
evidence queries, inspect dependency traffic, or invent a recording operation.

For a missing metrics profile with source present and target absent, trace the
ordinary product output path:

```text
configured output -> component loading -> initialization -> startup -> write
or flush -> observation timing -> shutdown
```

Confirm the configured path and source-side presence from the overview, then
inspect the corresponding source and target component wiring.

When `comparison_observation.rule_candidate` names
`allow_target_missing`, first inspect the source startup/configuration and
indirect-emitter paths described by the candidate. The candidate is not an
allowance. Return its `metric`, a dependency path ordered from the direct
dependency to the indirect emitter, and one structured `emitter_evidence`
object only when source code does not start the interaction and the interaction
does not affect source behavior. `emitter_evidence.inspected_paths` must name
the source and dependency source paths actually read, and `description` must
explain why the indirect dependency emits independently without affecting
source behavior. Do not include boolean eligibility fields. If either
eligibility condition is not proven, do not return rule inputs; repair the
target's normal startup, configuration, output creation, flush, or shutdown
behavior.

Do not create a replay-only file, copy a recorded output into the target, or
make target code read engine artifacts.

For a target repair, return the exact work scope and issue ID, proven cause,
changed files and shared impact, patch or commit, local test results, original
dispatch identity, and unresolved risks. For an eligible rule candidate,
return the same work scope, issue and original dispatch identities plus the three
requested rule inputs and unresolved risks; no target patch or local test is
required. Do not apply rules or run process-output comparison yourself.

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

## Missing Recorded Dependency Evidence

Treat a recording omission as a bounded hypothesis when a response, Replay, or
comparison difference traces through source code to one exact response-driving
backend endpoint, but the representative recording contains no corresponding
dependency target or exchange. The absence alone is not proof of Breeze bypass,
an external-data blocker, or a Recorder capability gap.

Prove the hypothesis in this order:

1. Trace the differing response field or status through source construction,
   cache/loading lifecycle, and the exact dependency client call. Identify the
   source-proven hostname and port when source configuration proves one.
2. Execute the representative `dependencies_command`, inspect any potentially
   equivalent returned target detail, and read raw immutable dependency
   evidence only when the bounded projection cannot establish presence or
   absence. Do not infer omission from a truncated preview or one empty
   protocol cluster.
3. Exclude a target call-topology defect, a legitimate source cache/snapshot
   path that made no dependency call in the recording lifecycle, an equivalent
   endpoint recorded under another resolved target, and unsupported Replay of
   evidence that is actually present.

When those checks prove that the source consumes an exact response-driving
endpoint that is absent from recorded dependencies, return the evidence ID, the
`hostname[:port]`, and one single-line source file/symbol proof to the
workflow coordinator. The hostname is required and the port is optional; include a
source-proven port when available. Never guess a Breeze resource or descriptor.

A configured resource bypass is a capture-rule input, not proof that the
capture mechanism is unsupported. If returned feedback identifies an unknown,
ambiguous, or already captured endpoint, retain the source/recording proof and
error and continue diagnosis. Use `recorder-capability-gap` only when the
required capture mechanism itself is unsupported.

An extra read may result from an absolute timestamp in an earlier successfully
replayed response. Check [Rule Discovery From Source Diagnosis](#rule-discovery-from-source-diagnosis)
before treating that read as missing external data or a cross-case scope problem.
The selected response can belong to a previous case of the same API; the extra
request itself need not have a recorded counterpart.

## MySQL Driver Compatibility

For MySQL dependency mismatches, inspect these engine matching and session
contracts before changing target SQL or connection behavior. Workers use the
returned read-only evidence APIs and report any required engine or recording
transition to the workflow coordinator.

### SQL Matching

Replay supports source text SQL with inline literals and target prepared SQL
with `?` parameters. For ordinary single-table SELECTs it compares IN/NOT IN
lists without requiring the same value order, and accepts reordered pure AND
conditions and OR branches after binding actual values. Do not reproduce source set iteration
order or sort target inputs solely for Replay. Exact values, types, NULL and
duplicate counts remain constrained, as do tables, ordering and pagination.
Keep AND/OR nesting and each branch's field/value pairing; the engine does not
expand boolean expressions or treat independently matching columns as a match.
Large OR groups with a repeated parameter template use bounded linear metadata
matching. Empty strings remain values, distinct from NULL. `IS [NOT] TRUE`,
`IS [NOT] FALSE` and `IS [NOT] UNKNOWN` can accompany reordered conditions and
tuple IN lists; retain these operators instead of rewriting them as `= 1/0`.
The independent read-effect check also handles derived tables, UNION, ordinary
joins, EXISTS and pure ROW_NUMBER windows, including long OR chains. Successful
matching alone never makes unknown effects safe to omit at session cleanup.
This built-in compatibility composes with direct-column projection mapping;
it requires no rule or new recording. Complex expressions and positional
dynamic-parameter policies keep their existing boundaries.

Single-table `SELECT DISTINCT` also supports normal prepared statements, bound
parameters, column/table aliases, table qualifiers, and reordered pure AND
conditions and OR branches. Both sides must retain DISTINCT and the same complete set of direct
output columns. Do not force COM_QUERY, inline dynamic values, or reproduce
SQLAlchemy column labels to work around Replay. Column removal, aggregates,
grouping, and other complex query forms retain their existing constraints.

Flat tuple IN/NOT IN supports whole-tuple reordering for forms such as
`(user_id,namespace,name) IN ((?,?,?),(?,?,?))`, including source SQL built from
set iteration. Preserve each tuple's field order, paired values, types and
duplicate count; use normal bound parameters. A repair still needs the affected
immutable cases rerun; an engine revision change alone is not functional acceptance.

### Read-Only Session Cleanup

Keep ordinary read requests on the shared pool. Source ORMs may close an
implicit read-only session with ROLLBACK. The engine allows this cleanup to be
omitted when semantic recording proves a transaction-free start, consecutive
ordinary reads, and a successful transaction end; repeated cleanup after a
confirmed COMMIT/ROLLBACK is also optional. Omitted cleanup is reported as
`allowed_unused_mysql_rollback_exchanges`. No rule is needed.

Cold source connections may also send `SET AUTOCOMMIT=0/1` before business
queries. Replay handles literal session assignments and tracks the target
connection's mode. Proven read-only source-session setup can be omitted and is
reported as `allowed_unused_mysql_autocommit_exchanges`. Do not add AUTOCOMMIT
assignments to a shared target pool just to consume source-driver setup. No
rule or new recording is needed when existing evidence contains the required
transaction status. Write-containing sessions, failed assignments and incomplete
evidence remain strict; inspect the evidence and route an engine capability
gap if ordinary driver behavior is still blocked. Preserve real business
transaction boundaries.

Do not add `mysql.execute("ROLLBACK", ())` to the end of every handler merely
to consume recording evidence. A pool can route that command to another
connection. Missing status evidence in an older recording requires fresh
recording through the coordinator workflow; unexplained failures remain an
engine investigation. Writes, locks and explicit business transactions retain
their required rollback/commit behavior, even when HTTP responses agree.

## Redis Connection Pool Differences

Ordinary Redis GET/MGET and other supported data commands do not require the
target to reproduce source connection counts, pool sizes, or per-call client
creation. Replay matches across physical connections while preserving exact
endpoint, database, authentication identity, RESP version, arguments, source
lane order and finite exchange counts. Keep normal target connection reuse;
this capability needs no rule or fresh recording.

If ordinary reads fail only because one pooled target connection spans several
short recorded connections, investigate an old engine or a replay capability
gap. Do not change target code to create one Redis client per read or separate
pools solely to satisfy physical lane matching. Inspect the returned Redis
dependency details for true session constraints: a source lane containing
transactions, subscriptions, blocking operations, scripts or unknown commands
retains whole-lane binding, and its remaining exchanges cannot move to another
target connection. Authentication/database differences and missing, extra or
out-of-order calls remain target behavior issues when proven by source evidence.

## Rejected Egress And IP Capture Preflight

When response/dependency verification fails, the issue overview's
`facts.issue.egress_rejections` and `dirty_clusters` may report REJECT packet-count deltas and sampled time
windows. Treat these as investigation leads: they identify no IP or origin,
include retries/background traffic, and do not prove response causality. A null
count means the read or rule generation was unavailable, not zero rejections.
A clean passing run needs no investigation based only on these counters.

Follow `rule_hints[].help` to discover response URL rewriting. Trace the source
call and the missing dependency before submitting a system defect. Return the
current evidence ID, case ID, literal IP:port and source citation to the
coordinator. If feedback requests more origin proof, supply it. A source-proven
`http-response` origin may support a response URL capture rule; return matching
JSON selectors and source proof. Reassess any remaining engine defect against
the next assigned recording evidence. Static/hardcoded addresses require source
configuration or a source mock. Unknown origins require investigation; do not
invent a response pointer. A matching IP in recorded JSON alone does not prove
source consumption or the absence of an equivalent recorded endpoint.

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

Use `source_process_traffic` only to prioritize source startup schedulers,
background refreshers, and cache loaders for the returned endpoints. An absent
endpoint is not proof that no process-local cache exists, and a high interaction
count or configured process-owned match is not proof that the traffic populates
a response-driving cache.

When source and target implement the same cache semantics, but recorded absolute
time has aged between capture and Replay, inspect Redis `time-shift` above. It
preserves the original relative age in the engine's dependency-response copy and
lets the target build its normal cache. Preserve the original expiry threshold;
do not reset timestamps to now or suppress refresh to fit Replay.

Do not apply a generated-scalar assertion rule for a cold, missing, stale, differently keyed,
partially loaded, or differently refreshed cache. Do not materialize recorded
cache results as target fixtures or boot configuration. Repair the target cache
or its genuine dependency path and rerun the same immutable group.

## Target Runtime Issues

When no response assertion completed, inspect the bounded lifecycle error and
then the normal target boundary:

1. compile and launch path;
2. supplied boot/config roots and source-compatible loader, including declared
   static startup files and directories mounted read-only at their original
   absolute source paths from `.traffic-e2e/local/startup/mounts`; these runtime
   inputs may contain configuration required during startup or request
   handling;
3. configured port and readiness endpoint/status;
4. Replay CA trust and dependency client construction;
5. container identity, foreground process ownership, and bounded `SIGTERM`
   shutdown behavior; and
6. runtime-writable directories. When logs contain `Permission denied` or
   `EACCES`, follow [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md#writable-directories)
   for source proof and the affected image's directory contract.

Repair product startup, composition, configuration loading, or
`.traffic-e2e/Dockerfile.e2e`. Do not add case execution, report parsing,
Replay control, or expected-response access to the target repository.

## Replay Issues

`replay=incomplete` means the engine did not publish complete lifecycle
evidence. Use the returned issue and dirty-cluster query to distinguish:

- target never emitted the expected genuine dependency call;
- semantic dependency evidence exists but Replay cannot match or reproduce it;
- interception, readiness, begin/end, finalize, or cleanup failed;
- the recording lacks required semantic evidence.

For the last case, follow
[Missing Recorded Dependency Evidence](#missing-recorded-dependency-evidence)
before classifying a capability gap or external-data blocker.

If target topology differs, repair target behavior. If semantic evidence exists
but the engine lacks support, return the current evidence ID, source
reference, and exact required system change to the workflow coordinator. Never implement a target workaround for
a Replay capability gap or supply an arbitrary acceptance command.

## Dirty Dependency Issues

Inspect dirty dependencies whenever the engine returns `dirty_clusters`,
including while the active issue is a response mismatch. Response equality is
not a prerequisite for discovering a dependency-value rule. Continue to use
the gate order above when deciding which failure owns the next repair.
For HTTP request-body mismatches, inspect `http_unordered_candidates` and the
`unordered` hint. Same-request array reorderings may support
`dependency-rule plan http unordered`; prove source collection and downstream
semantics, then return the endpoint, JSON Pointer and source citation to the
coordinator. An HTTP JSON array is ordered by default. A response unordered
rule does not apply to dependency requests. Complete existing exchanges do not
require new recording evidence for this rule.

For HTTP `unmatched_target`, also inspect `cross_case_candidates` and the
`cross-case` hint. A verified same-run exchange may support a source-proven
shared initialization scope rule through the returned `http cross-case` planner.
Return the source proof and exact selector inputs. Shared initialization scope
is not background ownership or permission to ignore a request.

Classify the representative protocol cluster by source ownership:

- request-owned and required: repair target call topology or Replay support;
- process-owned and case-independent: use a supported process-owned recording
  rule; separately repair target state behavior when source and response
  evidence prove the dependency is response-driving;
- unresolved: retain the dirty evidence and name the missing proof.

Timing overlap, high volume, scheduler names, unused exchanges, asynchronous
execution, and passing responses do not prove process ownership. A
recording-rule proposal must use
the current dirty-cluster evidence ID and one protocol-specific planner returned
in `applicable_rule_planners`. Run its exact read-only help argv and return only
the source-proven selector inputs to the workflow coordinator. Replay evidence, case
source, and source revision come from engine state and are not rule
inputs. Return exactly one proven ownership classification:
`request-owned`, `process-owned`, or `unresolved`. A request-owned result requires
normal target implementation; it cannot justify a process-owned rule. Never
rewrite Replay reports, trim traffic, or edit immutable capture files.

For dependency value mismatches, inspect each entry returned in
`rule_hints`. Run its exact `help` command, then verify the described value
mechanism in source and in the representative dependency details before
planning it. In the currently supported Memcached case,
`protobuf-timestamp` applies only to a `SET` value whose selected top-level
protobuf varint field is source-proven current Unix seconds. The hint is a
discovery mechanism, not authorization to apply the rule.

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
