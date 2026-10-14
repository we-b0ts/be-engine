# API Implementer Dependency Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when
the current issue or evidence concerns missing recordings, dirty
dependencies, or MySQL/Redis compatibility. Use only the relevant
sections below; the common evidence and handoff contracts still apply.

Also read the API-triggered traffic section when unused dependencies may come
from a source-detached API task.

## Missing Recorded Dependency Evidence

Treat a recording omission as a bounded hypothesis when a response or Replay difference traces through source code to one exact response-driving
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
replayed response. Check [Rule Discovery From Source Diagnosis](api-implementer-diagnosis.md#rule-discovery-from-source-diagnosis)
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

## Dirty Dependency Issues

MySQL supports source-proven process-owned SELECT templates with exact
connection identity and exact, numeric-series, or patterned physical tables,
including `AS {{table}}_id` aliases tied to the selected table. Return the
source-proven selector inputs. Such rules can reclassify existing unused
evidence without a new recording; target unmatched queries and incomplete
evidence remain dirty.

Inspect dirty dependencies whenever the engine returns `dirty_clusters`,
including while the active issue is a response mismatch. Response equality is
not a prerequisite for discovering a dependency-value rule. Continue to use
the [gate order](api-implementer-diagnosis.md#work-scope-contract) when deciding
which failure owns the next repair.
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

## API-triggered asynchronous process traffic

A source-proven detached API task may produce unused dependencies inside another
API's recording window. Redis GET, single-key DEL and LRANGE can use
`dependency-rule plan redis api-triggered` and the existing apply transaction.
See [API-origin process rules](../../../../../docs/api-triggered-process-traffic.md).
`trigger_source.request_body_json` selects typed scalars by JSON Pointer in the
triggering inbound REQUEST BODY: `/background: true` means JSON
`{"background":true}`, never URL query, response JSON, or the victim API's body.
Trace spawning and cleanup in source, then supply one explicit successful
COM_QUERY INSERT identity capture and exact Redis key template/arguments. A shared
ID or unused exchange is not source ownership proof. Trigger/resource API calls,
ambiguous origins/references and target failures remain strict. Complete old
recordings are reusable; the engine caches correlation outside immutable evidence.
Status performs no origin scan or cache build. This rule does not verify the
background task's eventual result or enable reusable Redis snapshots.

MySQL API-origin SELECT rules use `dependency-rule plan mysql --trigger-source
JSON --identity-value-index N`. The zero-based template `?` slot must be an
identity equality or singleton IN predicate; other endpoint/table/SQL bounds
remain exact. Use the same origin capture as related Redis rules. An ordinary
same-name, exact-selector rule may be narrowed through plan/apply, never reused
as API-origin proof. Do not classify every SELECT on a task table as background.

When a helper has polling/cancel callers, also trace indirect detached-task
callers such as terminal result collectors and accumulated-content helpers.
Protect direct inbound polling/cancel requests; a task reacting to cancellation
in its own detached lifecycle can still produce process-owned dependencies.
Plan proves recording correlation and scope, while source evidence proves
caller ownership.

API-origin Redis DEL accepts an exact ordered `key_sequence` through repeated
`--key-sequence-template`; every key must bind the same captured identity.
For EVALSHA, `--script JSON` declares an exact SHA-1, ordered KEYS envelope,
ARGV count and `identity_argv_index`. Date-keyed metrics may still carry the task
ID in ARGV. SCRIPT EXISTS requires a proven adjacent same-connection invocation.

API-origin MySQL also supports bounded single-row UPDATEs. Complete transaction
boundaries require `--include-transaction-boundaries`, consistent wire sequences
and server flags. `--transaction-member JSON` can admit explicit read-only helper
selectors only inside a fully proven transaction. Ordinary write rules, broad
COMMIT/ROLLBACK exceptions and standalone member matches remain unsupported.
Inspect actual dirty summaries: source-recorded ROLLBACKs may already be optional
cleanup and do not by themselves establish a missing capability.
