# API Implementer Dependency Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when
the current issue or evidence concerns missing recordings, dirty
dependencies, or MySQL/Redis compatibility. Use only the relevant
sections below; the [shared rule evidence contract](rule-policy.md) and the
common handoff contract still apply. Use current returned queries, capabilities
and planner commands; do not reconstruct commands from historical flag examples.

Also read the API-triggered traffic section when unused dependencies may come
from a source-detached API task.

## Traffic ownership

For a suspected foreign unused dependency, use
`dependency-attribution show --api <canonical-route>` to identify the concrete
unused Source occurrence. Return its exact Source UUID, current method evidence
ID and a bounded factual reason to the coordinator. This is sufficient to
request review. Proving exclusion, tracing the true trigger across Cases and
assessing its lifecycle rule are the independent repository analyst's work.
The coordinator submits the returned `claim_command` and dispatches the analyst.
For a suspected foreign request with only an unmatched Target observation, report
the exact observation and evidence IDs as unresolved ownership. The claim
requires an unused Source UUID from the current finalized attempt.

Your API owns the traffic you report as missing. Investigate its async lifecycle
and supply its own supported `async_api` rule when the work was captured in
another scope. Otherwise identify the exact recorder omission and repair inputs,
including fixed-IP interception or response IP-URL rewriting. Empty candidates
alone prove neither omission nor asynchronous ownership. Return the diagnosis to
the coordinator; only the coordinator publishes rules or investigation results.

## Missing Recorded Dependency Evidence

Claiming missing traffic gives this diagnosis an API owner. For an own async
scope gap, return the actual origin input, recorded occurrence IDs, supported
async lifecycle rule and positive Source ownership proof to the coordinator.
The coordinator can apply this known-owner proof through attribution before
resolving the investigation; it does not dispatch a repository analyst for it.
An async rule or investigation resolution alone cannot authorize another
Case's recorded dependencies. Missing origin or occurrence proof remains explicit.

After completing an own-API attribution analysis, also return the scenario's
end-rule assessment under `recording.async_api`, before independent optional
`recording.case_paths`; do not also emit the legacy root spelling.
Inspect its complete effective Case traffic, including newly
assigned occurrences, and propose missing end templates, necessary reply/message
conditions and counts from Case admission. Reuse already sufficient conditions.
Redis `when_response: {kind: nil}` selects native null; omitted/`any` accepts a
successful complete reply, while `when_message` selects PUBLISH request JSON.
Any end match can enter ending. Once all ends have matched, close admission
immediately and drain admitted requests, without a silence interval; a single end
follows this same rule. Partial matches permit a fixed one-second probe. A subsequent
relevant request start requires another fresh end before closure becomes eligible;
another one-second silence does not close the Case. Closure also requires no relevant
request in flight. Only unambiguously process-owned requests are ignored. There
is no absolute deadline while waiting for the first or next end after the
complete primary response. Without a fresh end, five continuous minutes of
relevant business I/O silence and no relevant request in flight close the Case
normally with completion unobserved, keeping Source running for rule analysis.
Real business activity restarts that interval; writer queues and definite process
traffic do not. The primary HTTP transport timeout remains separate; explicit
shutdown or actual capture failure can interrupt observation. Do not author timing settings,
all-of groups or an intermediate dependency list. Give this proposal to the
coordinator alongside the established proof; do not rerun ownership analysis
merely because plan/apply requires a fresh context.

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

Long SELECT projections can fill `sql_summary.preview` before the WHERE clause.
Read `sql_summary.select_body` and its independent `truncated` flag for the
outer FROM and following clauses; never infer an id lookup from the selected
column names. The bounded signature retains the original `index`,
`connection_id`, `query_sequence` and, for complete results, `row_count`.
Use those locators for complete semantic evidence when the excerpts are
insufficient. An omitted row count is unknown, not an empty result.

For repeated equivalent SQL, an unused Source occurrence does not identify the
missing Target call site: existing calls can consume earlier recorded copies.
Compare the complete Source occurrence count and actual Target calls, then trace
the missing Source position. Successful-detail arrays may be capped; absence
from that array alone does not establish a missing call or projection gap.

For MySQL `unused_recorded`, read `mysql_unused_diagnosis` before proposing a
rule or engine gap. Trace the complete request, including authentication and
helper calls. A commit or rollback can expire an ORM object; later attribute
access, explicit refresh or lazy loading may issue a required SELECT without
an explicit `get()` call. SQL aliases and LIMIT shape do not identify the
caller. Use connection/query locators and captured before/after server-status
flags in dependency details as bounded transaction facts, not ownership proof.
Equal rows, passing responses, empty candidates or empty planners do not make
a business read optional or establish an engine capability gap. Proven
request-owned reads require normal target implementation; retain unresolved
ownership when source proof is missing.

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
source task name and selector inputs under `process_dependencies`. Such
declarations can reclassify existing unused
evidence without a new recording; target unmatched queries and incomplete
evidence remain dirty.

Inspect dirty dependencies whenever the engine returns `dirty_clusters`,
including while the active issue is a response mismatch. Response equality is
not a prerequisite for discovering a dependency-value rule. Continue to use
the [gate order](api-implementer-diagnosis.md#work-scope-contract) when deciding
which failure owns the next repair.
For HTTP request-body mismatches, inspect `http_unordered_candidates` and the
`unordered` hint. Same-request array reorderings may support a global
`json.fields` unordered declaration; prove Source collection and downstream
semantics, then return the logical JSON Pointer and source citation to the
coordinator. This declaration applies across supported response and dependency
JSON carriers. An array remains ordered without that Source-proven declaration.
Submit the newly proven fields or formats; ordinary proposals add them while
preserving existing declarations and format order. Existing
complete exchanges need genuine Replay, not new recording evidence, for this change.

For HTTP `unmatched_target`, also inspect `cross_case_candidates` and the
`cross-case` hint. A verified same-run exchange may support a source-proven
`localcache.requests` declaration through the returned planner.
Return the source proof and exact selector inputs. Shared initialization scope
is not background ownership or permission to ignore a request.

Classify the representative protocol cluster by source ownership:

- request-owned and required: repair target call topology or Replay support;
- process-owned and case-independent: return the real Source task and supported
  `process_dependencies` declaration; separately repair target state behavior when source and response
  evidence prove the dependency is response-driving;
- unresolved: retain the dirty evidence and name the missing proof.

Timing overlap, high volume, scheduler names, unused exchanges, asynchronous
execution, and passing responses do not prove process ownership. A
recording-rule proposal must use
the current dirty-cluster evidence ID and one protocol-specific planner returned
in `applicable_rule_planners`. Run its exact read-only help argv and return only
the source-proven selector inputs to the workflow coordinator. Replay evidence, case
source, and immutable Source revision come from engine state; do not invent them
or replace the provided identity. Diagnose the behavior of the known owner. Route
disputed ownership through [traffic ownership](#traffic-ownership). A request-owned
result requires normal target implementation; it cannot justify a process-owned rule. Never
rewrite Replay reports, trim traffic, or edit immutable capture files.

For dependency value mismatches, inspect each entry returned in
`rule_hints`. Run its exact `help` command, then verify the described value
mechanism in source and in the representative dependency details before
planning it. For Memcached, inspect the returned operation, encoding and typed
capability before proposing a format. A protocol name or byte pattern alone
does not establish a supported schema; unknown encodings stay exact. The hint
is discovery guidance, not authorization to apply a rule.

## API-triggered asynchronous process traffic

A source-proven detached API task may produce unused dependencies inside another
API's recording window. Redis GET, single-key DEL and LRANGE can use
a self-contained `process_owned` rule with explicit API origin and the unified
proposal transaction returned by the engine under the [shared contract](rule-policy.md).
See [API-origin process rules](../../../../../docs/api-triggered-process-traffic.md).
The native `effect.origin.request_body` selects typed scalars by JSON Pointer in the
triggering inbound REQUEST BODY: `/background: true` means JSON
`{"background":true}`, never URL query, response JSON, or the victim API's body.
Trace spawning and cleanup in source, then supply one explicit successful
COM_QUERY INSERT identity capture and exact Redis key template/arguments. A shared
ID or unused exchange is not source ownership proof. Trigger/resource API calls,
ambiguous origins/references and target failures remain strict. Complete old
recordings are reusable; the engine caches correlation outside immutable evidence.
Status performs no origin scan or cache build. This rule does not verify the
background task's eventual result or enable reusable Redis snapshots.

MySQL API-origin SELECT rules use a typed `process_owned` effect with inline
origin and `identity_value_index`. The zero-based template `?` slot must be an
identity equality or singleton IN predicate; other endpoint/table/SQL bounds
remain exact. Use the same origin capture as related Redis rules. An ordinary
same-name rule is not API-origin proof. A scope change requires the engine's
explicit replacement proposal and complete preflight. Do not classify every
SELECT on a task table as background.

When a helper has polling/cancel callers, also trace indirect detached-task
callers such as terminal result collectors and accumulated-content helpers.
Protect direct inbound polling/cancel requests; a task reacting to cancellation
in its own detached lifecycle can still produce process-owned dependencies.
Plan proves recording correlation and scope, while source evidence proves
caller ownership.

API-origin Redis DEL accepts an exact ordered `key_sequence` in its typed
selector; every key must bind the same captured identity.
For EVALSHA, the typed `script` contract declares an exact SHA-1, ordered KEYS envelope,
ARGV count and `identity_argv_index`. Date-keyed metrics may still carry the task
ID in ARGV. SCRIPT EXISTS requires a proven adjacent same-connection invocation.

API-origin MySQL also supports bounded single-row UPDATEs. Complete transaction
boundaries require `include_transaction_boundaries`, consistent wire sequences
and server flags. Typed `transaction_members` can admit explicit read-only helper
selectors only inside a fully proven transaction. Ordinary write rules, broad
COMMIT/ROLLBACK exceptions and standalone member matches remain unsupported.
Inspect actual dirty summaries: source-recorded ROLLBACKs may already be optional
cleanup and do not by themselves establish a missing capability.
