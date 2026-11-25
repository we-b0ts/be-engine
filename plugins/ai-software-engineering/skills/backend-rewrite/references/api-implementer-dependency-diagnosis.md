# API Implementer Dependency Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when
the evidence points to a missing recording, dependency mismatch, or protocol
compatibility issue. For a `session run` assignment, start with the Source
sequences returned by the coordinator.

## Source Session Dependency Failures

Start at the attempt's expected Source sequence and any retained Target
observation. Run the bounded `session events` query and correlate the
dependency's admission, output, and termination using `dependency_sequence`.
Use that admission sequence with `session dependency` for the protected Source
request and result. When the failure includes a Target observation, use
`session target` with the report from that same attempt. Follow the
[Source session evidence commands](session-regression.md).

Check the endpoint, request and protocol session first. Trace Source and Target
through the caller, including startup, detached work and shutdown. A request
may belong to a later recorded event and wait for the timeline to reach it.
Use the first failed sequence to locate the blocking event and inspect later
Source events for context. Those later events have yet to be verified in this
attempt. If the expected dependency never arrives, trace the preceding primary
input, delivered dependency output or Target wait that enables it. For a real
Target wait on that path, follow the
[session timer guidance](api-implementer-runtime-diagnosis.md#source-session-progress).

Startup and background I/O stay in the shared timeline with ingress traffic.
Report the Source sequences and the caller that explains the observed ordering,
including work that continues after the primary response. Session Replay loads
its dependencies directly from the sealed recording. The Case diagnostics below
use evidence returned for separate Case workflow assignments.

For suspected capture omission, trace the exact Source endpoint and the
runtime path that calls it. Check the relevant startup, ingress, and process
segments using the bounded timeline and protected dependency queries. When
the evidence establishes an omission, return the endpoint, Source file/symbol,
relevant sequences and the missing capture mechanism to the coordinator. When
the record is present but the provider cannot replay it, report that protocol
capability gap using the same evidence.

### Redis In A Source Session

Compare each recorded application command at its admission sequence. Check the
command, full arguments, preceding trigger, and corresponding reply or push at
its recorded delivery boundary. Each recorded application command has a finite
occurrence on the timeline. Trace generated times, IDs or tokens through the
calling code and check the
[current rule capabilities](api-implementer-rule-diagnosis.md).

Preserve production client and pooling behavior. Distinguish canonical Redis
connection maintenance handled by the protocol adapter from business commands.
Check endpoint, database, authentication identity and RESP version with the
recorded command. Retain transaction and subscription continuity, and correlate
a push with its recorded subscription and output sequence.

### MySQL In A Source Session

Use the recorded SQL, bound values, connection ID, query sequence and before
and after server-status flags. Trace each proven transaction through its
required statements and terminal event. Keep actual writes, locks, and
snapshot-changing controls on the correct transaction.

The adapter can exclude a proven SQLAlchemy/PyMySQL connection prelude and
specific idle cleanups. These exclusions use complete captured wire order,
session identity and transaction status, and appear as
`session_dependency_exclusions` in the Replay report. An ordinary business
read stays required even when its result matches an earlier call. Use the
engine's session evidence and production driver behavior before changing
transaction setup or adding cleanup SQL.

## Traffic ownership

For Case evidence, `dependency-attribution show --api <canonical-route>`
locates an unused Source occurrence. Report its Source UUID, the current
method evidence ID and the caller established by Source code. If only an
unmatched Target request is available, return that observation and state
what Source evidence is missing.

## Missing Recorded Dependency Evidence

For Source session assignments, use
[Source Session Dependency Failures](#source-session-dependency-failures).
For the Case workflow, investigate a possible omission when Source code
identifies a response-driving endpoint and the representative evidence has
no corresponding dependency target or exchange.

Check the exact path from the response to the dependency:

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
source-proven port when available.

Check whether an explicit `dns_mock.bypass_domains` entry matches the endpoint.
Use `recorder-capability-gap` only when the required capture mechanism itself is
unsupported.

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
This built-in compatibility composes with direct-column projection mapping.

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

This subsection covers the Case workflow. For the Source session, use
[MySQL In A Source Session](#mysql-in-a-source-session).

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

For MySQL `unused_recorded`, read `mysql_unused_diagnosis` and trace the
complete request, including authentication and helper calls. A commit or
rollback can invalidate loaded ORM state. Later attribute access, explicit
refresh or lazy loading may issue a required SELECT without an explicit
`get()` call. SQL aliases and LIMIT shape do not identify the
caller. Use connection/query locators and captured before/after server-status
flags in dependency details as bounded transaction facts, not ownership proof.
Use the Source call path to establish whether a business read is required.
Repair a required call through normal Target behavior.

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

Use these Case matching diagnostics when the assignment carries Case evidence.

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

For a Case workflow failure, inspect dependency evidence alongside any response
difference. Use the [gate order](api-implementer-diagnosis.md#interpret-the-failure)
and trace the complete Source caller and Target call path for each relevant
cluster. Return the original Case evidence ID and the concrete Source or Target
occurrence. For a candidate time, ID or token rule, verify generation and
consumption against the protected values and Source code before reporting it.
Follow the [rule diagnosis](api-implementer-rule-diagnosis.md).
