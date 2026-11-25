# Traffic E2E Dependency Replay Contract

Read this reference when wiring or diagnosing case-owned dependency behavior.

## Genuine Target Calls

Recorded E2E MUST execute the target's genuine dependency interfaces,
production adapters, and real protocol clients. Intercept or explicitly route
their emitted traffic to recorder-owned replay listeners. Do not reach
production resources, and do not replace dependency calls with project-local
fixtures, fakes, in-process mocks, or recording-backed implementations.

Only recorder-owned replay consumes case or Global dependency JSONL. Under the
standard version-two runner contract, the system HTTP driver constructs the
inbound request from `request.json` and writes the actual-response artifact.
The target MUST NOT read case files or `expected-response.json`; the runner
alone reads them for final assertions.

## Request And Touch Contract

Build every inbound request from its case `request.json`, including method, URI
and query, applicable headers, and body. Remove only transport headers the
harness must regenerate. Do not hardcode case-specific auth, tenant, query, body,
or cookie values in target tests.

A typed `input_jwt` effect in `project.policy` may translate Source request
NumericDates using the resolved startup key. It does not consume expected
responses or dependency results. See [unified rules](replay-policy.md).

Treat recorder dependency summaries and final replay reports as the acceptance
evidence for case-owned touches. Equivalent target behavior must preserve the
dependency role, compatible operation and input, ordering or state when
relevant, response or error semantics, and required side effects. Different
source code or harmless protocol formatting does not by itself imply a mismatch.

Classify ambiguous dependencies only from source ownership, bootstrap timing,
recorder metadata, or replay evidence. Required side effects remain required.
For Source-proven process work, use
`process_dependencies.tasks.<actual-Source-task-name>.requests`; one task can
group requests from several protocols. HTTP entries require a host, method
and path scope. Finite initialization reads belong to `localcache.requests`.
Preserve original recording provenance and validate changes against the
affected evidence. Unmatched Target calls and unsupported exchanges remain dirty.

## Coverage

Completion requires no unexplained unmatched Target calls, unused case
exchanges, unsupported/unsafe operations or missing required side effects.
Global JSON, scalar and header formats change selected value comparisons only;
actual endpoint/database/authentication/protocol pairing and finite consumption
remain checked. Headers, including SDK metadata, retain strict presence and
multiplicity. A lifetime declaration does not certify Target cache behavior or
implement initial loading, refresh, fallback or readiness. HTTP response
compatibility alone is insufficient.

Use `dependencies-summary.json`, when present, as a human and agent checklist;
do not make target project code parse it to decide behavior or manufacture
completion. Use `dependencies-debug.jsonl` only to explain missing semantic
capture or protocol failures, never as the primary replay source.

## Protocol Evidence

For MySQL, match semantic exchanges by the business target host and port,
database or schema, and username or role before normalized SQL and parsed
parameters. Preserve transaction, lock, repeated-call, and session order when
required. Use semantic column metadata for schema evidence; missing SQL,
prepared parameters, column schema, or untruncated rows is a recording risk.
Single-table direct-column SELECTs can use different selected columns, order,
column aliases and table aliases when every target field maps unambiguously to
recorded data. Replay projects response metadata and cells together; it does not
require an ownership rule or new recording. COUNT(*) and integer constants keep
their expression identity. Physical tables, predicates, values, sorting and
pagination remain constrained. DISTINCT permits aliases and column reordering
only when both queries retain the same complete direct-column projection; it
never permits dropping/adding columns or switching to ordinary SELECT. Grouping,
subqueries, locks, wildcards and other expressions retain strict matching. JOIN
queries do not gain projection adaptation; their pure WHERE predicates may use
the compatibility below only when the projection and complete JOIN envelope
remain exact. See
[MySQL interoperability](../../../../../docs/mysql-replay.md) for the exact
boundary and actual-client acceptance tests.

Generated MySQL write timestamps use the native `mysql_values` effect in the
unified policy. Text and prepared requests share typed slots and complete SQL
remainder checks. Scalar/JSON write times default to their own dependency request
start, with independent Source/Target clocks and the unchanged five-second bound.
Statements support up to 1 MiB/16,384 tokens; large literals do not enter the SQL
cache, and identity bindings do not lower the parsing limit. Native parameters, generated bindings, JSON/PB values and
result time columns compose through their explicit owners. Verify the schema
from Source and validate supported policy changes with genuine Replay. Database
error propagation remains part of Target behavior.

Ordinary single-table SELECT predicates also support reordered IN/NOT IN values
and pure AND conditions / OR branches, including source text literals versus
target bound `?` parameters. Direct-table JOIN SELECTs use the same pure
predicate compatibility only when their projection, FROM/JOIN/ON clauses,
sorting and pagination remain exact. Values, types, NULL and duplicate counts
stay exact. This built-in compatibility needs no rule or new recording and does
not require target to reproduce source collection order. For single-table
queries it composes with direct-column mapping; an unchanged wildcard projection
can use predicate compatibility as well.
Complex predicates and positional dynamic parameter rules retain their existing
constraints. Parsed templates and constant queries are cached within Replay;
actual values and finite dependency availability are checked for each execution.
Large OR groups with identical parameter templates use linear PREPARE matching
within the SQL/work limits. Boolean tests `IS [NOT] TRUE/FALSE/UNKNOWN` retain
their semantics and can compose with tuple IN reordering. Neither support
requires target to change its normal SQL parameter binding.

A narrow complex-predicate fallback permits the same scalar/flat-tuple list
reordering inside correlated `EXISTS` subqueries that participate in an `OR`
branch, direct-table JOIN chains, and derived `SELECT count(*) FROM (SELECT ...)`
wrappers. The complete AST outside eligible lists stays exact, including
functions, JSON paths, projections, tables, correlations, operators, boolean
structure, JOIN conditions, sorting, pagination and non-list values. Unsupported
subquery forms remain strict.

A separate bounded full-query fallback permits the same list reordering inside
supported `UNION ALL` read trees, including JOIN predicates, derived tables,
inline window expressions, and computed projections. It retains exact UNION
branch order, JOIN conditions, every non-list expression, sorting, pagination,
types, NULL positions, and duplicate counts. UNION DISTINCT, other set
operations, locks, writes, CTEs, and unsupported subquery forms remain strict.

Flat tuple IN/NOT IN also permits whole-row reordering, including
`(user_id,namespace,name) IN ((?,?,?),(?,?,?))` versus source text literals.
Column order, tuple width, component values/types, NULL positions, value pairing
and duplicate counts stay strict. PREPARE supports bounded partial-row matching;
each execution binds fresh values before comparison. Source set iteration order
does not need to be reproduced by target. This Replay compatibility reuses
existing immutable recordings and needs no rule.

MySQL session cleanup can appear as `allowed_unused_mysql_rollback_exchanges`.
Replay allows a successful duplicate ROLLBACK after a confirmed transaction end,
and a first ROLLBACK after a proven implicit read-only span. The latter requires
captured before/after transaction status, a known inactive start, consecutive
ordinary SELECTs and successful transaction completion on the same connection
and identity. Read-effect checks cover derived tables, UNION, joins, EXISTS and
pure ROW_NUMBER windows by checking every child, independently of SQL matching;
long OR chains do not lose their read proof solely because of expression width.
Writes and locks do not qualify for this read-only proof; explicit BEGIN itself
remains required. Unknown starts and incomplete evidence remain strict.
Older recordings lacking query status evidence require
re-recording; do not infer eligibility from SELECT summaries or read debug JSONL
as the replay source. Optional cleanup stays matchable, and all business reads
remain required. A matching HTTP response alone cannot justify omitting rollback.

MySQL AUTOCOMMIT assignments are handled as connection state by Replay. A target
can use its normal driver mode; do not add SET AUTOCOMMIT merely to consume cold
source-connection initialization. With complete read-only session evidence,
omitted setup appears as `allowed_unused_mysql_autocommit_exchanges` and stays
matchable. Both 0 and 1 are retained during recording; failed controls,
unknown transaction starts and incomplete spans remain strict. Initial gaps
caused by omitted setup may be crossed only before the first read and with
consistent inactive status; unknown gaps inside a transaction never establish
proof.
New recordings retain complete COM_PING exchanges in semantic JSONL for sequence
continuity; unchanged-status, zero-effect PINGs do not break a read-only span and
are not required business exchanges. Older recordings with omitted post-read
PINGs need fresh recording rather than an inferred explanation for their gaps.
No rule or new recording is needed when the immutable capture already has the
required status evidence. This does not verify transaction isolation equivalence.

Write-containing implicit Source sessions use first-write-through-end
compatibility by default, without a configuration switch. A driver
`SET autocommit=0` is connection mode, not an explicit BEGIN. For each complete
ordinary Source transaction:

- One business write followed by successful COMMIT can omit that end when the
  corresponding Target delivery independently proves autocommit 1 with no active
  transaction before and after the write.
- Exactly one ordinary UPDATE followed by successful ROLLBACK can use the same
  Target witness only if Source's UPDATE returned an error or succeeded with
  known `affected_rows: 0`. Delivery of that recorded response must succeed.
  This is bounded compatibility, not proof about arbitrary trigger effects or
  the application's conditional branch. Positive-row UPDATE then ROLLBACK
  retains the transaction requirement; a zero-row UPDATE still counts as a write.
- Two or more writes, and write-containing ROLLBACK outside that exception,
  require one Target transaction from the first write through the matching end,
  including every intervening and trailing read. Ordinary SQLx transactions or
  a project's `with_transaction` wrapper provide this boundary. Prefix ordinary
  reads may use the normal read route outside it; every business SQL remains a
  finite required dependency.

Explicit Source BEGIN and locking or unclassified effects retain the full
Source boundary. Failed transaction controls never become optional. Successful
no-write cleanup retains its independent Source read-only/inactive proof.
Extra cleanup cannot replace the required business end or select another
socket's identical COMMIT/ROLLBACK.

Complete ordinary Global reads may supply Source-only continuity evidence for
a Case's already established implicit Source span before its first write. Each
missing sequence in its active gap must have one complete original Global read
on the same connection and identity with continuous transaction status. These
facts do not consume or reassign Global exchanges, change endpoints, or provide
a Target witness. Unknown or duplicate
sequences, writes, locks, unsupported effects, missing status and any gap after
the first write remain strict. A later independently known inactive start can
establish a separate complete transaction; it does not repair the rejected
earlier span or justify omitting connection setup over incomplete evidence.

All affected complete Source transactions in the loaded scope need their own
successful Target delivery witnesses before the SET becomes optional. Replay
retains the original SET and reports covered setup separately in
`transaction_equivalent_mysql_autocommit_exchanges`; reports identify the
default as `mysql_transaction_semantics: first_write_through_end_v1`.
Unconsumed setup/end summaries and transaction violations carry bounded
`mysql_autocommit_transaction_coverage` diagnostics. Resolve an incomplete Source proof using its
failure/missing query sequences first, then compare the proven write interval,
actual Target status and missing members. An unproven interval or absent
historical witness does not establish a write count or missing Target BEGIN.
For a proven required interval, split/merged transactions, an early end before
trailing reads, mismatched outcomes and a pooled standalone end remain strict.
Do not copy a driver SET, wrap prefix reads solely for Replay, skip an API or
use a value rule to hide transaction membership failures. Passing HTTP responses
and historical reports cannot establish fresh Target coverage or an engine gap.

For Redis and Memcached, preserve connection-lane ordering and protocol
semantics. Unmatched, unsupported, unsafe, and unused evidence remains dirty.
Ordinary Redis data commands support different source/target pool widths and
connection lifetimes by default, while retaining exact endpoint, database,
username, RESP version, command and arguments. A target connection may consume
several recorded source lanes; several target connections may consume one lane
in order. Each ordinary exchange is still consumed once. Source lanes with
retained session commands, transactions, subscriptions, blocking operations,
SCRIPT DEBUG or unknown commands/subcommands remain bound in their entirety to
one target connection per active case. Another target connection cannot consume their
remaining exchanges. Diagnose these session constraints before changing target
pooling; do not reproduce short source connections for ordinary GET/MGET calls.

EVAL/EVALSHA and their read-only variants, plus SCRIPT LOAD/EXISTS/FLUSH/KILL/HELP,
do not require connection binding by themselves. Their script cache belongs to
the Redis server. Replay preserves exact script identity, session/endpoint
scope, lock-token correlation and finite source-lane order, including recorded
NOSCRIPT failures followed by script loading and retries. A retained stateful
operation in the same lane still binds all of its exchanges.

Redis RESP2 `SUBSCRIBE`, `PSUBSCRIBE`, `SSUBSCRIBE`, `UNSUBSCRIBE`,
`PUNSUBSCRIBE`, and `SUNSUBSCRIBE` evidence is replayable only when one command
argument produced one exact three-element confirmation (or an ordinary Redis
error). Command and binary-safe subject must match; subscription counts must be
positive, and unsubscription counts may be zero. Successful unsubscription removes
only the confirmed channel, pattern, or shard channel; errors leave state intact.
Replay returns that recorded confirmation and leaves the connection open, with
the entire source lane still bound to one target connection. Recorder forwards a
subsequent well-formed RESP2 `message`, `pmessage`, or `smessage` only when its
channel or pattern matches the active subscription. Confirmed pushes become
finite semantic evidence: ordinary notifications remain Global process inputs,
while an RPC adapter can retain exact request ownership across connections.
Replay schedules captured pushes only for a matching confirmed subscription.
The Socket.IO Redis-adapter JSON RPC adapter translates publisher UUIDs and
callback counters while retaining exact command/result semantics. Missing or
inconsistent ACK evidence requires a refreshed recording. See
[Redis Pub/Sub](../../../../../docs/redis-pubsub.md).
Malformed or unbound pushes remain dirty. Multiple subject arguments,
no-argument unsubscribe-all commands, and RESP3 push frames remain unsupported.
Cases rejected by an older Recorder for unsubscription need a new recording;
never change the existing evidence or its `replay_safe` flag.

Explicit `redis_sequence` key capture/reference supports single-subject SUBSCRIBE
and UNSUBSCRIBE, translating only the confirmed subject after admission. LPUSH
and RPUSH JSON slots support independent canonical UUIDs and bounded nonempty
strings, while task ID fields retain explicit capture/reference relationships.
RPC PUBLISH composes selected time/URL contracts with protocol identity copies;
unselected application fields, ACK correlation and finite consumption stay strict.
See [Generated Redis request values](../../../../../docs/redis-generated-requests.md)
for exact vocabulary, query-date relationships and the signature-shape boundary.

Match Case evidence before run-level Global evidence. Consume ordinary
exchanges once. A marked Redis background cache-snapshot seed is the narrow
exception: Replay may return its first successful recorded response for every
identical logical read. Replay may also mark one old `bootstrap_window` Global
exchange in memory when the current Redis rule has complete configured-key
coverage and all matching Global and Case responses for the same exact logical
identity agree. This derived overlay never edits recording files and is
rejected as a whole on unsafe, truncated, failed, conflicting, or ambiguous
evidence. Other unmarked Redis, Memcached, HTTP, MySQL, Kafka, and Motan evidence
remains finite inventory. The target must issue genuine dependency calls and
build its own local state from replayed responses.

Explicit Redis `time-shift` rules translate selected timestamps in matched
GET/HGET JSON response copies by send time minus captured response time. They
preserve relative age, original invalidity and finite consumption. Source
diagnosis selects fields; Replay generates no speculative hints. See
[Redis response time rules](../../../../../docs/redis-time-shift-rules.md).

A legacy, Case-local `tcp_gateway_connection` with no recorded error and zero
bytes in both directions is finite evidence for one dependency connection that
returned no bytes. Only after normal HTTP exchange matching fails, Replay may
consume one such record for the same normalized `domain:port`, fully read the
target request, write no response bytes, and wait for the target to close the
connection. Do not reproduce the recorded connection duration as a server-side
timeout, and do not emit unmatched-request evidence for the claimed call.
Global/bootstrap connection records never authorize this behavior. If neither
an exchange nor a matching Case-local zero-byte record exists, preserve the
ordinary immediate HTTP 502 and unmatched evidence.

For ordinary MySQL, Redis, Memcached, and Kafka Produce/Fetch responses, preserve
the recorded semantic exchange `duration_ms` because callers may enforce
aggregate deadlines, retry budgets, or races above the protocol client. In Fast
mode, MySQL and Redis skip recorded response delays below 10 ms. For a recorded
`client_terminated` outcome, send zero response bytes and wait for EOF, FIN, or
RST on that same connection. Consume the exchange only after the client
termination arrives in the recorded timing window. Replay must not proactively
close the connection to manufacture the outcome; the watchdog may mark replay
dirty and release test resources only after the client fails to terminate.

For Kafka, use the recorder-supported client profile and semantic produce,
fetch, and delivery evidence. Match stable topic, key, headers, and value
semantics, preserve Fetch-to-delivery association, and reserve an exchange
until its delayed response is delivered or its expected client termination is
observed. Transactions, authentication, compression, unsupported APIs, unsafe
captures, or broker errors remain unsupported evidence unless the recorder
explicitly supports them. Return the corresponding capability
`action_required`; the artifact condition does not determine the handoff
status.

For other dependency types, require recorder-supported semantic input, output,
ordering, and error evidence. Do not synthesize downstream HTTP payloads, cache
values, queue messages, rows, or side effects from the expected response.

HTTP(S) `http_exchange` records with `outcome: client_terminated` carry a
complete request and integer `duration_ms`, with no response or capture error.
Replay sends zero response bytes and consumes the exchange only after the
actual client EOF/reset, within 50ms before through 1000ms after the recorded
duration. Early, late, or absent termination remains dirty. Recorder shutdown
is not client-timeout evidence, and a call-level timeout that leaves its
connection open is unsupported. This support does not reconstruct HTTP
requests missing from a historical recording.

## Metrics

Treat recorded push metrics as dependency side effects and validate them through
replay when supported. Validate pull metrics through the target exporter or
scrape surface. Do not write recorded metric payloads from target fixtures. If
metrics evidence is absent or unsupported, report the recorder gap or obtain
explicit approval for a behavior-contract change.

HTTP response URL rewrite records contain discovered synthetic host/fake-IP
routes alongside the rewritten JSON. Replay reserves those fake IPs and uses
recorded subsequent HTTP(S) exchanges; configuring a new capture rule cannot
synthesize missing historical exchanges. Rejection packet counts are auxiliary
context for failures and never count as semantic dependency mismatches.

## HTTP Request JSON Ordering

HTTP request JSON objects compare by value; arrays remain ordered unless a
`dependency.request` body contract selects a pointer with `kind: unordered`.
The same JSON/PB contract works in other supported value slots. Source proof
must justify order independence; the comparator retains duplicates, types,
query/header identity and every unselected field. See [unified rules](replay-policy.md).

## Explicit Cross-Case HTTP Scope

A typed `finite_sharing` rule may make
source-proven shared initialization exchanges available across APIs in the same
completed standard recording. The scope is derived in memory and exchanges
remain single-use per session. Query, body and identity headers stay strict;
this is not a background-ownership rule or an unmatched-request allowance.
See [HTTP cross-case replay](../../../../../docs/http-cross-case-replay.md).

Redis whole-string writes (`SET`, `SETNX`, `SETEX`, `PSETEX`) detect JSON and
Protobuf value encoding. JSON object keys compare independent of order; explicit
unordered rules for JSON arrays and Protobuf repeated fields require the same
Source proof as HTTP. Key patterns select rule scope, while key bytes, TTL/options
and source lanes stay exact. See
[Redis value rules](../../../../../docs/redis-value-rules.md).

Source-proven SET NX ownership tokens can use a `redis.lock` dependency rule.
Token-only mismatch witnesses require explicit host, port, and key scope.
Source recorded equality identifies single-key EVAL/EVALSHA/DELEX references.
The rule correlates opaque tokens without UUID or script SHA configuration,
retains other arguments and finite consumption, and requires fresh Replay.
It does not interpret Lua or emulate lock contention/expiry. See
[Redis scalar formats](../../../../../docs/redis-scalar-formats.md).
