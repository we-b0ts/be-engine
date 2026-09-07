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

An explicit `verification.yaml` `request_rules.jwt` policy may translate
verified HMAC JWT time claims in the engine's per-send request copy. This is
an exception only to exact credential-byte reuse: original recording files,
identity/permission claims, target authentication behavior and all dependency
checks remain intact. See [JWT request rules](../../../../../docs/jwt-request-rules.md)
for evidence-backed plan/apply and reexecution without new standard recording.

Treat recorder dependency summaries and final replay reports as the acceptance
evidence for case-owned touches. Equivalent target behavior must preserve the
dependency role, compatible operation and input, ordering or state when
relevant, response or error semantics, and required side effects. Different
source code or harmless protocol formatting does not by itself imply a mismatch.

Classify ambiguous dependencies only from source ownership, bootstrap timing,
recorder metadata, or replay evidence. Required side effects remain required.
For source-proven API-independent HTTP work, use the guarded narrow background
workflow and re-record; existing dirty cases are never retroactively
reclassified. `allowed_unused_http_hosts` remains a host-wide compatibility
exception for older recordings. Target calls that are neither matched by an
exchange nor claimed by the narrow zero-byte TCP behavior below remain dirty.
Unsupported exchanges always remain dirty.

## Coverage

Completion requires no unexplained unmatched target calls, unused case
exchanges, unsupported or unsafe dependency operations, or missing required
side effects. `allowed_unused_case_http_exchanges` are acceptable only when the
report also records the source-controlled recorder config, named recording
rule, and exact configured host. HTTP response compatibility alone is
insufficient.

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
never permits dropping/adding columns or switching to ordinary SELECT. Grouping, joins, subqueries, locks,
wildcards and other expressions retain strict matching. See
[MySQL interoperability](../../../../../docs/mysql-replay.md) for the exact
boundary and actual-client acceptance tests.

Generated MySQL write timestamps can use explicit `mysql.sql_values` time rules
across text and prepared protocols. Rules select database and SQL, independently
of inbound API paths; `sql_values: {0: {time: replay_now, tolerance: 5s}}` uses
UTC MySQL datetime defaults. The coordinator exposes
`dependency-rule plan mysql-time`; it requires source proof and matching immutable
write evidence, then reruns Replay without new recording or write omission.
See [SQL time rules](../../../../../docs/mysql-time-rules.md). Preserve database
error propagation in target code; swallowing an unmatched UPDATE is not a fix.

Ordinary single-table SELECT predicates also support reordered IN/NOT IN values
and pure AND conditions / OR branches, including source text literals versus target bound `?`
parameters. Values, types, NULL and duplicate counts stay exact. This built-in
compatibility needs no rule or new recording and does not require target to
reproduce source collection order. It composes with direct-column mapping;
an unchanged wildcard projection can use predicate compatibility as well.
Complex predicates and positional dynamic parameter rules retain their existing
constraints. Parsed templates and constant queries are cached within Replay;
actual values and finite dependency availability are checked for each execution.
Large OR groups with identical parameter templates use linear PREPARE matching
within the SQL/work limits. Boolean tests `IS [NOT] TRUE/FALSE/UNKNOWN` retain
their semantics and can compose with tuple IN reordering. Neither support
requires target to change its normal SQL parameter binding.

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
Writes, locks, explicit transactions, unknown starts and incomplete
evidence remain strict. Older recordings lacking query status evidence require
re-recording; do not infer eligibility from SELECT summaries or read debug JSONL
as the replay source. Optional cleanup stays matchable, and all business reads
remain required. A matching HTTP response alone cannot justify omitting rollback.

MySQL AUTOCOMMIT assignments are handled as connection state by Replay. A target
can use its normal driver mode; do not add SET AUTOCOMMIT merely to consume cold
source-connection initialization. With complete read-only session evidence,
omitted setup appears as `allowed_unused_mysql_autocommit_exchanges` and stays
matchable. Both 0 and 1 are retained during recording; writes, failed controls,
unknown transaction starts and incomplete spans remain strict. Initial gaps
caused by omitted setup may be crossed only before the first read and with
consistent inactive status; gaps inside a transaction never establish proof.
No rule or new recording is needed when the immutable capture already has the
required status evidence. This does not verify transaction isolation equivalence.

For Redis and Memcached, preserve connection-lane ordering and protocol
semantics. Unmatched, unsupported, unsafe, and unused evidence remains dirty.
Ordinary Redis data commands support different source/target pool widths and
connection lifetimes by default, while retaining exact endpoint, database,
username, RESP version, command and arguments. A target connection may consume
several recorded source lanes; several target connections may consume one lane
in order. Each ordinary exchange is still consumed once. Source lanes with
retained session commands, transactions, subscriptions, blocking operations,
scripts or unknown commands remain bound in their entirety to one target
connection per active case. Another target connection cannot consume their
remaining exchanges. Diagnose these session constraints before changing target
pooling; do not reproduce short source connections for ordinary GET/MGET calls.
Redis RESP2 `SUBSCRIBE`, `PSUBSCRIBE`, and `SSUBSCRIBE` evidence is replayable
only when one command argument produced one exact three-element subscription
confirmation (or an ordinary Redis error). Replay returns that recorded
confirmation and leaves the connection open. Multiple subscription arguments,
asynchronous Pub/Sub messages, unsubscribe commands, and RESP3 push frames are
unsupported and remain dirty.

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

For ordinary MySQL, Redis, Memcached, and Kafka Produce/Fetch responses, delay
delivery by the recorded semantic exchange `duration_ms`; do not collapse
dependency latency to an immediate response because callers may enforce
aggregate deadlines, retry budgets, or races above the protocol client. For a recorded
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
