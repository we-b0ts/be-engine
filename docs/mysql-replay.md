# MySQL driver interoperability

This reference covers MySQL protocol behavior and historical Case diagnostics and rule authoring. Case
coordinator command examples identify historical interfaces. Use the current
[Source session commands](session-regression.md) for managed migration.

SQL value matching supports one statement up to 8 MiB and 32,768 tokens,
including recorded inline image/text values versus prepared parameters plus a
bound identity. Configured templates retain their separate 64 KiB bound.
Large statements are parsed without entering the SQL cache; cache retention
accounts conservatively for keys, tokens, ASTs and bound constant metadata within
16 MiB. BLOB/text bytes, predicates, status fields and finite consumption remain
exact outside the explicitly authorized identity/time fields.

For `mysql_values.values`, scalar and JSON time fields always use the individual
dependency request start. Source uses its recorded start (or completion minus
recorded duration); Target uses its independently observed request start. The `anchor` configuration field is forbidden, including an explicit dependency
start. API-entry and response-delivery times are never fallback clocks. PREPARE
does not invent an execution clock.

Rule planning retains complete candidate evidence but compares only structurally
corresponding MySQL requests. Different statement structures supply no independent
Target validation. Same-structure candidates still validate every selected value,
unselected scalar, parameter and clock. Each related Target observation must
validate against a Source statement in the complete selected scope; failed
cross-row search edges do not invalidate its valid pair with another row.
Source exchanges without a corresponding
Target witness produce `planned_needs_replay`; applying the rule preserves the
requirement for fresh genuine Replay.

The public transaction regressions run with `cargo test --lib mysql_candidates_transaction`.
For a private finalized recording and reviewed MySQL proposal, run its original
protected witnesses through the same preflight without changing project state:

```bash
TRAFFIC_E2E_MYSQL_PLAN_PROJECT=/absolute/project \
TRAFFIC_E2E_MYSQL_PLAN_REPORT=/absolute/finalized/replay-report.json \
TRAFFIC_E2E_MYSQL_PLAN_PROPOSAL=/private/mysql-proposal.yaml \
  cargo test --lib recorded_mysql_candidate_preflight -- --ignored --nocapture
```

This fixture checks three Source statements, one independently observed request
and two missing Target witnesses. It preserves the original artifact hashes and
does not replace a successful genuine API Replay.

> Rule authoring now uses self-contained `traffic-policy/v3` records in
> `project.policy` and `rule plan --file … --evidence …`. Legacy rule YAML and
> commands below are historical semantic references; protocol/TLS/transaction
> requirements remain current. See [unified rule contracts](unified-rule-contracts.md).


Replay accepts the ordinary SQLx 0.8 MySQL client, including TLS, connection
initialization, prepared statements, cached statement reuse and explicit
single-connection transactions. Targets retain their driver's normal settings;
do not turn off `SET NAMES`, SQL mode setup or parameter binding for replay.

Recorder and Replay support text and binary result rows larger than the MySQL
physical packet limit of `0xFFFFFF` bytes, over both TCP and TLS. Recorder
validates consecutive continuation sequence IDs and reassembles each logical
message before semantic parsing or response completion. Forwarding and debug
capture retain physical packets. Replay splits logical messages, emits an empty
terminator for exact multiples of the physical limit, and advances subsequent
row/EOF sequence IDs by the packets sent. Capture-size limits still apply;
incomplete continuations produce a parse warning. Recordings created without
continuation support may contain corrupt semantic rows and require fresh
recording rather than edits to `dependencies.jsonl`.

Text (`COM_QUERY`) and prepared (`COM_STMT_EXECUTE`) evidence can match in either
direction. Matching checks target host/port, database, username and case scope
before SQL and parameter values. SQL tokens distinguish identifiers, literals,
comments and placeholders. Literal case, whitespace, binary bytes, NULL and exact
numeric values are preserved. PREPARE can obtain column metadata from a text
recording and flushes the complete metadata response over TLS before waiting
for execution, including queries with hundreds of parameters.
Physical tables, predicates, parameter values and fixed LIMIT values
remain matching constraints; the projection compatibility below handles ordinary
ORM and driver differences without requiring target code to mimic source SQL.

Cross-protocol matching requires SQL/value equivalence within those boundaries.
Existing dynamic parameter policies continue to apply to matching prepared-protocol records;
this change does not infer dynamic values from text literals. The tokenizer
uses default MySQL quoting and escapes. Executable comments, optimizer hints,
ANSI_QUOTES and NO_BACKSLASH_ESCAPES are not normalized across protocols.
Unsupported initialization or SQL remains visible as unmatched evidence.

Explicit [SQL time rules](mysql-time-rules.md) validate source-proven generated
time slots in writes across text and prepared protocols. They preserve stable
SQL values and require normal Replay after plan/apply.

Recorded responses take precedence over builtin responses. The builtin fallback
recognizes narrowly bounded driver initialization, not arbitrary SET statements
or business SQL containing `version()`. Replay preserves unsigned BIGINT,
binary column metadata and fractional seconds when converting text resultsets
to binary rows. BEGIN/COMMIT/ROLLBACK update per-connection transaction status
in OK and EOF packets; a successful BEGIN therefore works with SQLx's transaction
state checks. This status tracking does not simulate database contents or
replace recorded effects with an in-memory database.

## Transaction isolation scope

Replay permits an unused `SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED`
in a proven physical-connection initialization prefix. The contiguous Source
wire sequence starts at the first driver setup statement and includes successful
driver settings, an inactive `SET AUTOCOMMIT = 0` and an empty `COMMIT` immediately
after the isolation setting. All commands must keep the same connection identity.
Replay reports the unused setting under
`allowed_unused_mysql_connection_read_committed_exchanges`. Transaction-specific
settings, other isolation levels and business SQL retain their usual obligations.

Replay can match a driver's next-transaction isolation setting to a proven
Source session override. This requires an immutable successful
`SELECT @@transaction_isolation` or `@@session.tx_isolation` initialization
probe for the same physical endpoint, database and username, followed by a
complete Case-local sequence:

~~~sql
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
-- one transaction, with its original reads, writes and end
SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
~~~

The probe must establish the restored baseline, and all recorded probes for
that resource must agree. The setup and restoration may both name that baseline:
reasserting the existing session level still requires the complete original
transaction and genuine Target delivery before restoration can be omitted.
Repeated successful settings of that same level before the first business
operation may share this proof. Their exact contiguous Source references remain
unconsumed until the complete Target transaction ends successfully; then they
become optional alongside the restoration. Changed levels, gaps, failures and
active settings retain their independent obligations. The isolation audit lists
the finite `source_reassertion_indices` and whether their omission was proven.
A pool may initialize its shared dialect on one
connection and configure another without probing again. For that case the
independent probe must have completed strictly before the new scope starts;
sequence numbers from different connections are never compared. Same-connection
proof retains its original wire order. Every intervening scope wire sequence,
physical identity, successful response and transaction-status transition must
be present. The supported Source scope has one implicit transaction. Proven
savepoint controls stay required members of that transaction. Gaps, failures,
lifecycle cleanup, another transaction or an ambiguous baseline retain ordinary
strict matching. Preparation is bounded to 128 scopes
per Case, 260 exchanges per scope and 4096 installed scopes and baseline connections.

Target can instead send `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` as
`COM_QUERY`, then `BEGIN`, the original business operations and their end. The
setting consumes the actual Source setup exchange. A proved isolation scope's
transaction members become eligible only after that setup is delivered. This
keeps identical requests from consuming members before their transaction opens.
Admission binds the actual
Target socket; every member must finish delivery on that socket in the same
explicit transaction. Existing business SQL, value and write-transaction
equivalence checks still apply. Another socket, wrong level, active-transaction
setting, missing `BEGIN`, omitted member or failed delivery cannot prove the
restoration omission. Known Target session settings also constrain the next
scope's baseline. No new general SET builtin or policy exemption is installed.

Only after the real end completes may the Source restoration exchange remain
unstarted as optional session cleanup. Its status stays available; no Target
reset is reported as delivered or consumed. `mysql_isolation_equivalence`
records the original setup/end/reset indexes, baseline probe connection and sequence, levels,
actual Target connection, delivered-member count and coverage phase. Pending
or invalid scopes retain the restoration obligation. Immutable recordings and
Global probe consumption are unchanged; the probe supplies Source facts rather
than a fabricated Target observation.

For a Source transaction proven entirely read-only, COMMIT and ROLLBACK are
equivalent ends. The original end may already be optional under the transaction
owner. Restoration still requires every original read to finish delivery in the
bound Target transaction, followed by a successful real COMMIT or ROLLBACK that
leaves the socket outside a transaction. The audit reports
`source_end_omission_proven` separately; no omitted Source end is counted as a
Target delivery. Missing reads, failed ends, other sockets, writes and locking
reads cannot use this read-only proof.

See MySQL's [transaction characteristics](https://dev.mysql.com/doc/refman/8.4/en/set-transaction.html)
for the distinct SESSION and next-transaction lifetimes.

## Transaction ownership across cases

In a completed standard recording, a complete transaction whose first exchange
starts in Global keeps Global ownership through its COMMIT or ROLLBACK, even
when later exchanges were captured inside one or more HTTP cases. Replay derives
this ownership from the complete connection sequence, resource identity,
before/after status and successful immutable responses. Missing starts, sequence
gaps, failed or truncated responses, nested BEGIN, chained ends, DDL and unknown
transaction controls do not establish this proof. Original recordings stay immutable.

Preparation includes proven members from unselected cases. Each original
exchange is registered exactly once as a finite Global dependency; eager and
lazy loading skip the original Case registration. Derived Global members stay
outside the stable native Global report inventory.
`global_mysql_transaction_exchanges` retains the original Case, dependency path,
line, record digest and transaction start. These Source facts are independent
of policy-dependent API-origin classifications.

Target connections retain their current transaction owner across case changes.
A transaction started between cases keeps Global matching and error attribution
while a later case is active. Its successful end or a confirmed implicit commit
resets that owner for connection-pool reuse. Delivery failures retain the
original request ownership. SQL/parameter matching and business-write
consumption remain strict.

The versioned proof cache binds the complete Source file inventory and identities.
Cold preparation reuses transaction metadata and reads candidate records by
offset. Native Global admission tracks whether a proven transaction start is
possible; recordings without one skip this additional Global transaction proof
preparation. Existing API-origin preparation may still load shared transaction facts.
Warm preparation validates file stamps and uses cached locators without
loading the full transaction-facts inventory. Response rows remain referenced
by their original immutable records. Request matching uses in-memory scope and
wire indexes without rescanning transaction evidence.
New MySQL Global report projections include the transaction semantic revision in
their cache identity. First-write-through-end semantics rebuild older MySQL
projections once; historical reports remain readable and other protocols retain
their existing cache identities. This revision only separates report caches:
Source-only prewarming cannot grant a Target delivery or transaction witness.

## Optional transaction cleanup

### Native Replay and attribution

Native Replay and Source attribution review use the same MySQL classification
of optional transaction controls. Plain COMMIT or ROLLBACK can be optional
when a successful response proves that the connection was already inactive,
or when complete consecutive Source evidence proves an ordinary read-only
transaction. Every business SELECT remains a required exchange. The original
capture and its global sequence are preserved, so an omitted control contributes
no Target delivery.

A proven SET autocommit=0 describes connection mode. A Target can use an
implicit transaction with autocommit disabled or an explicit BEGIN. From the
first write through the recorded COMMIT or ROLLBACK, all required members must
finish in order on the same physical Target connection and transaction.
This applies to a single UPDATE affecting zero rows. Ordinary reads preceding
the first write still match individually. Locking reads, savepoints and observed
snapshot requirements preserve the strict transaction boundary. Incomplete
Source proof grants no control exemption. A local inactive-session cleanup
response does not satisfy a required Source transaction end.

### Historical transaction reports

ROLLBACK remains semantic evidence, including failed rollbacks. Replay permits
omitting a redundant successful bare ROLLBACK immediately following a
successful bare COMMIT or ROLLBACK on the same recorded connection and identity.
Both exchanges must have consecutive query sequence numbers and complete,
successful zero-effect responses whose captured OK status flags confirm no
active transaction or pending results. This also excludes implicit transaction
chaining through MySQL's `completion_type` setting. Missing status flags or
missing or duplicate sequence evidence,
intervening statements, explicit transaction chaining, and parse warnings prevent
this compatibility.

Replay also permits omitting a successful bare COMMIT or ROLLBACK whose known
before and after status confirm no active transaction, no further results and
an unchanged AUTOCOMMIT mode. This includes repeated empty COMMITs. Complete
zero-effect responses and unique connection/sequence/resource identities are
required; contradictory immediate local predecessor evidence or available
Global read-prefix evidence prevents exemption. Zero affected rows alone does
not prove a COMMIT had no business effect.

Replay also permits a bare COMMIT or ROLLBACK that closes a proven read-only
session, including an explicit BEGIN or START TRANSACTION with a complete
successful response proving a transition from inactive to active. BEGIN itself
and all business SELECTs remain required.
Recorder preserves `server_status_before` from the immediately
preceding completed command, including maintenance such as COM_PING, and records
the final resultset EOF status in `response.server_status`. The first ordinary
SELECT must start with confirmed absence of an active transaction or continue
that proven explicit BEGIN. Every
subsequent exchange through the transaction end must have consecutive sequence numbers,
the same complete connection/endpoint/database/username identity, consistent
before/after transaction flags, and complete successful responses. Successful
PREPARE preserves the read proof because it does not execute SQL. The transaction end
must confirm transaction completion without chaining or further results.

The independent SQL classifier parses one bounded query (at most 1 MiB and
65,536 tokens) and excludes common locking and side-effect forms across its
full token stream. It does not maintain
a whitelist of SELECT expressions or functions: JSON operations, COALESCE,
CASE, aggregates, joins, CTEs, scalar/IN/EXISTS subqueries and window expressions
use the same check. Literal strings, ordinary comments and quoted keywords do
not count as executable clauses. SQL size, token count and parser depth remain
bounded; invalid/multiple statements and executable comments/hints remain strict.

The exclusions cover FOR UPDATE, FOR SHARE, LOCK IN SHARE MODE (including
nested queries), SELECT INTO, embedded DML, session variables/assignments,
SQL_CALC_FOUND_ROWS, and common lock/session/external-effect calls: GET_LOCK,
RELEASE_LOCK, RELEASE_ALL_LOCKS, service lock functions, LAST_INSERT_ID with an
argument, SLEEP, BENCHMARK, LOAD_FILE, SYS_EXEC and SYS_EVAL. Vendor output/settings
clauses also remain unsupported. Ordinary function names, including custom
functions, do not require registration. This is a practical cleanup classification
with known exclusions, not a proof of arbitrary stored-function/UDF behavior.

SQL query matching remains independent and strict. Business reads are still
required dependencies; this classification only governs optional session
setup/cleanup. This includes ORM refreshes after a commit or rollback expires
an object: later attribute access can issue a primary-key SELECT without an
explicit `get()` call. Equal rows from an earlier authentication read do not
make that later read optional. Column aliases or LIMIT shape do not identify
the source caller; supported alias/projection adaptation does not remove the
finite-consumption requirement.

Dirty-cluster evidence labels `unused_recorded` as an unconsumed recorded call,
with source ownership unresolved. Its `mysql_unused_diagnosis` directs the
source trace through request dependencies, helper commits, expiration and
refresh. MySQL dependency details expose captured `server_status_before` and
`server_status_after` alongside connection/query locators; bit `0x0001` is
IN_TRANS, zero is known and an absent field is unknown. Representative details
remain bounded and may omit other calls. These facts do not identify a source
caller or authorize omission. Rule hints and planner help are discovery;
empty candidates do not prove an engine gap. A MySQL time planner is offered
for `unmatched_target`, not an unused-only cluster: a time rule cannot consume
an omitted call. Request-owned reads require normal target implementation.

Writes, nested or unproven BEGIN, locks, savepoints and excluded calls
interrupt the read span. Unknown transaction starts, sequence gaps, errors or
truncated evidence prevent a read-only proof. Replay retains compact tails of
complete read spans from `global-dependencies.jsonl` once at load time. Only a
case's first exchange on the same recorded connection can continue such a tail;
its query sequence, endpoint/database/username and transaction flags must agree.
This handles a Global read session whose close falls inside a later HTTP case.
Case files never supply prefixes for other cases, so eager/lazy loading order
does not affect the result. SQL checks are cached only during each file load.
This does not prove concurrency/isolation equivalence. A SELECT-only case
without transaction-state evidence is insufficient.

A successful bare ROLLBACK that is the first recorded MySQL exchange on its
connection in a case is also optional foreign/empty cleanup. It requires a
complete identity, unique query sequence and known before/after transaction
state with no pending results or chaining. Other SQL on different connections
or in later transactions does not prevent this classification. An earlier
exchange on that connection prevents the leading-cleanup exemption, including
when a sequence gap makes the earlier transaction unknown. This is a practical
recorded-scope classification, not coroutine tracing: it assumes the semantic
recording has not lost that case's preceding SQL. It never uses HTTP response
contents or a target-specific rule. A leading COMMIT with unknown preceding
effects remains required; COMMIT needs the complete read-only or confirmed-empty
status proof described above, or existing source-proven API-origin transaction rules.

An identical optional close does not outrank a required business transaction
end whose immediately preceding exchange has already been consumed on the
same recorded connection, identity and transaction state. Before that prefix
is consumed, a startup cleanup still matches the optional exchange. This
preserves finite consumption without forcing targets to issue extra closes.

Targets can retain their normal pooled client after read-only requests; do not
add `pool.execute("ROLLBACK")` merely to consume ORM session-close traffic.
Such a call can acquire a different connection and cannot replace a business
transaction's rollback. Preserve business transactions on one connection: a
missing rollback can change persisted data even when the HTTP response agrees.

Optional cleanup stays matchable and appears separately in
`allowed_unused_mysql_rollback_exchanges` or
`allowed_unused_mysql_commit_exchanges` when omitted or while its recorded
response is being delivered. In-flight cleanup is not counted as a completed
target call. Failed delivery remains a required unused exchange and reports an
unmatched error; ordinary in-flight business responses remain required.
Recorded files remain unchanged. Existing reports are not cleaned by SQL-summary filtering: rerun Replay to derive the classification
from full exchanges. Older recordings without query before/final-EOF status
remain strict for the first read-session rollback; re-record to establish that
proof. The existing duplicate-rollback compatibility still applies when its
own OK status evidence is present. Debug JSONL is never substituted for missing
semantic evidence. Recordings produced
by versions that omitted ROLLBACK already lack that semantic evidence and need a
new recording to validate it.

AUTOCOMMIT is also handled by Replay. A single literal session assignment
(`SET [SESSION|LOCAL] autocommit=0/1`, or `SET @@[session.]autocommit=0/1`)
can be sent by ordinary clients without a matching recorded initialization.
Replay maintains the connection's AUTOCOMMIT flag, preserves an existing
transaction when disabling it, and clears transaction flags on OFF-to-ON.
Repeated ON does not end an explicit transaction. Recorded errors take
precedence over built-in success. Recorded transaction flags for an implicit
session are applied only when both source and target have autocommit disabled;
they never force the source's implicit transaction onto an autocommitting target.
This is protocol state tracking, not a simulation of storage-engine transaction
effects when source and target use different modes.

Recorder retains both successful and failed AUTOCOMMIT exchanges, including
ON assignments that older versions discarded. Replay permits omitting them
only when the loaded connection/identity evidence proves a read-only span:
known inactive start, complete ordinary reads, no writes, locks, explicit BEGIN,
unsupported statements or failures, and a confirmed inactive finish. Successful
PREPARE does not execute SQL. An initial sequence gap before the first read is
allowed only with consistent inactive status on both sides, because Recorder
can omit driver setup such as SET NAMES. Within a Case, those same confirmed
inactive boundaries also separate completed read spans. Sequence continuity is
required inside each active transaction; a gap between completed spans starts
a new span without inferring or authorizing the missing commands. This permits
omitting a Case's read-only initialization even when an older recording omitted
maintenance between its completed sessions. Recorded writes, locking reads,
explicit transactions, failed/incomplete exchanges, identity changes and
inconsistent or active boundary status still keep setup required. Global
evidence retains its stricter post-read sequence continuity.
Recorder retains semantic COM_PING
exchanges as continuity evidence, although they are not required business
dependencies. Replay answers COM_PING with a built-in OK response. A complete
successful, zero-effect PING with unchanged transaction
status preserves that proof, including inside an active read transaction.
Unknown gaps inside active transactions remain strict.
This read-only setup check is scoped to one immutable dependency file and does
not infer the contents of a gap or join evidence across cases/Global. The
write-containing Source proof below has a separate, bounded Global-read bridge.
SQL effect checks share the load-local cache used for rollback classification.

Optional setup remains matchable and, if omitted, appears separately as
`allowed_unused_mysql_autocommit_exchanges`; business reads remain required.
No target shim, rule or re-recording is needed when existing captures contain
the required status evidence. An incomplete session keeps the setup required.
Old captures that discarded AUTOCOMMIT=1 cannot validate
that missing transaction control without a new recording.

Write-containing implicit Source sessions use first-write-through-end
compatibility by default. No configuration switch is required. A recorded
`SET autocommit=0` sets connection mode; it is not an explicit BEGIN and must not
force the complete connection lifetime into one Target transaction. Source's
SET remains in the immutable recording. Target can retain autocommit mode 1,
with explicit transactions only where the following proof requires them.

For each complete implicit Source transaction:

- With no business writes, successful setup and cleanup can use the existing
  bounded read-only proof; every business SELECT remains required.
- With one business write and a successful plain Source COMMIT, independently
  observed Target autocommit mode 1 and no active Target transaction at that
  write, followed by successful response delivery, can satisfy its Source setup
  and COMMIT without a Target transaction end. The write and every read still
  require their ordinary finite matching and delivery.
- With exactly one ordinary UPDATE followed by a successful plain Source
  ROLLBACK, the same independently observed Target autocommit-1/no-active-
  transaction delivery can satisfy the setup and ROLLBACK only when the recorded
  UPDATE returned an error, or succeeded with known `affected_rows: 0`. Delivery
  of the corresponding UPDATE response, including a recorded error response,
  must still succeed. The UPDATE remains one write request; it is not converted
  into a zero-write span.
- With two or more business writes, or Source ROLLBACK after a write outside
  that single-UPDATE exception, Target must use one explicit transaction from
  the first corresponding write through the matching Source COMMIT or ROLLBACK.
  Every intervening statement and every trailing read after the last
  write must remain ordered on that same Target socket through the end.
  Preceding ordinary reads may execute outside the Target transaction and use
  the normal read route; they are still required dependencies.

Ordinary ROLLBACK cleanup remains optional when complete Source evidence
establishes no pending business write: for example a complete ordinary read-only
transaction, a confirmed inactive session, or the existing redundant cleanup
after a successful end. The additional single-UPDATE error/zero-row case above
is a deliberately bounded compatibility rule based on recorded Source results;
it does not prove the absence of arbitrary trigger or session side effects,
and it does not identify a particular conditional branch in Source code.
A successful UPDATE with positive affected rows followed by ROLLBACK retains
the write-through-ROLLBACK obligation even when there is only one write.
Missing affected-row evidence does not establish the zero-row exception. Each
UPDATE in a multi-write span counts as a write even when it affects zero rows.

The ordinary SQLx transaction API or a project's `with_transaction` wrapper
provides the explicit Target boundary. A Source transaction ending in COMMIT
cannot be satisfied by Target ROLLBACK, or conversely, when this boundary is
required. Successful Source cleanup after the actual end is independently
optional; it cannot replace a required business end. Source explicit BEGIN
transactions retain their existing boundary requirements.

Finite asynchronous tails honor these same native omission proofs. An unstarted
control already permitted to be omitted does not keep a Case waiting or appear
as a pending business call. It remains unconsumed in the allowed-unused report.
If Target starts that control, its real I/O must finish before Case release;
failed delivery and unproven transaction ends retain their obligations.

Replay requires complete Source connection identity, sequence and transaction
status evidence. It supports complete ordinary reads and INSERT/UPDATE/DELETE/
REPLACE writes with successful plain transaction ends. PING/PREPARE can prove
continuity without adding executed business statements. Complete transactions
containing locking reads or SQL whose effects cannot be classified keep their
full same-connection boundary; neither prefix trimming nor single-write end
omission applies. Their diagnostics identify `strict_source_effects`, and their
write count describes recognized DML only. Unknown starts, missing status,
errors outside the bounded single-UPDATE case above, and unproven transaction
fragments grant no new compatibility exemption and retain required Source
controls. A failed ROLLBACK itself is always required; the UPDATE exception
never hides a failed transaction end.
Successful `SAVEPOINT`, `RELEASE SAVEPOINT` and `ROLLBACK [WORK] TO
[SAVEPOINT]` controls now retain a connection-local lifetime proof. Source
transactions must contain complete, consecutive exchanges and active before/after
status. Generated savepoint names may differ between SQLAlchemy and SQLx;
Replay binds each delivered creation to its Source name and requires subsequent
release/rollback references on that same Target socket. Rollback removes later
savepoints; release removes only the selected name. SQLx may reuse the depth name
of a rolled-back scope on a subsequent Source retry. Unbound, released, foreign
and wrong-kind references remain rejected, and failed controls retain strict SQL
matching without granting an alias or omission.

Savepoint transactions require a real outer Target transaction, including single-
write and read-only savepoint spans. Their required interval begins at the first
savepoint preceding the first write (or the write itself when earlier), through
the final outer COMMIT/ROLLBACK. Ordinary prefix reads remain finite required
calls and may use the ordinary read route. Inner release never counts as an
outer commit. Complete Global-started transactions use the same Source savepoint
lifetime validation before cross-Case promotion; old proof caches are rebuilt.
No recording, policy rule or setup SQL needs to be changed.

This does not prove arbitrary storage-engine, isolation or session-setting
equivalence. Existing strict session operations and ordinary SQL/value matching
remain in force.

Some original ordinary reads can have Global ownership while surrounding
statements belong to a Case. Replay can use those Global reads only to complete
the Case's already established implicit Source span across an active sequence
gap before its first write. Every missing sequence must have one complete,
successful ordinary Global read on the same recorded connection, with matching
endpoint/database/username, continuous before/after transaction status and no
mode change. Duplicate wire
identities, unknown or absent exchanges, writes, locks, session effects,
unsupported reads and missing status cannot bridge the gap. No gap after the
first write can use this bridge, including one containing ordinary Global reads.

The bridge retains only immutable identity/status metadata; it supplies neither
SQL matching permission nor a Target delivery witness. Global ownership,
endpoint checks and finite consumption stay unchanged, and the proof itself
does not consume a Global read or move it into the Case. Case evidence never
supplies another Case's missing prefix. If an earlier segment is incomplete,
a later independently known inactive start can establish a separate complete
transaction. The earlier segment keeps its rejection evidence, and its
connection-level incompleteness still prevents setup omission; later recovery
does not repair the missing history.

Each required Target transaction must cover exactly one Source transaction's
ordered first-write-through-end window. A Source connection's transaction order
is retained, although completed transactions can use different Target pool
connections. Splitting or merging write windows, early ends before trailing
reads, reversed outcomes, nested/restarted transactions and another socket's
commit cannot satisfy the SET. One persistent Source SET can cover several
transactions; every affected complete segment must establish its corresponding
proof. Read-only setup and cleanup compatibility retain their independent rules.
When concurrent transactions have identical end SQL, the delivered members on
each Target socket select its corresponding finite Source end; ordinary identity,
value, availability and policy checks still apply. Neither the initial SET nor
this compatibility grants permission to change dependency endpoints.

Coverage is recorded only after successful response delivery and response-policy
commit. Failed setup/end controls, unknown boundaries and incomplete evidence
remain required. Replay never fabricates a Target SET or consumes its Source
record. Covered setups retain the historical
`transaction_equivalent_mysql_autocommit_exchanges` report field, separately from
read-only omissions, with bounded Source interval and independent Target
connection/transaction witnesses. This field records the supported write-window
compatibility; it does not claim full implicit-transaction snapshot or isolation
equivalence. New reports identify the default with
`mysql_transaction_semantics: first_write_through_end_v1`; aggregate summaries
preserve it when present and do not relabel historical reports. Remaining setup
summaries expose
`diagnostic.kind: mysql_autocommit_transaction_coverage`, a precise rejection
or pending reason, and covered/total transaction counts. The coordinator's
`mysql_autocommit_diagnosis` guides Source lifecycle and Target SQLx transaction
investigation. Resolve `source_proof_status: incomplete` using its failure and
missing query sequences before deciding whether Target needs a transaction.
An unregistered end or absent historical witness does not prove the write count
or Target status. Once Source proof is complete, compare its required members
and end with actual Target connection/status witnesses. Do not wrap prefix reads
or add driver SET statements solely to remove an unused count. Missing evidence
and passing responses alone grant no exemption or engine-gap attribution.
Historical reports can receive guidance, but only a fresh Replay can establish
transaction coverage.

When a completed Target transaction fails member/end validation, its focused
Source group includes a bounded `member_comparison`. `first_difference` gives
the zero-based member position and the expected and actual matched Source
references (recorded index, Source connection, query sequence). The two member
lists contain at most 32 entries each with explicit omitted counts; the first
difference remains visible even when it is beyond that prefix. These are
matched Source references in actual Target delivery order, not Target event
indexes. No SQL or parameter values are included.

Consuming every operation is insufficient when the write/read order differs.
An earlier reordered write can prevent selection of the correct COMMIT and
leave only that end in `missing_required_query_sequences`. Inspect
`member_comparison.first_difference` before treating this as an absent COMMIT.
Older reports without the comparison retain their original evidence; only a
fresh Replay captures it.

Run the actual-client and focused protocol tests with:

```sh
cargo test --lib mysql
```

`sqlx_tests` exercises an ordinary SQLx client over a TLS socket, including its
default initialization, strict-policy text recordings, strings, NULL, binary
values, unsigned BIGINT, fractional timestamps, decimals, statement reuse,
writes, commit, rollback and errors. These tests have an explicit time bound.
SQLx is a development dependency only.

## SELECT column compatibility

For a single-table SELECT of direct columns, replay permits a different column
selection, order, column aliases and table alias. It resolves each target field
to the same physical field in the recorded projection, selects the recorded
cells, and emits column metadata in the target's requested order and names.
The target may read a subset of the recorded columns. A field absent from the
recording, or an ambiguous source mapping, cannot acquire a match. Replay never
substitutes unrelated cells merely because their positions or types agree.

For example, these queries can share recorded evidence:

```sql
-- Source ORM
SELECT s.id AS subtasks_0640_id, s.uid AS subtasks_0640_uid,
       s.title AS subtasks_0640_title
FROM subtasks_0640 AS s WHERE s.uid = 640 ORDER BY s.id LIMIT 10;

-- Target (also accepts a bound ? with value 640)
SELECT t.title AS title, t.id AS task_id
FROM subtasks_0640 AS t WHERE t.uid = 640 ORDER BY t.id LIMIT 10;
```

Endpoint, database, username, physical table, predicates, values, sorting and
pagination remain constrained by the existing matcher. `ORDER BY` output aliases
and column positions are resolved to physical fields before comparison: merely
keeping `ORDER BY 1` after reordering columns does not prove equivalent sorting.
Exact candidates take precedence within the existing Case-before-Global order;
every successful delivery still consumes its original exchange once.

`COUNT(*)` matches `COUNT(*)`, and integer constants such as `1` match the same
constant, with optional alias changes. These expressions cannot be dropped,
added or replaced with ordinary columns. This compatibility does not equate
`COUNT(*)` with `COUNT(column)`, nor `1` with a different expression or result
type. GROUP BY, subqueries, locks, wildcard projections and other computed
expressions stay on the existing strict matching path. JOIN queries do not gain
projection adaptation; only the pure-predicate compatibility below applies when
the complete projection, FROM/JOIN/ON clauses and query tail stay exact.

Single-table `SELECT DISTINCT` supports the same alias and qualifier adaptation
when both queries select exactly the same complete set of direct columns.
Columns may be reordered, but cannot be dropped, added, or duplicated: doing so
would change the tuple used for deduplication. DISTINCT never maps to ordinary
SELECT. Predicates, bound values, sorting, and pagination retain their existing
checks. DISTINCT aggregates, constants, and wildcard projection adaptation remain
unsupported. The recorded row order and duplicate handling are preserved; Replay
does not deduplicate or sort result rows itself.

For example, source `SELECT DISTINCT resource_members.entity_id AS
resource_members_entity_id FROM resource_members WHERE
resource_members.resource_type='Namespace'` can match target
`SELECT DISTINCT entity_id FROM resource_members WHERE resource_type=?` with
the string parameter `Namespace`. Target can keep normal prepared statements
and decode `entity_id`; copying ORM labels or forcing COM_QUERY is unnecessary.

The same mapping supplies PREPARE metadata, text rows and binary prepared rows,
including NULLs, empty results and original column types. It requires complete,
successful resultset evidence without parse warnings. Only the delivered copy
changes: dependency JSONL files remain immutable, and no rule application or
new recording is required for this compatibility. Process-owned classification
below is a separate ownership decision and retains its explicit SQL selectors.

The SQLx tests exercise subset/reorder/alias mapping over TLS in both text and
prepared protocols, cached parameter rebinding, COUNT and constant projections,
rejection of changed conditions, scope isolation and immutable recordings.
DISTINCT tests also cover the models/unified query shape, empty results,
both protocol directions, reordered AND predicates, finite evidence consumption,
and cached parameter rebinding.

## SELECT predicate order compatibility

Replay accepts different list orders in ordinary `IN` / `NOT IN` predicates
and different orders of pure `AND` conditions and `OR` branches in single-table
SELECTs. Direct-table JOIN SELECTs use the same predicate compatibility when
their complete projection, FROM/JOIN/ON clauses, sorting and pagination are
otherwise exact. This is built in and requires neither a rule nor a new
recording. Source can interpolate literal values into text SQL while target
retains its normal `?` binding:

Global value formats retain this native compatibility when no SQL field is
selected. Result delivery and protected response-witness validation use the same
predicate proof as request matching. Selected value contracts remain enforced;
changed values and exhausted exchanges remain rejected.

Ordinary SQL strings that happen to parse as JSON scalars, such as `'801'`,
remain native strings when no global JSON field selects that scalar. They do
not force positional JSON comparison of an otherwise equivalent string `IN`
list. Structured JSON payloads retain their automatic codec, and explicitly
selected scalar formats retain their contracts. Protected request-witness
validation uses the same native predicate proof in the unselected case.

Global format preflight treats SQL-less session commands such as `COM_PING` as
exact protocol controls, with no positive format-rule witness. Missing SQL in a
business query or prepared statement remains invalid evidence.

Protected `backend-rewrite evidence-detail --api PATH --witness ID --pointer POINTER`
queries can select a SQL literal or bound parameter without reading the whole
statement. Use `/sql_values/<token-index>/value`, or
`/sql_values/<token-index>/json/<JSON-pointer>` for JSON encoded in that value.
Response witnesses use `/request/sql_values/...`. The `physical_fields` entries
in `unified-rule-candidates` expose the same SQL token positions; the selected
cell's `/field` view reports a physical column only when the normal resolver
can prove it. `/kind` distinguishes strings, exact SQL number text, NULL and
binary bytes (`/base64`). Ordinary native-envelope pointers remain available.

The engine authenticates the current assignment, finalized attempt and original
Source bytes before decoding. Each statement is materialized independently;
equal token indexes alone do not prove Source/Target correspondence or grant a
value rule. Queries return at most 4096 bytes of the selected value. Narrow JSON
pointers can therefore inspect a small field inside a larger SQL string;
unsupported statements and incomplete bindings remain explicitly unavailable.

```sql
-- Recorded source text
SELECT id FROM tasks WHERE tenant=7 AND id IN (3,1,2);

-- Target prepared SQL, parameters [2,3,1,7]
SELECT id FROM tasks WHERE id IN (?,?,?) AND tenant=?;
```

`sqlparser` with `MySqlDialect` recognizes the query and predicate structure.
Replay associates each placeholder with its original parameter position before
normalizing values or conditions. The existing literal decoder retains exact
decimals, string case/bytes, escapes and NULL. An IN list may contain numbers or
strings/binary values, optionally with NULL; mixed string/number lists remain
strict. Reordering preserves duplicates, list length and each exact value.
`?` is never a value exemption during execution.

Flat tuple `IN` / `NOT IN` lists also support reordering, including ordinary
SQLAlchemy row constructors and target parameter binding:

```sql
-- Source
WHERE (user_id,namespace,name) IN ((7,'default','a'),(7,'shared','b'))
-- Target, parameters [7,"shared","b",7,"default","a"]
WHERE (user_id,namespace,name) IN ((?,?,?),(?,?,?))
```

The left side is an ordered tuple of direct columns and every list item must
have the same arity, at least two, with scalar literal/parameter components.
Only whole tuples are sorted: column order, value pairing, NULL position and
duplicate tuple counts remain exact. Types are checked per component across
rows, so `(integer,string)` is allowed while mixing numbers and strings in
the same tuple position remains strict. Nested/ragged tuples, row expressions,
subqueries and function calls stay on the existing exact matching path.

PREPARE matches complete fixed tuples before unknown rows and uses injective
matching for partially bound tuples such as `((?,2),(1,?))`. That ambiguous
search is bounded to 64 partial rows and 4096 possible assignments; fully
parameterized or concrete lists retain the fast multiset path within the
existing SQL size/token limits. EXECUTE binds each parameter before sorting
and validates the actual complete tuples on every call. The same compiled
template, metadata and constant-query caches apply. Ordinary tuple IN reads
can also participate in proven read-only session cleanup described above.

The supported conditions are direct fields and scalar values compared with
`=`, `!=`, `<>`, `<`, `<=`, `>`, `>=`, `<=>`, `IS NULL`, `IS NOT NULL`,
`IS [NOT] TRUE`, `IS [NOT] FALSE`, `IS [NOT] UNKNOWN`, `BETWEEN`, and
literal/parameter IN lists, combined by AND, OR and parentheses. Truth tests
retain their own operators: `IS TRUE` does not become `= 1`, and `IS NOT TRUE`
does not become `IS FALSE`. This support composes with reordered tuple IN lists.
Only groups with the same operator are flattened and sorted, after parameter
binding, without dropping duplicate conditions. Mixed AND/OR nesting and each
branch's column/value pairing remain exact. For example, `(a=1 AND b=2) OR
(a=3 AND b=4)` matches `(b=4 AND a=3) OR (b=2 AND a=1)`, but not `(a=1 AND b=4)
OR (a=3 AND b=2)`. No distribution, absorption or logical expansion is performed.
The grammar distinguishes BETWEEN's internal AND. A narrow fallback also supports
scalar and flat-tuple `IN` / `NOT IN` list reordering inside correlated `EXISTS`
subqueries when the `EXISTS` participates in an `OR` branch. Direct-table JOIN
chains and `SELECT count(*) FROM (SELECT ...) alias` wrappers also admit list
reordering, including the paginated SELECT corresponding to that count. The complete parsed query remains
strict: projections, functions, JSON paths, tables, correlations, boolean
structure, JOIN conditions, sorting, pagination, operators and every non-list
value must be identical. This covers
source collections whose order changes inside access-control `EXISTS` checks
without treating the surrounding complex predicate as generally equivalent.
A second full-AST fallback supports the same list reordering in supported
`UNION ALL` read trees, including direct joins, derived tables, inline window
expressions and computed projection expressions. Every node outside eligible
lists remains exact: UNION branch order, JOIN conditions, projections, windows,
predicates, sorting and pagination cannot change. Only `UNION ALL` is admitted;
UNION DISTINCT and other set operations remain strict. Other function/arithmetic
predicate changes, unsupported subquery forms, tuple comparisons outside IN,
locks and writes retain their existing strict matching behavior. Wildcard SELECTs can match
when their projection remains the same; supported direct-column projections
can also use the column compatibility above.

Exact and existing projection candidates precede predicate-equivalent candidates
within each scope; Case still precedes Global. Only complete successful
resultsets qualify. Host, port, database, username, table, sorting, pagination,
case ownership and finite dependency consumption remain constraints. IN
compatibility does not make response row order irrelevant. Recorded JSONL is
immutable; only delivered response columns/cells are adapted.

PREPARE checks structure and all fixed literals to select column metadata without
consuming an exchange. EXECUTE checks freshly bound values. Cached prepared
statement reuse with different parameters therefore cannot reuse a previous
successful match. Selected positional dynamic-parameter policies keep their
existing matching path; predicate compatibility does not move their parameter
indices or bypass their validation. Cross-protocol matching continues to require
actual value equivalence, without inferring dynamic bindings.

The Replay-local FIFO cache retains compiled SQL templates, negative parsing
results, parameter-independent metadata shapes and normalized constant queries.
It holds at most 256 SQL strings within a 16 MiB retained-memory budget, including
compiled representations. Statements up to 8 MiB and 32,768 tokens are supported;
statements over the separate 64 KiB cache-entry limit parse without retention.
Parenthesis/parser depth remains bounded. Flat AND/OR groups are traversed iteratively; their
term count does not consume the predicate nesting budget. PREPARE uses a linear
path when every branch has the same parameter template, including common fixed
literals. Each recorded branch must satisfy that template and the branch counts
must agree. This supports large parameterized OR groups (including 79 branches
and empty strings) without quadratic assignment work. Heterogeneous partially
bound groups retain the 64-term / 4096-pair assignment limit.
Nested boolean metadata comparisons share a 16,384-pair work budget;
excessively ambiguous forms fall back to strict matching. Execution compares
normalized bound trees without that combinatorial assignment.
Unsupported/oversized forms still try the existing matcher. Actual parameters
are bound once per semantic lookup; cached templates never retain previous
execution parameters, selected exchanges, responses or policy decisions.
The cache is discarded with the Replay runtime and never written to recordings.

The actual SQLx/TLS tests cover all four text/prepared protocol combinations,
reordered integer/string lists and conditions, partial literal/parameter lists,
column mapping, cached rebinding, wrong values, scope and finite consumption.
Focused checks: `cargo test --lib mysql`.

## Process-owned MySQL reads

MySQL joins the existing HTTP/Redis/Memcached/Motan process-owned classification.
A rule requires source ownership evidence, exact endpoint/database/username,
a physical table selector and one read-only SELECT template. `{{table}}`
selects a matching physical table; `AS {{table}}_id` expands a column alias
using that same table, and `?` selects a variable literal position.
Every other projection, predicate and constant remains exact. Do not classify a
query as process-owned merely because replay reports it unused.

Reads from a detached API task can instead use an explicit API origin and a
captured identity bound to a SELECT predicate. See [API-triggered process
traffic](api-triggered-process-traffic.md#mysql-selects-from-the-same-api-origin)
for `--trigger-source`, `--identity-value-index`, old-recording reuse and
same-name narrowing of an ordinary rule. Direct polling/cancel requests keep
their case ownership; a background task's terminal collection is a separate caller.

Table selectors can be combined (their union is used):

- Repeat `--table` for exact table names.
- Use `--table-prefix`, `--table-start`, `--table-end`, and `--table-width`
  for a numeric shard series, bounded to 4096 physical names.
- Repeat `--table-pattern` for a pattern containing one `*`, such as
  `'subtasks_*'`, `'*_archive'`, or `'recovery_*_pending'`. Quote patterns in
  the shell. The wildcard matches zero or more ASCII identifier characters;
  matching remains case-sensitive and limited to 64-byte table names. Bare
  `*`, multiple wildcards, regular expressions, and SQL fragments are rejected.

The policy stores these as `tables`, `table_series`, and `table_patterns`.
Patterns must be justified by the source's table naming and ownership contract;
an observed prefix alone does not prove that all matching tables are process-owned.
Every table mode also requires the same endpoint, database, user, and SQL shape.

For example, after proving that a recovery scan runs independently of an API:

```sh
traffic-e2e config recorder plan process-owned-dependencies \
  --target-root /path/to/target \
  --name task-recovery \
  --case-source /path/to/finalized/cases \
  --source-revision 0123456789abcdef \
  --evidence 'src/recovery.py:run process startup recovery scan' \
  mysql --target-host mysql.internal --target-port 3306 \
  --database appdb --username app_user \
  --table video_tasks --table-prefix video_tasks_ \
  --table-start 0 --table-end 1023 --table-width 4 \
  --sql "SELECT id FROM {{table}} WHERE status='RUNNING' AND created_at>=?"
```

Review the plan and repeat with `apply`. Planning requires a finalized version-6
report and corresponding complete, successful immutable dependency evidence;
unmatched or unsupported target queries selected by the rule reject the plan.
Apply checks that evidence and rules have not changed since planning.

In a backend rewrite, the API implementer starts with the dirty-cluster result's
`representative_dependencies_command`, then the relevant target's returned
`detail_command`. Like Redis, MySQL has a structured detail view: SQL (up to
8192 bytes), typed parameters, connection identity, attribution, result status,
row count, column names, warnings, and original exchange locator. Previews and
omitted counts are explicit; result rows are not dumped. The tool reads
`dependencies.jsonl` internally. Read only the necessary original record if a
truncated or omitted detail prevents the diagnosis.

The worker verifies process ownership in source and returns selector inputs and
source proof. The main orchestrator uses the coordinator-issued dirty-cluster
evidence ID and the exposed `applicable_rule_planners` entry to plan and apply:

```sh
backend-rewrite --target-root /path/to/target dependency-rule plan mysql \
  --evidence-id <current-dirty-cluster-evidence-id> \
  --ownership process-owned --name task-recovery \
  --source-evidence 'src/recovery.py:run process startup recovery scan' \
  --target-host mysql.internal --target-port 3306 \
  --database appdb --username app_user \
  --table video_tasks --table-prefix video_tasks_ \
  --table-start 0 --table-end 1023 --table-width 4 \
  --sql "SELECT {{table}}.id AS {{table}}_id FROM {{table}} WHERE {{table}}.status='RUNNING' AND {{table}}.created_at>=?"
backend-rewrite --target-root /path/to/target dependency-rule apply <returned-plan-id>
```

Apply reclassifies the finalized focused report and recomputes its verification
result using the existing recording. The original dependency JSONL stays
immutable. Only unused Case summaries backed by complete successful immutable
exchanges and matching the current rule move to Global in the derived report.
SQL previews are not matching evidence. Unmatched and unsupported target traffic,
failed or incomplete recorded responses, and unrelated business queries remain
dirty. Reclassification is idempotent and restores Case ownership when a rule is
removed or no longer matches. No new recording is required for this classification.

The table expansion is bounded by the configured physical table selectors. A column
alias `{{table}}_id` must occur after `AS` in the SELECT projection and use the
same table as FROM and all other `{{table}}` references. `--table-pattern` matches
only that table identifier; SQL-wide glob matching, identifier fragments
elsewhere, and literal interpolation are not supported. For example,
`--table-pattern 'subtasks_*'` with `AS {{table}}_id` matches
`subtasks_0640_id` only when the actual table is `subtasks_0640`.

Future recordings also use the rule: matching reads enter Global even while an
API case is active. Global MySQL records remain finite and consumed once; no
Redis-style reusable snapshot is inferred. Source-required initialization,
background state changes and readiness remain target responsibilities.
