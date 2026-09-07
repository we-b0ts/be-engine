# MySQL driver interoperability

Replay accepts the ordinary SQLx 0.8 MySQL client, including TLS, connection
initialization, prepared statements, cached statement reuse and explicit
single-connection transactions. Targets retain their driver's normal settings;
do not turn off `SET NAMES`, SQL mode setup or parameter binding for replay.

Text (`COM_QUERY`) and prepared (`COM_STMT_EXECUTE`) evidence can match in either
direction. Matching checks target host/port, database, username and case scope
before SQL and parameter values. SQL tokens distinguish identifiers, literals,
comments and placeholders. Literal case, whitespace, binary bytes, NULL and exact
numeric values are preserved. PREPARE can obtain column metadata from a text
recording. Physical tables, predicates, parameter values and fixed LIMIT values
remain matching constraints; the projection compatibility below handles ordinary
ORM and driver differences without requiring target code to mimic source SQL.

Cross-protocol matching requires SQL/value equivalence within those boundaries.
Existing dynamic parameter policies continue to apply to matching prepared-protocol records;
this change does not infer dynamic values from text literals. The tokenizer
uses default MySQL quoting and escapes. Executable comments, optimizer hints,
ANSI_QUOTES and NO_BACKSLASH_ESCAPES are not normalized across protocols.
Unsupported initialization or SQL remains visible as unmatched evidence.

Recorded responses take precedence over builtin responses. The builtin fallback
recognizes narrowly bounded driver initialization, not arbitrary SET statements
or business SQL containing `version()`. Replay preserves unsigned BIGINT,
binary column metadata and fractional seconds when converting text resultsets
to binary rows. BEGIN/COMMIT/ROLLBACK update per-connection transaction status
in OK and EOF packets; a successful BEGIN therefore works with SQLx's transaction
state checks. This status tracking does not simulate database contents or
replace recorded effects with an in-memory database.

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

Replay also permits the first bare ROLLBACK that closes a proven implicit
read-only session. Recorder preserves `server_status_before` from the immediately
preceding completed command, including maintenance such as COM_PING, and records
the final resultset EOF status in `response.server_status`. The first ordinary
SELECT must start with confirmed absence of an active transaction. Every
subsequent exchange through ROLLBACK must have consecutive sequence numbers,
the same complete connection/endpoint/database/username identity, consistent
before/after transaction flags, and complete successful responses. Successful
PREPARE preserves the read proof because it does not execute SQL. The rollback
must confirm transaction completion without chaining or further results.

The independent SQL effect classifier uses sqlparser and caches ReadOnly,
StateChange or Unknown for each SQL string during loading. It admits
single-table SELECTs with direct columns, literals, wildcards, DISTINCT, pure
boolean/arithmetic expressions, grouping, HAVING, ordering and pagination.
This proves absence of effects; it does not require those expressions to be
supported by the query equivalence matcher. Writes, explicit BEGIN,
locks, savepoints, calls/functions, subqueries and unsupported SQL interrupt
the read proof. Unknown transaction starts, sequence gaps, errors or truncated
evidence keep the first rollback required. Classification stays within one
dependency file and caches SQL effect checks only during that load. It neither
joins transactions across cases/Global nor proves concurrency/isolation
equivalence. A SELECT-only case without transaction-state evidence is insufficient.

Targets can retain their normal pooled client after read-only requests; do not
add `pool.execute("ROLLBACK")` merely to consume ORM session-close traffic.
Such a call can acquire a different connection and cannot replace a business
transaction's rollback. Preserve business transactions on one connection: a
missing rollback can change persisted data even when the HTTP response agrees.

Optional cleanup stays matchable and appears separately in
`allowed_unused_mysql_rollback_exchanges` when omitted or while its recorded
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
can omit driver setup such as SET NAMES. Gaps after reads start remain strict.
The check is scoped to one immutable dependency file and does not infer the
contents of a gap or join evidence across cases/Global. SQL effect checks share
the load-local cache used for rollback classification.

Optional setup remains matchable and, if omitted, appears separately as
`allowed_unused_mysql_autocommit_exchanges`; business reads remain required.
No target shim, rule or re-recording is needed when existing captures contain
the required status evidence. A write-containing or incomplete session keeps
the setup required. Old captures that discarded AUTOCOMMIT=1 cannot validate
that missing transaction control without a new recording.

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
type. GROUP BY, joins, subqueries, locks, wildcard projections and
other computed expressions stay on the existing strict matching path.

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
and different orders of pure `AND` conditions and `OR` branches in single-table SELECTs. This is
built in and requires neither a rule nor a new recording. Source can interpolate
literal values into text SQL while target retains its normal `?` binding:

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
`BETWEEN`, and literal/parameter IN lists, combined by AND, OR and parentheses.
Only groups with the same operator are flattened and sorted, after parameter
binding, without dropping duplicate conditions. Mixed AND/OR nesting and each
branch's column/value pairing remain exact. For example, `(a=1 AND b=2) OR
(a=3 AND b=4)` matches `(b=4 AND a=3) OR (b=2 AND a=1)`, but not `(a=1 AND b=4)
OR (a=3 AND b=2)`. No distribution, absorption or logical expansion is performed.
The grammar distinguishes BETWEEN's internal AND. Function/arithmetic predicates,
subqueries, tuple comparisons outside IN, joins, grouping, locks, writes and computed sorting
retain their existing strict matching behavior. Wildcard SELECTs can match
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
It holds at most 256 SQL strings and 1 MiB of original SQL text (the associated
compiled representations consume additional bounded memory). A single SQL is
limited to 64 KiB and 4096 tokens for this compatibility path, with bounded
parenthesis/parser depth and at most 64 terms per AND/OR group for metadata
assignment. Nested boolean metadata comparisons share a 16,384-pair work budget;
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

In a backend rewrite, the API worker starts with the dirty-cluster result's
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
