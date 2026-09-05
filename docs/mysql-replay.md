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
omitting only a redundant successful bare ROLLBACK immediately following a
successful bare COMMIT or ROLLBACK on the same recorded connection and identity.
Both exchanges must have consecutive query sequence numbers and complete,
successful zero-effect responses whose captured OK status flags confirm no
active transaction or pending results. This also excludes implicit transaction
chaining through MySQL's `completion_type` setting. Missing status flags or
missing or duplicate sequence evidence,
intervening statements, explicit transaction chaining, and parse warnings prevent
this compatibility. A first rollback after reads, writes, or locks remains
required; a read-only request alone does not prove transaction equivalence.

Optional cleanup stays matchable and appears separately in
`allowed_unused_mysql_rollback_exchanges` when omitted. It is never marked as a
successful target call. Recorded files remain unchanged. Existing reports are
not cleaned by SQL-summary filtering: rerun Replay to derive the classification
from full exchanges. Older recordings without status flags remain strict;
a new recording is needed to establish cleanup eligibility. Recordings produced
by versions that omitted ROLLBACK already lack that semantic evidence and need a
new recording to validate it.

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
type. DISTINCT, GROUP BY, joins, subqueries, locks, wildcard projections and
other computed expressions stay on the existing strict matching path.

The same mapping supplies PREPARE metadata, text rows and binary prepared rows,
including NULLs, empty results and original column types. It requires complete,
successful resultset evidence without parse warnings. Only the delivered copy
changes: dependency JSONL files remain immutable, and no rule application or
new recording is required for this compatibility. Process-owned classification
below is a separate ownership decision and retains its explicit SQL selectors.

The SQLx tests exercise subset/reorder/alias mapping over TLS in both text and
prepared protocols, cached parameter rebinding, COUNT and constant projections,
rejection of changed conditions, scope isolation and immutable recordings.

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
