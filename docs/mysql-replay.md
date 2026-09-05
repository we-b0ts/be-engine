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
recording; only the actual placeholder positions vary. Different projections,
tables, predicates or fixed LIMIT values do not acquire a match.

Cross-protocol matching requires exact SQL/value equivalence. Existing dynamic
parameter policies continue to apply to matching prepared-protocol records;
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

Run the actual-client and focused protocol tests with:

```sh
cargo test --lib mysql
```

`sqlx_tests` exercises an ordinary SQLx client over a TLS socket, including its
default initialization, strict-policy text recordings, strings, NULL, binary
values, unsigned BIGINT, fractional timestamps, decimals, statement reuse,
writes, commit, rollback and errors. These tests have an explicit time bound.
SQLx is a development dependency only.

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
