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
a bounded physical table set and one read-only SELECT template. `{{table}}`
selects a configured physical table; `?` selects a variable literal position.
Every other projection, predicate and constant remains exact. Do not classify a
query as process-owned merely because replay reports it unused.

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

Create a new recording after applying a rule. Matching reads enter Global even
while an API case is active; unrelated business queries remain Case-owned.
Global MySQL records are finite and consumed once. Existing recordings and
unused-case reports are unchanged, and no Redis-style reusable snapshot is
inferred. Source-required initialization, background state changes and readiness
remain target responsibilities.
