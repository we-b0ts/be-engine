# Traffic E2E MySQL Case Format

Read this reference when inspecting, replaying, or diagnosing semantic MySQL
dependency records.

## Exchange Fields

Prefer `mysql_exchange` over raw MySQL records. Important fields:

- `connection_id`: connection-scoped id
- `query_sequence`: sequence of queries on the connection
- `target_host`: business/original target host used by the application, not a
  fake IP and not an upstream IP fallback
- `target_port`: original target port
- `target_addr`: original target host and port
- `database`: default MySQL database/schema for this exchange
- `username`: MySQL username observed for this exchange
- `command`: MySQL command name
- `sql`: SQL text, when parsed
- `statement_id`: prepared statement id; connection-local only
- `params`: parsed prepared statement parameters, when available
- `outcome`: `response`, or `client_terminated` when the application ended the
  connection while waiting for the dependency; protocol commands that
  intrinsically have no response use `no_response` where applicable
- `duration_ms`: elapsed time from the complete request to the recorded outcome
- `response.status`: `resultset`, `ok`, `error`, `client_terminated`,
  `incomplete`, or another parser status
- `response.columns`: decoded resultset column schema for replay and target
  adapter type mapping
- `response.rows`: resultset rows as arrays of MySQL values
- `response.affected_rows`: OK response affected row count
- `response.last_insert_id`: OK response insert id
- `response.error_code` and `response.error_message`: error response details
- `response.rows_truncated`: true when result rows were truncated
- `parse_warnings`: parser warnings that may make replay unsafe

Match MySQL calls by dependency identity first, then normalized SQL plus parsed
`params`. The identity is `target_host`, `target_port`, `database`, and
`username`; `target_host` must be the business/original domain seen by the
application. Normalize SQL by collapsing whitespace while preserving
placeholders. Preserve ordering for transactions, locks, repeated SQL, stateful
sessions, and connection-specific behavior. Do not use `statement_id` as a
stable replay key across connections.

## Replay Risks

Treat these as unsafe or incomplete MySQL replay evidence:

- missing `sql` for `COM_QUERY`, `COM_STMT_PREPARE`, or `COM_STMT_EXECUTE`
- missing business `target_host`, `target_port`, default `database`, or
  `username`
- fake or upstream IP identity instead of the business/original target host
- `COM_STMT_EXECUTE` without parsed `params`
- resultsets without semantic column family, SQL type, nullability, or numeric
  signedness
- non-empty `parse_warnings` or `response.rows_truncated == true`
- global use of the connection-local `statement_id`
- stateful SQL replay without required ordering or connection state
- `mysql_tls_rejected`, because MySQL TLS MITM is intentionally unsupported

Use `dependencies-debug.jsonl` to explain parser gaps, not as the primary
replay source. Raw/base64 payloads are less reliable than semantic
`mysql_exchange` records.

## Resultset Schema

MySQL resultset columns in `dependencies.jsonl` are semantic, not wire-protocol
columns. Expected fields:

- `name`: resultset column name used by the application, including aliases
- `table`: source table when known
- `column`: source column when known
- `family`: language-facing type family such as `integer`, `string`,
  `decimal`, `float`, `datetime`, `date`, `time`, `binary`, `json`, `bit`,
  `geometry`, `null`, or `unknown`
- `sql_type`: SQL/MySQL type name such as `INT`, `BIGINT`, `VARCHAR`,
  `TEXT`, `DATETIME`, or `DECIMAL`; do not use MySQL protocol names such as
  `LONG` or `LONGLONG` here
- `unsigned`: true/false for numeric types where signedness applies
- `bits`: numeric width when known, such as 32 for `INT` and 64 for `BIGINT`
- `nullable`: true/false when known
- `scale`: decimal scale when known

Use `name` for resultset access and `table` plus `column` for source schema
evidence. For example, `SELECT user_appkey.id AS appkey_id` should have
`name: "appkey_id"` and `column: "id"`.

MySQL values contain:

- `kind`: value kind such as null, integer, string, bytes, date, or
  parser-specific type
- `value`: JSON value when parsed
- `raw`: base64 body capture when the value could not be represented cleanly
