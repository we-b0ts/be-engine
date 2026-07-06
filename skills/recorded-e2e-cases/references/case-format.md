# Recorded Case Format

Use this reference when parsing recorded case artifacts or translating them into
target-project test inputs and mocks.

## Directory And Files

Canonical case layout:

```text
recordings/<rule>/<uri-group>/<case-id>/request.json
recordings/<rule>/<uri-group>/<case-id>/expected-response.json
recordings/<rule>/<uri-group>/<case-id>/dependencies.jsonl
recordings/<rule>/<uri-group>/<case-id>/dependencies-debug.jsonl
```

`uri-group` is usually built from the first two URI path segments joined by
hyphens, for example `/api/users/list` becomes `api-users`. Older recordings may
omit this directory and use `recordings/<rule>/<case-id>`.

A path ending at `recordings/<rule>/<uri-group>` is a case collection, not a
single case. Its direct child directories are case ids, commonly UUIDs. The
collection can contain cases for related but different URLs. To select a case,
open each child `request.json` and match the recorded `uri` path against the
requested API/function scope. Do not infer the selected API from `uri-group`
alone.

Treat `expected_response.json` as a tolerated user spelling only. Prefer
`expected-response.json` in new references and test names. Do not rename or
rewrite recorded files during replay work.

Load order:

1. `request.json`
2. `expected-response.json`
3. `dependencies.jsonl`
4. `dependencies-debug.jsonl` only for missing semantic data, parse warnings, or
   protocol debugging

## HTTP Boundary Files

`request.json` records the inbound HTTP gateway request:

- `timestamp`: capture time
- `client_addr`: original client socket address, when known
- `method`: HTTP method
- `uri`: path and query as received by the gateway
- `authority`: original authority/host, when known
- `matched_rule`: gateway rule name, when a rule matched
- `upstream`: upstream base URL used during recording
- `headers`: lowercase header map, values as arrays
- `body`: case body capture

`expected-response.json` records the upstream response observed for that request:

- `timestamp`: capture time
- `matched_rule`: gateway rule name, when a rule matched
- `upstream`: upstream base URL used during recording
- `status`: HTTP status, or null when the upstream call failed
- `headers`: lowercase response header map, or null when unavailable
- `body`: case body capture, or null when unavailable
- `duration_ms`: observed upstream duration
- `error`: recorder/upstream error, or null

Use `method`, `uri`, headers, and body to drive the request. Use `status` and
meaningful body fields for assertions. Assert headers only when they are
business-relevant or the target project's existing E2E style already does so.

## Body Capture

HTTP case body fields:

- `encoding`: `utf8` or `base64`
- `original_len`: byte length before truncation
- `stored_len`: byte length stored in the case file
- `truncated`: true when the body exceeded recorder limits
- `decoded`: true when gzip/deflate content was decoded before storage
- `content_encoding`: original `Content-Encoding`, when present
- `data`: UTF-8 text or base64 bytes depending on `encoding`
- `decode_error`: decode error text, or null

If `encoding` is `utf8`, use `data` directly. If `encoding` is `base64`, decode
`data` before sending the request or comparing bytes. If `truncated` is true,
avoid exact full-body assertions; assert only stable fields available in the
stored data.

## Dependency Files

`dependencies.jsonl` contains semantic dependency records for mocks and replay.
Each line is a JSON object with `event_type`.

Common semantic records:

- `mysql_exchange`: structured SQL request and response; preferred for mocks
- `mysql_connection`: connection metadata
- `tcp_gateway_connection`: captured TCP/fake-IP dependency connection metadata
- `mysql_tls_rejected`: MySQL TLS rejection event; MySQL TLS MITM is out of scope
- `proxy_error`: recorder or dependency proxy error

Case dependency records also include `case_dependency_matched_by`:

- `process`: dependency process matched the active upstream process
- `active_window`: dependency occurred during the active request/response window

Case dependency records compact `client_process` to the process id. The global
`traffic.jsonl` may contain full process details, but normal replay should rely
on the case-local dependency files.

`dependencies-debug.jsonl` contains raw/protocol records such as `mysql_query`,
`mysql_response`, and `mysql_packet`. Keep these out of normal E2E assertions
unless the protocol detail itself is under test. Raw MySQL protocol type names,
type codes, and flags belong in debug records, not normal semantic replay data.

## MySQL Exchange Records

Prefer `mysql_exchange` over raw MySQL records. Important fields:

- `connection_id`: connection-scoped id
- `query_sequence`: sequence of queries on the connection
- `command`: MySQL command name
- `sql`: SQL text, when parsed
- `statement_id`: prepared statement id; connection-local only
- `params`: parsed prepared statement parameters, when available
- `response.status`: `resultset`, `ok`, `error`, `incomplete`, or another parser
  status
- `response.columns`: decoded resultset column schema for replay and target
  adapter type mapping
- `response.rows`: resultset rows as arrays of MySQL values
- `response.affected_rows`: OK response affected row count
- `response.last_insert_id`: OK response insert id
- `response.error_code` and `response.error_message`: error response details
- `response.rows_truncated`: true when result rows were truncated
- `parse_warnings`: parser warnings that may make replay unsafe

Match MySQL calls by normalized SQL plus parsed `params`. Normalize SQL by
collapsing whitespace while preserving placeholders. Preserve ordering for
transactions, locks, repeated SQL, stateful sessions, and connection-specific
behavior. Do not use `statement_id` as a stable mock key across connections.

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

- `kind`: value kind such as null, integer, string, bytes, date, or parser-specific
  type
- `value`: JSON value when parsed
- `raw`: base64 body capture when the value could not be represented cleanly
