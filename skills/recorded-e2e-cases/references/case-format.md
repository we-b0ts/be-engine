# Recorded Case Format

Use this reference when parsing recorded case artifacts or translating them into
target-project E2E inputs and dependency replay config.

## Directory And Files

Canonical case layout:

```text
recordings/<rule>/<uri-group>/<case-id>/request.json
recordings/<rule>/<uri-group>/<case-id>/expected-response.json
recordings/<rule>/<uri-group>/<case-id>/dependencies.jsonl
recordings/<rule>/<uri-group>/<case-id>/dependencies-summary.json
recordings/<rule>/<uri-group>/<case-id>/dependencies-debug.jsonl
recordings/bootstrap-dependencies.jsonl
recordings/bootstrap-dependencies-summary.json
recordings/bootstrap-dependencies-debug.jsonl
```

`uri-group` is usually built from the first two URI path segments joined by
hyphens, for example `/api/users/list` becomes `api-users`. Older recordings may
omit this directory and use `recordings/<rule>/<case-id>`.

A path ending at `recordings/<rule>/<uri-group>` is a case collection, not a
single case. Its direct child directories are case ids, commonly UUIDs. The
collection can contain cases for related but different URLs. To select cases,
open each child `request.json` and match the recorded `uri` path against the
requested API/function scope. Multiple matches for the same scope are a case
set and must all be considered. Do not infer the selected API from `uri-group`
alone.

Treat `expected_response.json` as a tolerated user spelling only. Prefer
`expected-response.json` in new references and test names. Do not rename or
rewrite recorded files during replay work.

Load order:

1. `request.json`
2. `expected-response.json`
3. `dependencies.jsonl`
4. `dependencies-summary.json` when present
5. root-level `bootstrap-dependencies.jsonl` when present
6. root-level `bootstrap-dependencies-summary.json` when present
7. `dependencies-debug.jsonl` only for missing semantic data, parse warnings, or
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
the response body for assertions. Assert headers only when they are
business-relevant or the target project's existing E2E style already does so.

For JSON response bodies, parse recorded and actual bodies and compare JSON
values structurally. Object member order is not meaningful. Field presence and
value kind are meaningful: a missing field, `null`, and `""` are three different
results. Arrays remain ordered unless the product contract or explicit
assertion config says otherwise.

Use byte-level comparison only for non-JSON bodies, binary payloads, or an
explicit exact-bytes assertion mode.

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
`data` before sending the request or comparing exact bytes. If `truncated` is
true, avoid exact full-body assertions; assert only stable fields available in
the stored data.

## Dependency Files

`dependencies.jsonl` contains semantic dependency records for managed replay.
Each line is a JSON object with `event_type`.

Common semantic records:

- `mysql_exchange`: structured SQL request and response; preferred for replay
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

`dependencies-summary.json` is a derived coverage checklist generated from
`dependencies.jsonl`. It is not the source of dependency data. Use it to see
which protocols, CRUD operations, tables, hosts, side effects, and errors the
case recorded, and to verify that replay covered the behavior that matters for
the case. If it is absent, derive the same working summary from
`dependencies.jsonl`.

Summary rules:

- Successful MySQL `COM_STMT_PREPARE` exchanges are omitted from
  `dependencies.jsonl` and from the acceptance summary; the debug file keeps raw
  protocol evidence.
- MySQL `COM_STMT_EXECUTE`, text query execution, execute failures, and prepare
  failures are semantic dependencies and should appear in `dependencies.jsonl`
  and the summary.
- Dependency coverage should compare response-driving, auth/session, and
  required side-effect behavior. Unrelated/background traffic may be listed but
  should not fail replay when it is safely ignored with evidence.

First-version summary fields:

- Top level: `version`, `source`, `total_events`, `event_types`, optional
  `parse_errors`, and optional protocol sections such as `mysql`, `http`,
  `tcp_gateway`, and `proxy_errors`.
- `mysql`: connection counts, TLS rejection counts, route/database/user/upstream
  counts, semantic exchange counts, executed and failed CRUD counts, resultset
  and error counts, returned/affected row totals, per-table executed/failed CRUD
  counts, per-dependency identity summaries, and compact statement records.
- `http`: call counts, methods, authorities, status codes, and errors.
- `tcp_gateway`: connection counts, domains, upstreams, and errors.
- `proxy_errors`: protocol and target error counts.

The summary is an index for coverage and triage. Use `dependencies.jsonl` as the
source of replay payloads and exact dependency behavior.

`bootstrap-dependencies.jsonl` is a root-level replay dependency file for
startup/bootstrap traffic captured before the first case starts. It is shared
across cases from the same recording directory. Do not move it into a case
directory unless packaging a standalone case bundle; replay should discover it
by walking upward from the case directory. Its debug and summary companions use
the same naming pattern: `bootstrap-dependencies-debug.jsonl` and
`bootstrap-dependencies-summary.json`. Newer recordings may close the bootstrap
window earlier when the recorder's `[http_gateway.ready]` probe observes the
configured upstream path returning the configured success status. Traffic after
that ready signal is normal idle/background traffic, not bootstrap evidence,
unless it belongs to an active case.

## MySQL Exchange Records

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

Successful prepared-statement setup is not a replay dependency by itself.
Record successful `COM_STMT_PREPARE` in debug/protocol data, not as a normal
semantic dependency. If a prepare fails, keep it as a `mysql_exchange` because
the failure is an observed dependency result or side effect.

Match MySQL calls by dependency identity first, then normalized SQL plus parsed
`params`. The identity is `target_host`, `target_port`, `database`, and
`username`; `target_host` must be the business/original domain seen by the
application. Normalize SQL by collapsing whitespace while preserving
placeholders. Preserve ordering for transactions, locks, repeated SQL, stateful
sessions, and connection-specific behavior. Do not use `statement_id` as a
stable replay key across connections.

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
