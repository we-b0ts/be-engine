# Recorded Case Format

Use this reference when parsing recorded case artifacts or translating them into
target-project E2E inputs and dependency replay config.

## Directory And Files

Canonical published case layout:

```text
recordings/<run-id>/traffic.jsonl
recordings/<run-id>/recording-run.json
recordings/<run-id>/errors.jsonl
recordings/<run-id>/bootstrap-dependencies.jsonl
recordings/<run-id>/bootstrap-dependencies-summary.json
recordings/<run-id>/bootstrap-dependencies-debug.jsonl
recordings/<run-id>/<rule>/<uri-group>/<case-id>/request.json
recordings/<run-id>/<rule>/<uri-group>/<case-id>/expected-response.json
recordings/<run-id>/<rule>/<uri-group>/<case-id>/dependencies.jsonl
recordings/<run-id>/<rule>/<uri-group>/<case-id>/dependencies-summary.json
recordings/<run-id>/<rule>/<uri-group>/<case-id>/dependencies-debug.jsonl
recordings/<run-id>/failed/<rule>/<uri-group>/<case-id>/
```

Each recorder process creates one `YYYYMMDDHHMMSS` run directory. Do not scan
`failed`, `staging`, or `.replay` as case collections. Failed case directories
may contain `.partial`, `.truncated`, and `recording-error.json` files. They are
evidence for recorder configuration or recorder implementation fixes, not E2E
replay fixtures.

`uri-group` is usually built from the full request URI path joined by hyphens,
for example `/api/users/list` becomes `api-users-list`. When the recorder rule
defines segment-wildcard `case_path_patterns`, the matching pattern defines the
group instead: `/api/users/123/xxx` with `/api/users/*/xxx` becomes
`api-users-wildcard-xxx`.

A path ending at `recordings/<run-id>/<rule>/<uri-group>` is a case collection,
not a single case. A path ending at `recordings/<run-id>` is a run collection
and may contain multiple rules and URI groups. To select cases, open each
published child `request.json` and match the recorded `uri` path against the
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
5. run-level `bootstrap-dependencies.jsonl` when present
6. run-level `bootstrap-dependencies-summary.json` when present
7. `dependencies-debug.jsonl` only for missing semantic data, parse warnings, or
   protocol debugging

If canonical `request.json` or `expected-response.json` is missing and only
`.partial` or `.truncated` variants exist, stop. The case was not published as
valid and must be re-recorded after fixing recorder limits, service readiness,
or recorder behavior.

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

`expected-response.json` is assertion-only evidence. MUST NOT read its status,
headers, body, or derived values to produce the target's actual response,
configure product/replay behavior, seed database/HTTP/cache/queue dependency
results, decide whether a dependency is called, or manufacture a cache or side
effect. If the target cannot generate the result from request/session context,
source behavior, product config, time/generated values, and recorded
dependencies alone, keep the case incomplete. A passing comparison after
reverse-feeding expected data is an invalid circular test.

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
`data` before sending the request or comparing exact bytes. Published HTTP
cases should not have truncated request or expected-response bodies. If they do,
treat the recording as invalid and report a recorder improvement instead of
weakening assertions.

## Dependency Files

`dependencies.jsonl` contains semantic dependency records for managed replay.
Each line is a JSON object with `event_type`.

Newly published cases include this file even when they have no semantic
third-party dependencies. In that case the file is empty and
`dependencies-summary.json` has `total_events: 0`; treat this as a confirmed
zero-dependency contract. A missing file in an older recording is not
equivalent evidence and still requires case-specific investigation.

Common semantic records:

- `mysql_exchange`: structured SQL request and response; preferred for replay
- `mysql_connection`: connection metadata
- `redis_connection` / `redis_exchange`: RESP version and session identity,
  normalized command, binary-safe arguments, and exact response frame
- `memcached_connection` / `memcached_exchange`: Text/Binary wire protocol,
  request semantics, CAS/quiet/noreply metadata, and exact response frames
- `kafka_connection`: business target and replay-safety metadata
- `kafka_produce`: exact topic, nullable key/value bytes, headers, and accepted
  result for an outbound Kafka record
- `kafka_delivery`: exact topic, nullable key/value bytes, headers, and timestamp
  for a Kafka record delivered to the application
- `tcp_gateway_connection`: captured TCP/fake-IP dependency connection metadata
- `udp_datagram`: captured UDP/fake-IP dependency datagram or push side effect
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

- Successful protocol setup is omitted from `dependencies.jsonl` and from the
  acceptance summary; the debug file keeps raw protocol evidence.
- Executed dependency calls, returned rows, write results, and dependency
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
- `redis`: connection/exchange counts, targets, RESP versions, commands,
  response kinds, errors, unsafe evidence, and byte counts. It never lists
  credentials, keys, or values.
- `memcached`: connection/exchange counts, targets, wire protocols, commands,
  normalized response statuses, hit/miss/error and quiet/noreply counts, unsafe
  evidence, and byte counts. It never lists keys or values.
- `kafka`: connection, produced and delivered record counts, topics, targets,
  unsafe evidence, and aggregate key/header/value byte counts. It never lists
  message contents.
- `http`: call counts, methods, authorities, status codes, and errors.
- `tcp_gateway`: connection counts, domains, upstreams, and errors.
- `udp`: datagram counts, protocols, target hosts/addrs, upstreams, payload
  bytes, forwarding counts, and errors.
- `proxy_errors`: protocol and target error counts.

The summary is an index for coverage and triage. Use `dependencies.jsonl` as the
source of replay payloads and exact dependency behavior.

`bootstrap-dependencies.jsonl` is a run-level replay dependency file for
startup/bootstrap traffic captured before the first case starts. It is shared
across cases from the same recording run. Do not move it into a case directory
unless packaging a standalone case bundle; replay should discover it by walking
upward from the case directory. Its debug and summary companions use the same
naming pattern: `bootstrap-dependencies-debug.jsonl` and
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
