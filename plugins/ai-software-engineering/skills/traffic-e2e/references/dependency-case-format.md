# Traffic E2E Dependency Case Format

Read this reference when inspecting recorder-owned semantic dependency,
summary, debug, or Global files.

## Contents

- Semantic records
- Summary records
- Global dependency records

## Semantic Records

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
  result for an outbound Kafka record, grouped by connection/request sequence
- `kafka_fetch`: requested topic set plus response or client-termination timing
- `kafka_delivery`: exact topic, nullable key/value bytes, headers, and
  timestamp for a Kafka record delivered to the application, associated to its
  Fetch
- `motan_connection` / `motan_exchange`: legacy Motan target metadata, codec and
  method identity, exact binary frames, response outcome, and duration; the
  frames may contain sensitive business objects
- `tcp_gateway_connection`: captured TCP/fake-IP dependency connection metadata
- `udp_datagram`: captured UDP/fake-IP dependency datagram or push side effect
- `mysql_tls_rejected`: MySQL TLS rejection event; MySQL TLS MITM is out of scope
- `proxy_error`: recorder or dependency proxy error

Semantic MySQL, Redis, Memcached, Kafka Produce/Fetch, and Motan exchanges carry
`duration_ms` and an `outcome`. Replay waits the recorded duration before
delivering a normal response. A replay-safe `client_terminated` exchange sends
no response bytes and remains unconsumed until the same physical client
connection closes or resets in the recorded timing window. Replay does not
proactively close that connection; a missing, early, or late client
termination is dirty replay evidence. Protocol commands such as MySQL
statement close/quit, Memcached noreply/quiet, and Kafka Produce with `acks=0`
remain `no_response` behavior rather than client timeouts.

Case dependency records also include `case_dependency_matched_by`:

- `active_window`: dependency occurred during the single active
  request/response window in the recorder network namespace

Normal replay should rely on recorder-owned consumption of the case-local
dependency files. Target code, tests, commands, and config must never consume
them as fixtures.

`dependencies-debug.jsonl` contains raw/protocol records such as `mysql_query`,
`mysql_response`, and `mysql_packet`. Keep these out of normal E2E assertions
unless the protocol detail itself is under test. Raw MySQL protocol type names,
type codes, and flags belong in debug records, not normal semantic replay data.
Recognized legacy Motan heartbeats are also debug-only; replay may reuse their
exact response frame as protocol-maintenance behavior, but they are not a
business dependency or acceptance-summary item.

## Summary Records

`dependencies-summary.json` is a derived coverage checklist generated from
`dependencies.jsonl`. It is not the source of dependency data. Use it to see
which protocols, CRUD operations, tables, hosts, side effects, and errors the
case recorded, and to verify that replay covered the behavior that matters for
the case. If it is absent, rely on recorder replay reports and inspect the
semantic file only for recorder diagnosis; do not derive a target-project
fixture or behavior source.

Summary rules:

- Successful protocol setup is omitted from `dependencies.jsonl` and from the
  acceptance summary; the debug file keeps raw protocol evidence.
- Recorder-recognized driver maintenance probes are also debug-only and are
  handled as deterministic built-ins during replay.
- Executed dependency calls, returned rows, write results, and dependency
  failures are semantic dependencies and should appear in `dependencies.jsonl`
  and the summary.
- Dependency coverage should compare response-driving, auth/session, and
  required side-effect behavior. Exclude source-proven process-level HTTP
  polling from case attribution with a configured background rule and a new
  recording. Existing dirty case exchanges are not retroactively reclassified
  during replay.

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
- `motan`: connection/exchange counts, targets, codec versions, methods,
  exceptions, client terminations, and unsafe evidence. It never lists RPC
  argument or response contents.
- `http`: call counts, methods, authorities, status codes, and errors.
- `tcp_gateway`: connection counts, domains, upstreams, and errors.
- `udp`: datagram counts, protocols, target hosts/addrs, upstreams, payload
  bytes, forwarding counts, and errors.
- `proxy_errors`: protocol and target error counts.

The summary is an index for coverage and triage. Recorder-owned replay alone
uses `dependencies.jsonl` as the source of replay payloads and exact dependency
behavior.

## Global Dependency Records

`global-dependencies.jsonl` is shared run-level replay inventory. It contains
startup/bootstrap traffic captured before case admission and traffic matched
by an explicit background rule during bootstrap or runtime. Each record has a
reason, phase, and matching rule/window owner. Do not move it into a case
directory unless packaging a standalone case bundle; Replay discovers it by
walking upward from the case directory.

The debug and summary companions are `global-dependencies-debug.jsonl` and
`global-dependencies-summary.json`. Recorder flushes startup records before
opening case admission but keeps the Global writer available for later rule
matches; it generates the summary during final shutdown. Ready-time idle
traffic without a rule is not replay inventory.

Read [background-dependencies.md](background-dependencies.md) for the complete
ownership, phase, and rule contract. For semantic MySQL exchange fields,
matching identity, replay risks, and resultset schema, read
[mysql-case-format.md](mysql-case-format.md).
