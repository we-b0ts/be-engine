# Generated dependency request fields

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v1` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


These contracts compare request copies while preserving the recordings and
recorded responses. All entries below belong in version 3 `dependency_rules`.
Normal protocol rules use `case: {method, path}` for the inbound HTTP API;
`dynamic_value` retains its existing route-only `api` selector.

Redis keys containing time-window indices or generated identities use explicit
[Redis key contracts](redis-key-contracts.md). A key capture can compose JSON
identity references and existing timestamp fields in the same atomic request
contract. This preserves strict stable fields and avoids exempting an entire SET.

## Source request conditions

Both rule families accept an optional top-level `when` to select the Source
branch that generates a dependency value. For Redis protocol rules, only argument
request contracts support `when`; unordered values, lock tokens, PUBLISH UUIDs
and response time shifts reject it. Dynamic captures support it independently.
For example, initialization can select
`/event_type: {equals: session.created}` while a separate update rule selects
`/event_type: {not_equals: session.created}`:

```yaml
when:
  request_body_json:
    /event_type: {equals: session.created}
```

Use the field that the Source handler actually dispatches on. The conditions
read immutable recorded inbound `request.json` body captures, in UTF-8 or
base64 encoding. They do not inspect Target output or grant sharing. Existing
API, endpoint, database, key, ordering and finite-consumption checks still apply.

Declare 1–16 exact, non-root JSON Pointers, with one `equals` or `not_equals`
operator per pointer. Conditions are ANDed. Expected values must be non-null
strings, numbers or booleans; strings are limited to 1024 bytes. Operators retain
JSON scalar types, with no string/number/boolean coercion. A missing pointer,
null, object, array, type mismatch, invalid capture encoding, decoding error,
duplicate JSON member, truncated body or JSON body larger than 1 MiB matches
neither operator. In particular, `not_equals` does not turn missing evidence
into permission to normalize. Omitting `when` retains the existing API scope.

Ownership checks can prove two scopes disjoint from differing `equals` values
at the same pointer, or `equals` and `not_equals` of the same value. Different
pointers or two `not_equals` conditions remain conservatively overlapping.
When initialization regenerates a timestamp but later updates preserve it,
partition the rules explicitly; adding the field to a broader update rule would
also normalize values that Source preserves.

## Integer JSON-RPC correlation ID

```yaml
- id: rpc-correlation
  kind: dynamic_value
  api: /knowledge/*/nodes
  value_type: integer
  targets: [{host: rpc.internal, port: 443}]
  capture:
    protocol: http
    target: {host: rpc.internal, port: 443}
    method: POST
    path: /mcp/knowledge/sse
    json_pointer: /id
  source_evidence: 'RpcClient:request increments an integer correlation counter'
```

The default remains `value_type: string`. Integer captures preserve JSON type
and bind only the selected pointer on the selected request. They do not infer
references in other numbers, strings, paths, Redis arguments or response IDs.
Redis JSON captures also support `value_type: integer` for an explicit pointer
in a SET/HSET value or RPUSH element. Floats, stringified integers, missing
pointers and inconsistent bindings fail.
Stable JSON members and the original HTTP path/query remain checked.

## Redis SET JSON containing generated JWTs and a timestamp

```yaml
- id: approved-session
  protocol: redis
  case: {method: POST, path: /sessions/*/approve}
  target: {host: cache.internal, port: 6379}
  source_evidence: 'Session:approve writes current Unix seconds and two signed tokens'
  redis:
    database: 0
    key: {prefix: 'session:'}
    commands:
    - command: SET
      argument_values:
        1:
          json:
            /approved_at: {time: preserve_relative, format: unix_seconds}
            /access_token:
              jwt:
                signing_key_source: {kind: target_env, name: SECRET_KEY}
                algorithm: HS256
                relative_to: /approved_at
            /refresh_token:
              jwt:
                signing_key_source: {kind: target_env, name: SECRET_KEY}
                algorithm: HS256
                relative_to: /approved_at
                dynamic_claims: [/jti]
```

Argument indices exclude the command: SET key is index 0, value is index 1,
and options such as `EX 300` remain exact. JSON members use exact, nonoverlapping
JSON pointers and are validated together. JSON serialization order may differ;
unselected values, member presence and array order must agree.

Both JWT signatures must verify using the declared target startup input. Keys
are cached privately for the Replay session and never included in rules,
plans or diagnostics. `target_file` with `path` and `field` also works through
the existing read-only startup mount mechanism. Supported algorithms are
HS256, HS384 and HS512. Header values and stable claims must agree. `exp` is
required; `exp`, `iat` and `nbf` retain their relative relationship to the
selected JSON timestamp. Historical tokens are checked at their generation
time. An explicit `/jti` permits a bijective case-local UUID v4 binding; other
dynamic claims are rejected. A failed field leaves all bindings uncommitted.

## Redis write timestamps with preserved parameter differences

```yaml
- id: presence-time
  protocol: redis
  case: {method: PUT, path: /presence}
  target: {host: cache.internal, port: 6379}
  source_evidence: 'Presence:update uses current time for expiry score and cleanup cutoff'
  redis:
    database: 0
    key: {prefix: 'presence:', numeric: true}
    commands:
    - command: ZADD
      argument_values:
        1: {time: preserve_relative, format: unix_seconds}
    - command: ZREMRANGEBYSCORE
      argument_values:
        2: {time: preserve_relative, format: unix_seconds}
```

There is no configured clock or offset. The source anchor is the immutable
inbound recording timestamp; the target anchor is taken by Replay immediately
before the engine sends the inbound request. Each selected time preserves its
distance from its own anchor. Integer and fractional Unix seconds are supported;
the numeric category is preserved. Tolerance is fixed at 5s and is omitted from
generated rules. Legacy explicit 5s remains readable; other values are rejected.

The command list also preserves order and the recorded parameter difference
within 1 microsecond. The sequence resets after each complete update, allowing
later updates on the same key. It does not pin the key to its first update time.
This initial implementation supports a plain single-member ZADD score and a
ZREMRANGEBYSCORE maximum. Keys, members, range minimums, extra options, database,
authentication, connection lanes and finite consumption remain checked.

Redis SET/RPUSH JSON time fields also accept `format: rfc3339`. For example,
`/last_activity_at: {time: preserve_relative, format: rfc3339}` compares the two
ISO timestamps relative to their own captured request anchors. No configured
clock, offset or timezone is needed; invalid times and changed stable JSON fields
still fail.

## Redis script ARGV timestamps

```yaml
- id: callback-script-time
  protocol: redis
  case: {method: POST, path: /internal/callback}
  target: {host: cache.internal, port: 6379}
  source_evidence: 'Callback:enqueue passes current milliseconds as the first Lua ARGV'
  redis:
    database: 0
    key: {prefix: 'callback:'}
    commands:
    - command: EVALSHA
      script: {sha1: '0123456789abcdef0123456789abcdef01234567'}
      argument_values:
        3: {time: preserve_relative, format: unix_milliseconds}
```

Supply the actual script digest from source and immutable evidence. EVALSHA
requires its 40-digit SHA1; EVAL instead requires `script: {sha256: '...'}`
with the SHA256 of the exact Lua bytes. Replay never interprets or executes Lua.
For `EVALSHA digest 1 key timestamp`, argument index 3 is ARGV[1]. The key
selector scopes the first KEYS entry; all KEYS, numkeys, script bytes/digest and
unselected ARGV remain exact. Rules require 1..32 keys and at most 128 argument
indices. Selected indices must lie in the present ARGV region, never KEYS.
Unix seconds, milliseconds and microseconds retain numeric category and request-relative
offsets. JSON rules may also select exact time pointers inside an ARGV argument;
all remaining JSON members and array order stay exact. Related time parameters
retain their differences; independent clock reads require explicit groups below.
SCRIPT LOAD remains an ordinary exact dependency exchange.

## Script JSON and microsecond timestamp copies

For seven KEYS, ARGV[1] is argument index 9: in general ARGV[n] is
`numkeys + 1 + n`. Select raw argument indices, excluding the command name.
For example, a script taking seconds in ARGV[5], microseconds in ARGV[6],
a JSON state in ARGV[7], and a second independent clock read in ARGV[9] uses:

```yaml
redis:
  database: 0
  key: {prefix: 'metrics:'}
  commands:
  - command: EVALSHA
    script: {sha1: '0123456789abcdef0123456789abcdef01234567'}
    argument_values:
      13: {time: preserve_relative, format: unix_seconds, clock_group: event}
      14: {time: preserve_relative, format: unix_microseconds, clock_group: event}
      15:
        json:
          /changed_at_us: {time: preserve_relative, format: unix_microseconds, clock_group: event}
      17: {time: preserve_relative, format: unix_seconds, clock_group: after_commit}
```

This also works for EVAL with the exact Lua SHA256. Script identity, every
KEYS entry, numkeys and unselected ARGV remain checked. JSON arguments require
complete unique-member JSON and exact nonoverlapping field pointers, just like
SET/RPUSH. Script JSON fields do not enable signed JWT normalization outside SET.
Integer microseconds are scaled directly to integer nanoseconds, including
values above JavaScript's exact integer range. Numeric strings are rejected.
By default all selected times preserve a common shift within one microsecond;
when two source timestamps are exactly equal, their target copies must be exactly
equal. Named clock groups limit these relationship checks to related fields as
specified below. The same comparator validates protected planning witnesses and
live Replay.

## Independent clock groups

An optional `clock_group` on each request time field explicitly identifies
fields sharing one source clock read or a derived time window. This works across
Redis scalar arguments, JSON pointers and ordered command sequences, and HTTP
JSON time pointers. Names use 1..64 ASCII letters, digits, underscores or hyphens;
names are case-sensitive. Omitted names share one legacy group, distinct from
every named group. Existing rules and their serialized form remain unchanged.

Within a group, all fields retain the existing common shift within one
microsecond. Equal Source instants, including seconds/microseconds/JSON copies,
require exactly equal Target instants. This keeps fixed TTLs, window lengths and
copies checked. Sequence groups persist across its commands and reset only when
the sequence completes; names do not share state across rules or cases.

Between groups, elapsed execution time may change. For example, a clock read
before flush and a second read after commit can be 48 ms apart in Source and
2 microseconds apart in Target. The example above puts the first read's three
copies in `event` and the second read in `after_commit`. Every field still
preserves its own distance from the independently captured request start within
the fixed inclusive five-second window. Missing anchors, wrong numeric types,
wrong units, inconsistent copies within a group and changed stable fields fail.
Coincident values from independently read clocks do not infer a shared clock.

Prove each group's source generation in `source_evidence`. Keep a timestamp and
its derived expiry, cutoff or copies together; separate names describe actual
independent clock reads, not a way to relax a failed TTL or copy relationship.
Group declarations never select a clock or supply a time offset. Planning and
Replay use the same group checks, frozen evidence and ordinary apply/fresh-Replay
lifecycle. Already applied rules must be revised through that lifecycle.

## PUBLISH JSON timestamps and publisher UUIDs

```yaml
- id: completion-time
  protocol: redis
  case: {method: POST, path: /internal/callback}
  target: {host: cache.internal, port: 6379}
  source_evidence: 'Emitter generates local ISO completion times; deployment fixes TZ to UTC'
  redis:
    database: 0
    key: socketio
    commands:
    - command: PUBLISH
      argument_values:
        1:
          json:
            /data/0/completed_at:
              time: preserve_relative
              format: iso8601_naive
              utc_offset: '+00:00'
```

PUBLISH time contracts require one command, an exact channel, and time-only JSON
fields. They select only recorded messages containing every declared pointer.
A Source message without the pointer retains ordinary exact/UUID matching; a
selected Source message with a missing Target pointer fails. Channel, event,
room, status, task identity and all other unselected JSON values remain checked.
Invalid or duplicate-member JSON cannot use the time contract. No binary
serializer is interpreted by this JSON capability.

For ISO strings without a timezone, `iso8601_naive` requires an explicit
source-proven fixed `utc_offset` in `+/-HH:MM` form, at most 14 hours. Do not
infer the timezone from a displayed date or the Replay host. Fixed offsets do
not model daylight-saving transitions; use a timezone-bearing source format
when those transitions are required. RFC3339 retains its embedded timezone and
rejects `utc_offset`. All formats use the independently captured request clocks
and fixed inclusive five-second relative window; there is no wall-clock fallback.

Existing [PUBLISH UUID rules](redis-publish-rules.md) compose with these time
contracts. Apply the source-proven publisher UUID rule first using a UUID-only
failure witness, then obtain fresh Replay evidence for the time rule. The UUID
binding remains session-wide and bijective, including ordinary messages that
have no selected time. Only declared UUID copies and time fields may differ;
all validations must pass before committing either binding or consuming the
exchange. JSON whitespace and member order may differ for selected messages.
Use the existing `dirty_clusters` → `rule plan --dependency-request RULE_JSON`
→ apply → fresh Replay workflow; recordings remain immutable.

## RPUSH JSON identities and timestamps

A dynamic-value rule can select `capture.command: RPUSH`, an element
`argument_index` in 1..128, and an exact `json_pointer: /id`. Use
`value_type: integer` only when the source ID is a JSON integer. A separate
request contract can select a disjoint time pointer in that same element:

```yaml
redis:
  database: 0
  key: callback:events
  commands:
  - command: RPUSH
    argument_values:
      1:
        json:
          /timestamp: {time: preserve_relative, format: unix_seconds}
```

The two contracts compose on comparison copies. Capture the ID, apply that
rule and run fresh Replay; then plan the time contract from its protected
failure witness. Planning honors already applied identity rules. Discovery
can report separate typed scalar candidates in one RPUSH JSON element, but
does not infer which field is an identity or a time. Source proof is required
for each selected field. Overlapping pointers are rejected; other fields,
element count/order, keys, session identity and finite consumption stay strict.

Managed E2E sends the internal `request_begin` control command after preparing
the inbound request. For manual low-level Replay, call
`traffic-e2e diagnose replay-control --session SESSION request-begin CASE_ID`
immediately before sending that request. Beginning a case alone does not supply
a time anchor, and missing anchors fail closed.

## HTTP JSON request timestamps

```yaml
- id: query-window
  protocol: http
  case: {method: POST, path: /windows/*}
  target: {host: metrics.internal, port: 443}
  source_evidence: 'WindowClient:query sets end to current seconds and start to end minus its lookback'
  http:
    method: POST
    path: /query
    json:
      time:
        /start: {time: preserve_relative, format: unix_seconds}
        /end: {time: preserve_relative, format: unix_seconds}
```

Each selected field preserves its offset from its own **dependency request**
start, with the fixed inclusive 5s tolerance. The recorded anchor is
`request_started_at`, or recorded completion minus duration for older captures;
Replay captures the target anchor when the outbound HTTP request starts. Missing
clocks fail closed. No configured clock, business-specific offset or outgoing
request rewrite is involved. Fields within the same clock group (one shared
unnamed group by default) must share the same shift within 1 microsecond,
preserving the recorded start/end window. Independent reads can use the explicit
`clock_group` contract above.

Supported formats are `unix_seconds`, `unix_milliseconds`, `unix_microseconds`,
`rfc3339` and explicit-offset `iso8601_naive` as described below.
JSON numeric categories remain checked. Select 1..32 exact non-root JSON
pointers; wildcard and overlapping pointers are rejected. Bodies must be complete
unique-member JSON of at most 1 MiB. Other JSON members, array ordering, path,
query and identity headers remain exact, including authentication. The rule
requires an explicit inbound case method/path and exact dependency host/port.
Overlapping HTTP normalizations or dynamic captures at that endpoint and case
are rejected. Case ownership and finite response consumption are unchanged.

Discovery exposes `http_json_request_time` failure candidates without body or
header values. Use the existing `rule plan --dependency-request RULE_JSON`,
apply, then fresh Replay workflow below. Complete existing HTTP recordings can
be reused without recording again.

When several request bodies share an endpoint, planning pairs witnesses by all
JSON fields outside the declared time pointers before validating timestamps.
Candidates with different stable fields are skipped. A matching pair still
requires valid timestamp types, request-relative times and parameter differences;
planning requires at least one verified same-case pair. Fresh Replay continues
to enforce stable fields and finite response consumption.

## HTTP multipart boundary

```yaml
- id: multipart-upload
  protocol: http
  case: {method: POST, path: /attachments/*}
  target: {host: upload.internal, port: 80}
  source_evidence: 'Uploader:build generates a fresh multipart boundary'
  http:
    method: POST
    path: /upload
    multipart: {boundary: normalize}
```

Only matching multipart delimiters and the Content-Type boundary may differ.
The parser requires a complete form-data body and matching boundary declaration.
Part header bytes, field names/values, filenames, content types, ordering,
multiplicity and file bytes remain exact. Other Content-Type parameters,
non-transport identity headers, path and query remain checked. Truncation,
duplicate boundary declarations, malformed delimiters or trailing bytes fail.
Bodies are bounded to 16 MiB, 128 parts and 16 KiB of headers per part.

## Existing discovery and authoring workflow

1. Run focused Replay, then query `dirty_clusters` evidence. Integer differences
   appear in `dynamic_capture_candidates`; the other contracts appear in
   `dependency_request_candidates`. Review the source generator before selecting
   locations. JWT candidates also expose the existing `signing_key_discovery`
   projection of startup variable names and mount paths.
2. Use `backend-rewrite rule plan --evidence-id ID --dynamic-value RULE_JSON`
   for the integer rule, or `--dependency-request RULE_JSON` for request contracts.
   Supply `--source-evidence 'file:function explains generation and semantics'`.
   The coordinator supplies the active inbound API scope. Plan one family at a
   time; no response body codec is needed.
3. Apply with `backend-rewrite rule apply --plan-id ID`, then run fresh Replay
   using the existing recordings. Usage and unused applicable rules are reported
   through the existing policy gates.

Planning requires a finalized report under the current policy and complete,
same-case immutable dependency witnesses. A failed first Redis command may
prevent later target commands; every configured command must nevertheless be
present for the same key in the source recording. Runtime verifies the complete
target sequence after apply.

Target witnesses are bounded to 64 candidates and 1 MiB each, authenticated and
encrypted with the existing managed recording key. Discovery removes encrypted
payloads and exposes metadata only. Multipart witnesses use SHA-256 digests of
complete part bytes, so larger file content does not inflate the protected report.
Witness encryption also authenticates the
endpoint, command, case and request-time anchor. A missing key prevents witness
capture; initialize the managed key or provide `TRAFFIC_E2E_ENCRYPTION_KEY_B64`
for external recordings before fresh Replay. Plans reject changed policy,
report or source witnesses, and applying a rule never marks old Replay as passed.
