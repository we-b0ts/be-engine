# Global field formats

`project.policy` names one `traffic-policy/v2` document. Declare JSON field
formats once under `json.fields`, regardless of the API, SSE event, database
column or cache key that carries the payload. Protocol adapters still pair the
same requests, resources, rows and response positions before comparing values.
The global JSON policy controls decoded content; it does not relax that pairing.

```yaml
format: traffic-policy/v2
json:
  fields:
    /created_at: {kind: time, formats: [unix_seconds]}
    /response/created_at: {kind: time, formats: [unix_seconds]}
    /item_id: {kind: identity, formats: [uuid]}
    /item/id: {kind: identity, formats: [uuid]}
    /blocks/*/id: {kind: identity, formats: [{prefix: msg_, hex: 12}]}
    /members: {kind: unordered}
    /items/*/waitingDurationSeconds: {kind: duration, formats: [seconds]}
mysql:
  database: app
  tables:
    tasks:
      pattern: tasks
      fields:
        id: {kind: identity, formats: [uuid]}
    task_links:
      pattern: task_links_*
      fields:
        owner_id: {kind: identity, formats: [uuid]}
redis:
  database: 0
  keys:
    task-run-monitor:v2:as-of: {kind: time, formats: [unix_seconds]}
rules: []
```

The JSON policy is one map of root-relative JSON Pointers. It is not a registry
of business models. `/created_at` and `/response/created_at` describe distinct
locations; a rule does not restart at each nested object. `*` traverses array
elements only. Pointer escapes retain their ordinary JSON Pointer meaning.
Overlapping selectors for the same leaf reject during compilation.

## Decoding and format selection

The engine automatically recognizes complete JSON without duplicate object
members in supported payload positions. A MySQL JSON-valued column does not
need a table/column codec declaration. Redis storage values, HTTP bodies and
SSE data reuse the same JSON field policy. Native protocol envelopes, keys,
headers, SQL tokens, options, ordering and finite consumption remain checked by
their existing owners.

An unknown encoding compares exact bytes. A recognized Source JSON payload
fixes the encoding: malformed Target JSON or a field contract failure cannot
fall back to byte comparison. Typed Protobuf still requires a known numeric
schema; its decoded logical fields can reuse the global policy, while unknown
wire fields remain exact. Arbitrary bytes are not guessed to be Protobuf.

Each field's `formats` list is ordered. Source chooses a matching format
independently for each observed leaf; Target must satisfy that same format and
scalar type. If several numeric epoch units match, the engine chooses the
decoded Source instant closest to its independent Source request clock. A
missing clock or an equal-distance ambiguity keeps that scalar exact. Other
format alternatives use declaration order. Target values never choose the
format. Equal scalars pass exact comparison before format validation and need
no clock or time observation. A scalar matching no declared format stays exact:
it may not change. This also preserves fixed sentinels without configuration.

Supported identity formats are `uuid`, positive `decimal`, `{hex: N}`,
`{base64url: N}`, `string` and bounded `{string: N}` (1–1024 bytes). String IDs contain nonempty UTF-8 text without
control characters, bounded to 1024 bytes including their literal prefix. A literal prefix can be included in a format map, for example
`{prefix: msg_, hex: 12}` or `{prefix: item_, format: uuid}`. Prefix bytes are
literal and token lengths for hex/base64url are bounded to 1 through 1024 characters.
For a compound string ID, use a stable literal prefix plus the string format,
e.g. `{prefix: 'chat:streaming:block_content:', format: string}`. The complete
value participates in the shared correspondence; its embedded parts do not
introduce authored captures or groups. A JWT uses the whole-token identity format below.

Forwarded and fixed scalar IDs stay exact when they match no generated format.
Their equal values still reserve an internal identity anchor. This prevents the
same Source ID from being renamed inconsistently elsewhere; no extra fallback
format is authored.

Time formats include `unix_seconds`, `unix_milliseconds`, `unix_microseconds`,
`rfc3339`, `amz_date`, `iso8601_naive`, `sql_datetime` and `calendar_date`.
Calendar dates declare their fixed local offset explicitly:

```yaml
json:
  fields:
    /last_active_date: {kind: time, formats: [{format: calendar_date, utc_offset: '+08:00'}]}
```

Relative naive timestamps do not require an offset because the shared civil
offset cancels in the comparison. Consistent Source/Target timezone behavior
is still required. Native SQL dates use the protocol adapter's date arithmetic.

Fixed scalar values need no policy entry. Equal Source/Target sentinels compare
exactly without a clock. An unrecognized differing scalar fails; the engine does
not infer a business meaning from its spelling. Source-only delivery keeps
unknown formats unchanged.

A duration uses `kind: duration` with one unit in `formats`: `seconds`,
`milliseconds`, `microseconds`, `minutes` or `hours`. Equal values pass exactly;
differing values must preserve the corresponding request-clock delta in that
unit. There is no business-status predicate. Missing fields remain optional,
and status or other unselected members remain strict.

## JSON protocol formats

A JWT is one complete identity value:

```yaml
json:
  fields:
    /access_token: {kind: identity, formats: [jwt]}
    /refresh_token: {kind: identity, formats: [jwt]}
    /headers/origin: {kind: identity, formats: [{string: 255}]}
    /download_path: {kind: url, formats: [aws_sigv4]}
```

`jwt` validates compact token syntax up to 64 KiB. It does not verify a
signature, load a key, compare business claims or change the payload. Identical
complete Source tokens must correspond to identical Target tokens throughout
the case, just like UUIDs. Different signing keys, claims and clock values do
not create additional JSON policy conditions. Dependency reads deliver an
already established complete Target token; an unknown historical input remains
anchored to its original token.

Only a native inbound transformation that actually changes a JWT's time claims
needs its declared signing key and re-signing procedure. The managed runner
registers the actual derived token at its precise request send timestamp before
sending HTTP. Replay independently reconstructs that input from immutable
Source, the compiled native transformation and frozen startup keys. Only the
verified complete-token pair can override a fixed input anchor; unrelated
inputs remain exact. The private delivery is not independent Target evidence.

`aws_sigv4` checks the request-relative signing date, a 64-character lowercase
hexadecimal signature, and the credential date segment. Scheme, authority,
path, expiration, remaining query components and fragment stay exact. Duplicate
selected query parameters fail. This validates the recorded signature format;
it does not verify an S3 HMAC without a signing secret. JSON URLs use this same
format map across carriers, without repeating paths under a key or API.

## Missing values and strict remainder

Field paths are optional. If neither Source nor Target contains a selected
field, no value is validated or translated and no clock is required. Empty
wildcard selections have the same behavior. Source/Target field additions,
deletions, container changes and scalar type changes still fail. A present
`null` is a present value. Time and identity fields automatically accept paired
nulls without a clock or identity mapping. Null against a value or missing field
still fails; no null format entry is needed.

Only declared fields receive their selected semantics. Unselected members
compare exactly. `unordered` compares whole array elements as a multiset,
preserving duplicate counts and element associations. Descendant field formats
compose with bounded candidate pairing; a failed candidate does not retain
identity decisions. Array order remains strict without `unordered`.

Absent fields do not count as positive witnesses in Replay or plan/apply
preflight. Unsupported encodings remain exact rather than silently losing
their unselected content.

## Automatic identity correspondence

Rules describe identity formats. The engine maintains correspondence internally
across declared identity fields and supported carriers in the same replay case:

```text
Source: /item_id = /item/id = database.id = A
Target: /item_id = /item/id = database.id = X
```

Equal Source IDs must produce equal Target IDs. Different Source IDs cannot
collapse into one Target ID. A first eligible independent observation can
establish the correspondence; no generator-first statement or authored
equality group is needed. The engine keys complete typed values: prefixes are
not stripped for correspondence, and numeric `1` differs from string `"1"`.
The same complete value can link fields that declare different compatible
format lists. Independent replay cases have independent identity state.

Dependency reads preserve data flow. An established Source ID delivers its
corresponding Target ID. An unknown recorded ID delivered as input anchors
itself; a later write or response cannot arbitrarily rename that historical
input. Immutable API inputs are also fixed before dependency matching. A
derived delivery is not independent Target evidence.

Comparison candidates propose changes without mutating committed identity
state. Only an accepted observation commits the complete proposal. Read
delivery reserves its correspondence atomically before exposing IDs, with
successful wire accounting recorded separately. A failed write can retain its
conservative input anchor. Null, empty
values, fixed business IDs and externally supplied IDs do not gain permission
from an incidental random-looking spelling. Derived keys, URL templates,
hashes and actual signature transformations retain their typed native effects.
Redis ownership tokens use the ordinary identity graph, including later Lua
arguments or conditional deletion. No lock declaration or lock-specific
lifecycle is required.

## Protocol expiry

Redis and Memcached TTLs belong to their protocol adapters and need no field
strategy. Redis relative expirations (`EX`, `PX`, `EXPIRE`, `PEXPIRE`, `SETEX`,
`PSETEX`) remain exact durations. Absolute `EXAT`, `PXAT`, `EXPIREAT` and
`PEXPIREAT` compare remaining TTL using independent request clocks, preserving
units, options, expiry state and finite consumption.

Memcached store, touch, gat/gats, flush and supported binary arithmetic commands
retain their protocol expiration semantics. The binary arithmetic `ffffffff`
sentinel stays exact. Store JSON inference covers complete set/add/replace/cas
values; append/prepend fragments remain exact. Do not declare these protocol
expiry arguments under JSON or Redis scalar field formats.

## Redis scalar values

Root `redis.keys` declares scalar value formats by physical key pattern. The
optional `redis.database` selects one observed database; omitting it covers
recorded Redis databases. Each pattern supports at most one `*` wildcard.
Matched values use the same `kind` and `formats` as JSON and MySQL scalar fields.

The Source scalar encoding fixes Target representation: a JSON number remains
a number, a quoted JSON string remains quoted, and a plain UTF-8 UUID or date
remains text. Structured JSON values use the global JSON field map. Unknown
binary values stay exact. Equal scalars need no format or time validation, and
identity values retain equality anchors. Extra arguments, keys, hash fields,
container shape and expiry semantics retain protocol checks.

A supplied scalar `redis` section replaces its complete key-format map in
plan/apply; `redis: {keys: {}}` clears it. A JSON path is never repeated under a
Redis key. Stateful Redis effects, including ordered streams, key derivation and
write/read lifetimes, are grouped under `redis.rules`. They compile into the
same native rule list and retain their finite state. Source proof is frozen in
the separate plan record; the published policy contains no evidence metadata.
A section containing only `redis.rules` adds native rules without creating or
clearing scalar permissions. The renderer groups Redis effects there automatically;
other native effects remain under root `rules`.

## MySQL scalar fields

`mysql.tables` is needed only for explicit scalar semantics that cannot be
inferred from native column metadata, such as identity formats. Each entry has
a local descriptive name, a physical `pattern`, and column `fields` using the
same `kind` and `formats` syntax. `mysql.database` optionally scopes one exact
physical database. Patterns contain table names or table wildcards, without a
database prefix. Overlapping declarations must agree.

A root `mysql: {}` enables automatic native time inference without scalar
declarations. DATE, DATETIME and TIMESTAMP inference uses recorded wire types and physical
column origins. Only an inferred value near the independent Source request
clock is translated on input delivery; historical and epoch values remain exact.
Column names such as `created_at` are not type evidence. JSON
payload recognition is independent of the physical column declaration. Where
the recorded protocol or SQL shape does not establish a safe native type or
column origin, values retain exact comparison rather than being guessed from
their appearance.

The SQL resolver conservatively associates direct INSERT values, UPDATE
assignments, comparisons, BETWEEN and IN operands with physical columns.
Unsupported expressions and ambiguous joins do not grant field permissions.
Source and Target must still use the same physical relation and preserve
unselected predicates, values, transaction boundaries and finite exchanges.

## Time comparison and dependency delivery

Global time declarations use relative differences; no authored relation is
needed. Target time minus its independent request clock must preserve Source
time minus its independent request clock within the fixed engine tolerance.
Each physical field occurrence has independent clock observations. Sharing a
global declaration does not imply that unrelated business fields were sampled
from one clock read.

Dependency response adapters materialize declared global times relative to
the Target request clock. Missing fields stay missing and unchanged payloads
retain their original bytes. Ordinary response assertion compares independently
observed values. Original recordings are never modified, and successful wire
delivery remains distinct from constructing a derived response.

Native effects under `rules` retain typed PB schemas, signatures, state
transitions and additional clock relationships. Resource aliases identify the
protocol endpoint, database and user for those effects. Ordinary JSON formats
belong in the global map; API, SSE, table and cache selectors do not duplicate
them. Extra native constraints still validate their owned fields and unselected
content; they do not grant blanket permission to ignore a global format.

## Compilation, Replay and plan/apply

Compilation prepares a global field plan separately from contextual rules;
it does not generate one copy per API, table or cache key. Global JSON and
MySQL format changes affect runtime fingerprints, while value-only changes do
not require a new recording merely to refresh capture policy.

HTTP headers use the same scalar formats through one case-insensitive root map:

```yaml
http:
  headers:
    x-amz-date: {kind: time, formats: [amz_date]}
    x-request-id: {kind: identity, formats: [uuid]}
```

Presence, repeated-value counts and order stay strict. Header identities join
the same complete-value graph as JSON and storage identities. Protected
unavailable Source headers remain exact. See [header formats](http-header-formats.md).

Managed changes use `rule plan --file ... --evidence ...` and
`rule apply --plan ...`. A supplied root `json`, `mysql`, `redis` or `http` section replaces
that complete section atomically. Omitting a section preserves it; supplying
`json: {fields: {}}` clears the last JSON format declaration. Additional native
effects retain their own explicit plan/apply lifecycle.

Recording lifecycle is separate from value formats. `async_api` matches the
original API and literal request JSON fields, then retains the case until a
declared successful resource, an ordinary dependency access failure or the
engine's existing request deadline. An end resource's bounded `occurrence`
counts successful commands for one physical resource. Lifecycle changes affect
capture fingerprints and require fresh recording evidence. Existing complete
Source cases can still replay when their immutable dependency inventory proves
the configured completion; Replay waits for real Target consumption of that
finite inventory. See [recording](recording.md).

Planning preserves complete Source coverage, independent protected Target
witnesses, strict unselected evidence, stale checks and durable recovery.
Global format changes carry system-wide Replay obligations. Source
self-validation does not establish Target correctness. Speculative candidate
IDs are not merged into an accepted case graph during offline preflight;
fresh genuine Replay establishes cross-message identity correspondence,
delivered-input anchors and successful exchange admissions together.
