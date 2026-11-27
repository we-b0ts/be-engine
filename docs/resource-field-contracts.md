# Global field formats

`project.policy` names one `traffic-policy/v3` document. Declare JSON field
formats once under `json.fields`, regardless of the API, SSE event, database
column or cache key that carries the payload. Protocol adapters still pair the
same requests, resources, rows and response positions before comparing values.
The global JSON policy controls decoded content; it does not relax that pairing.

Known standard textual dates use [built-in time semantics](time-policy.md)
without per-field rules. Numeric epochs still require declared units or a
provisional hypothesis. Dependency matching uses dependency request initiation;
API response comparison uses response completion or individual stream events.

Primary SSE responses retain the typed timestamp pairs actually delivered by
matched HTTP, MySQL and Redis dependencies. A copied field must match that exact
pair, and the successful delivery must precede the output frame in both
executions. A later dependency cannot authorize an earlier frame. This reuses
the dependency's time validation instead of rebasing a stored value again
against another event. Locally generated response times retain their
independent capture clock. Timestamp differences allow the larger of Source
and Target elapsed time from API request start to that observation, plus two
seconds for clock error. This includes timestamps created earlier in a request
and reused in its final response. Stream offsets
use the capture start; legacy recordings recover that start from the recorded
completion timestamp and duration without changing their original files.

```yaml
format: traffic-policy/v3
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

When delivery rebases a JSON time or identity, only the changed scalar tokens
are replaced. Object member order, whitespace, escaping and unchanged number
spelling retain their original bytes, including inside MySQL JSON-valued cells.
This preserves consumers that iterate a JSON object to construct an ordered
list. Comparison permissions and array ordering are unchanged.

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
introduce authored captures or groups. JWT verification and internal complete-token correspondence are described below.

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

A finalized partial Replay may plan additive JSON time declarations without
changing existing fields or protocol permissions. The planner still freezes
and validates the complete Source scope. For an exact field path, authenticated
completed dependency reads can prove that the proposed declaration would
change an input already delivered by the old policy. Later observations on the
same resource, after both its Source completion and Target delivery, then remain
explicit `unvalidated_retimed_witnesses`; they do not count as independent Target
validation. These cuts apply across Cases in the same protected Replay session,
with both clocks still enforcing order; a separate session collects its own
evidence. A later primary response can carry the same fresh-execution
obligation. Render-only payloads, missing clocks, future reads and other
resources cannot establish it. Application always requires fresh genuine Replay;
unselected counters and native requests remain strict during that execution.

Integer Unix timestamps compare independent anchors at the declared seconds,
milliseconds or microseconds precision. The elapsed-time budget is computed
before that projection, retaining fractional request durations. Floating
timestamps and textual formats retain their existing precision; duration
contracts do not acquire timestamp rounding.

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

JWT verification refers to a named signature profile:

```yaml
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}
  oidc: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: OIDC_STATE_SECRET_KEY}}
json:
  fields:
    /access_token: {kind: jwt}
    /refresh_token: {kind: jwt}
    /state: {kind: jwt, signature: oidc}
    /authorize_url: {kind: url, formats: [url]}
    /headers/origin: {kind: identity, formats: [{string: 255}]}
    /download_path: {kind: url, formats: [aws_sigv4]}
```

`kind: jwt` defaults to the explicitly declared `default` profile. The engine
loads its private key snapshot once, verifies HMAC signatures and relative
NumericDates, compares stable claims and applies global scalar/array formats
to declared claim paths. Complete Source-equal tokens must remain Target-equal
across carriers. Recognized equal tokens also authenticate; a failed candidate
commits no token or claim identities. Global RS256 verification currently fails
closed; exact native recorded-public-key checks remain available.

The old authored `{kind: identity, formats: [jwt]}` syntax is rejected.
JWT fields use `kind: jwt` with a declared profile; there is no keyless or
syntax-only JWT policy alternative.

`api` declares the exact request header/query/body positions that actually need
translation and re-signing. Additional response nonce echoes and signed expiry
companions remain at their API positions and lower to the existing crypto
owners. Unknown historical dependency inputs are not arbitrarily re-signed.
See [signature profiles](signature-profiles.md) for the complete syntax,
startup inputs and strict planning boundaries.

`url` parses a complete URL or path/query value and applies the same global
field formats to decoded query parameters. For example, `/session_id` describes
a query parameter with that name as well as a JSON member at that pointer. Query
values are text strings; scheme, host, path, fragment, unselected components and
unmodified escaping remain exact. URL fields join the same identity graph as
ordinary JSON fields. This does not infer a signature algorithm or key.

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

Root `redis.keys` declares scalar value formats and key-local behavior by
bounded key pattern, without resource aliases or database selectors. Each
pattern supports at most one `*` wildcard. Actual Source/Target endpoint,
database, authentication and protocol identities still have to match.

```yaml
redis:
  keys:
    'task:current:*': {kind: identity, formats: [uuid]}
    'task:counter:*': {commands: [INCRBY, EXPIRE]}
    'task:events:*':
      commands:
        - operation: ZADD
          arguments:
            1: {kind: time, formats: [unix_seconds]}
```

The Source scalar encoding fixes Target representation: a JSON number remains
a number, a quoted JSON string remains quoted, and a plain UTF-8 UUID or date
remains text. Structured JSON values use the global JSON field map; JSON paths
are never repeated under a key. Unknown binary values stay exact. Equal scalars
need no format or time validation, and equal identities retain equality anchors.
Extra arguments, keys, hash fields, container shape and expiry remain strict.

`commands` is an ordered list, with one-based value-argument indexes (the key is
separate). Each time argument declares one format. The engine relates equal
Source instants internally; no binding, relation or clock group is authored.
EVAL/EVALSHA entries retain their exact script digest. A standalone identity
`key_format` declares the complete ID in a physical key's wildcard segment.
It shares the Replay Session mapping with other declared ID positions.
[Key contracts](redis-key-contracts.md)
Key-local permissions retain their complete Source state and finite-inventory
validation. They are not exemptions for asynchronous work.

A supplied `redis` section adds scalar and key identity declarations by default.
Compatible formats append in order, with exact duplicates removed.
Replacing or clearing the map requires `traffic-policy-change/v1` with `replace_sections: [redis]`
and the complete intended Redis map. Key-local behaviors compile to the existing
native owners and retain their native rule lifecycle. Advanced native rules are retained only for relationships not covered
by this declaration. Source proof is frozen in the separate plan record; the
published policy contains no evidence metadata.

## MySQL scalar fields

`mysql.tables` is needed only for explicit scalar semantics that cannot be
inferred from native column metadata, such as identity formats. Each entry has
a local descriptive name, a physical `pattern`, and column `fields` using the
same `kind` and `formats` syntax. Patterns contain table names or table
wildcards, without repeated database or resource selectors. The engine still
pairs actual Source/Target physical databases and tables. Overlapping
declarations must agree.

A root `mysql: {}` enables automatic native time inference without scalar
declarations. DATE, DATETIME and TIMESTAMP inference uses recorded wire types and physical
column origins. Only an inferred value near the independent Source request
clock is translated on input delivery; historical and epoch values remain exact.
Each inferred or globally declared scalar time is checked independently at its
physical SQL value or result cell. Sharing a native type or format does not
declare a cross-column or cross-row clock relationship; those relationships
require an explicit contextual rule.
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

## Dependency lifetimes

Content formats do not authorize shared or process-level dependency lifetimes.
Declare those requests separately:

```yaml
source_revision: source-image-v1
localcache:
  requests:
    - redis: {operation: HGET, key: token_v2, field: '3061639762'}
    - http: {host: auth.example.com, method: GET, path: /.well-known/jwks.json}
process_dependencies:
  tasks:
    refresh_signing_keys:
      requests:
        - http: {host: auth.example.com, method: GET, path: /keys/}
        - redis: {ports: [6379], operation: GET, keys: [{kind: exact, value: refresh_flag}]}
```

`localcache.requests` identifies finite initialization requests shared by the
Source process. It declares dependency requests, not cache objects or arbitrary
cached responses. HTTP entries require an explicit host, method and path;
Redis entries require an exact GET key or HGET key/field. Request identity,
response inventory and successful delivery remain finite.

`process_dependencies.tasks` uses actual logical task names from Source code.
One task can contain requests from several protocols. HTTP entries require a
host plus `method`/`path`, or bounded `methods`/`path_prefixes` lists. A host
selects its observed port; no default port is invented. Actual endpoint pairing
remains strict. MySQL process entries retain their precise SQL selector and
transaction members, with resource aliases where needed. Root `source_revision`
binds this classification to immutable Source behavior. Task names are labels
for real Source work, not a way to create new tasks or exempt unknown traffic.
Each proposed entry requires its independent Source proof; runtime rendering
removes it. Lifetime declarations do not implement destination state, change
payload comparisons or relax finite consumption.

## Time comparison and dependency delivery

Global time declarations use relative differences; no authored relation is
needed. Target time minus its independent observation clock must preserve
Source time minus its independent observation clock within
`max(source_elapsed, target_elapsed) + 2 seconds`. Each elapsed interval starts
at that side's API request and ends at the current comparison observation. The
value itself need not lie in that interval: business offsets remain valid.
Missing or reversed request observations do not widen the two-second allowance;
missing comparison anchors still fail. Earlier stream frames cannot borrow a
later frame's budget. This rule applies with either recorded or fast delivery.
Each physical field occurrence has independent clock observations. Sharing a
global declaration does not imply that unrelated business fields were sampled
from one clock read.

Dependency response adapters materialize declared global times relative to
the Target request clock. Missing fields stay missing and unchanged payloads
retain their original bytes. Ordinary response assertion compares independently
observed values. Original recordings are never modified, and successful wire
delivery remains distinct from constructing a derived response.

[Content formats and carrier bindings](content-policy-layout.md) cover global
string templates, HTTP acquisition and path contracts, shared DOCX fields and
scoped API encryption/header positions. Supported multipart comparison is an
engine protocol capability. Explicit bindings retain their existing typed
owners, scope and causal checks; they do not grant blanket permission to ignore
a global format. Native effects remain available for extra relationships that
cannot be represented losslessly. Resource aliases retain physical protocol,
endpoint, database and user identity. Ordinary JSON formats stay in the global
map; API, SSE, table and cache selectors do not duplicate them.

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

Presence, repeated-value counts and order stay strict. There is no header
absence waiver or generic SDK-header exception. Header identities join
the same complete-value graph as JSON and storage identities. Protected
unavailable Source headers remain exact. See [header formats](http-header-formats.md).

Managed changes use `rule plan --file ... --evidence ...` and
`rule apply --plan ...`. A supplied root `json`, `mysql`, `redis` or `http`
format section adds to current declarations. New positions retain existing
fields; compatible formats at one position append in the existing order with
exact duplicates removed. Conflicting kinds or immutable settings reject.
An omitted section or an empty format map does not remove existing declarations.
Target workers need only describe their currently required additions.
Whole-section replacement is explicit through `traffic-policy-change/v1`
`replace_sections`, with the complete intended map for each listed section.
The plan reports declaration additions, changes and removals before publication.
Additional native effects retain their own explicit plan/apply lifecycle.

Recording lifecycle is separate from value formats. `recording.async_api` matches the
original API and literal Source request/response JSON fields, selecting the
first matching scenario in its ordered array. All matched ends close admission
immediately and drain; partial matches permit a one-second probe, while a new
request requires another end or five-minute business-idle fallback. An uncovered
end saves the Case normally without stopping Source or asserting business
completion. Actual capture failure and explicit stopping retain their own behavior.
HTTP terminals require a complete successful
exchange at the declared endpoint, method and path. A Redis end's bounded `occurrence`
counts successful commands for one physical resource. Lifecycle behavior changes
affect capture fingerprints; moving the compatible root declaration under
`recording` alone does not. Existing complete
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
