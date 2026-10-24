# Unified Traffic Rules

Use one `traffic-policy/v2` policy for acquisition, classification, input
adaptation and all comparisons. Managed project configuration contains:

```yaml
project:
  policy: .traffic-e2e/policy.yaml
```

The path is relative to the target repository root. Initialization creates an
empty policy with endpoint aliases and `rules: []`; it supplies
no project-specific exceptions. Only `traffic-policy/v2` is accepted; former
version-numbered verification documents, v1 and separate Source policies reject.

## Discover, Plan, Apply

During a managed rewrite, load the backend-rewrite skill instead of operating
its state machine from this skill. Current evidence supplies a bounded rule
discovery query and capability metadata. Follow its returned command. Inspect
immutable Source code and the exact Source/Target witnesses before proposing a
rule; a mechanically explainable difference is not a semantic justification.

Follow discovery's `pagination.next_page.command` for omitted candidate/location
summaries and `pagination.next_scan.command` for remaining observations. Counts
describe the current bounded scan window; Source locations have separate
`location_count` and `summary_omitted` fields. Explicit nonresumable limits remain
under `bounded_analysis.nonresumable_limits`. Missing drafts are not proof of a
missing capability, and supported mechanism hints never supply Source proof.

At the first relevant mismatch, inspect the single global `json.fields` map.
Declare time, identity, protocol or single-unit duration `formats` and unordered
semantics once per logical pointer, regardless of APIs, SSE events, tables or cache keys. JSON payloads
are recognized automatically. Root `mysql` enables native time metadata;
`mysql.tables` declares remaining explicit scalar formats. Redis scalar values
use `redis.keys` patterns across physical databases; JSON objects still use
the single JSON field map. Redis causal and stateful native effects belong under
`redis.rules`, using the same typed rules and Source proofs as other native
effects. A rules-only Redis section does not change scalar permissions. Source clocks resolve
ambiguous numeric epoch units; unresolved units stay exact. Paired nulls are
implicit for time and identity fields. Equal scalars pass exact comparison
without time validation; equal identity scalars still reserve equality anchors.

Declare common HTTP header formats once under `http.headers`, such as
`x-amz-date: {kind: time, formats: [amz_date]}`. Names are case-insensitive;
presence, occurrence count and order remain strict. Header IDs join the same
complete-value graph. Per-API request-header timestamp declarations are retired.

Use `async_api` only for recording lifecycle: select an API and original request
literal fields through `when`, and list successful terminal resources under
`end`. A Redis terminal may declare `occurrence` (default 1) for repeated success
on the same physical endpoint, database and key. A terminal can explicitly
select its physical database; omitted database selectors match any Source database. Failure and request deadlines use engine defaults;
they are not rule options. This change requires fresh recording evidence.
Replay retains async case ownership until the finite recorded dependencies are
actually consumed. Older complete Source inventories must independently prove
their configured completion before they can supply this tail.

Equal complete typed Source IDs must remain equal Target IDs, and distinct IDs
cannot merge. The engine maintains that correspondence internally. Source
selects the format branch; Target cannot select another branch to pass.
Dependency reads reuse established Target IDs and anchor unknown inputs.
See [global field formats](../../../../../docs/resource-field-contracts.md).

Draft discovery follows actual array structure: `/blocks/*/timestamp` covers
repeated elements across indexes and cases without guessing that numeric object
keys are arrays. Candidate IDs remain stable across witness cases/indexes; `locations`, `location_count` and
`locations_omitted` expose bounded concrete witness pointers. These are sampled
observations, not complete coverage or Source permission: drafts retain empty
proofs and `plan_ready: false`, and differing IDs do not authorize identities.

Global JSON formats cover every carrier; they have no API, resource, model or
SSE discriminator. Native protocol effects keep only the physical request and
causal ownership needed for that effect. Planning validates complete Source
coverage, using each API's independent Target witnesses and clocks where
available. Missing Target evidence requires genuine Replay; changed Source
membership or foreign execution invalidates the plan. `calendar_date` retains
its required explicit `utc_offset`.

Use `kind: url, formats: [aws_sigv4]` for signed S3-style JSON URLs: signing date,
credential date and signature shape are validated while static URL components
stay exact. JSON JWTs use `kind: jwt` with the explicit default or named
`signatures` profile. Runtime key snapshots authenticate HMAC signatures,
NumericDates and stable/declared claims while preserving complete-token
correspondence across carriers. Old authored identity `formats: [jwt]` is
rejected; there is no keyless JWT policy mode. `api` request positions explicitly
authorize time translation and re-signing; API response positions retain extra
nonce/expiry relationships. Keep ordinary formats under `json.fields`, including
Redis JSON values. See [signature profiles](../../../../../docs/signature-profiles.md).

The coordinator accepts one rule, a list, or a complete typed document:

```bash
backend-rewrite --target-root <target> rule plan \
  --file /tmp/proposed-rules.yaml --evidence <current-evidence-id>
backend-rewrite --target-root <target> rule apply --plan <plan-id>
```

The plan expands every selected rule, validates its whole affected payload and
reports remaining Replay, reclassification and recording obligations. Reuse the
same pending plan after an interruption; `rule recover --plan <plan-id>` resolves an
interrupted transaction through the coordinator. Do not edit a managed policy
or recording to bypass this transaction.

A supplied root `json`, `mysql` or `redis` section replaces that entire section; omitted
sections preserve current content. An empty `json.fields` map clears all JSON
formats. Endpoint aliases and native rules remain additive. Explicit native rule
replacement uses `traffic-policy-change/v1` with `replace_rules` and complete
replacement native rules. Every plan freezes original evidence and policy;
Apply retains the fresh genuine Replay obligation.

## Three Comparison Surfaces

| Surface | Evidence and responsibility |
| --- | --- |
| `api.response` | Complete recorded and independently observed API responses |
| `dependency.request` | Complete recorded request and real Target client request |
| `dependency.response` | Complete recorded result and its explicit Replay delivery; materialization and verification remain separate |

Every decoded JSON carrier uses root `json.fields`, including HTTP/SSE, MySQL
JSON-valued columns and cache payloads. Unknown encodings compare exact bytes.
Source-recognized JSON requires valid Target JSON; format errors never fall back
to opaque comparison. Root `mysql` enables DATE/DATETIME/TIMESTAMP inference;
`mysql.tables` fields use table-only patterns across databases and describe
exceptional scalar formats. Source and Target physical connection identities
still match. Native SQL
origin mapping remains conservative and does not guess units from a column name.

```yaml
format: traffic-policy/v2
json:
  fields:
    /written_at: {kind: time, formats: [unix_milliseconds]}
    /item_id: {kind: identity, formats: [{prefix: msg_, hex: 12}]}
    /members: {kind: unordered}
mysql: {}
rules: []
```

## Exact Remainder And Time

Time formats preserve offsets relative to independent Source/Target request
clocks. Multiple numeric units are chosen from Source and its own clock, never
from Target. Date-only values need an explicit format UTC offset, such as
`formats: [{format: calendar_date, utc_offset: '+08:00'}]`. Dependency delivery
translates time inputs so Target can preserve its recorded read/modify/write flow.
Verified historical time-copy facts require actual completed input delivery,
its matching request, both causal cutoffs and typed leaf equality.

All field paths are optional. Both absent passes without clocks; one-sided
presence fails. Time and identity fields accept paired nulls implicitly; null
versus a value or absent field fails. Fixed sentinels compare exactly without a
clock; no sentinel configuration is needed.

Identity formats validate both complete typed values. Equal Source values must
remain equal Target values across paths and carriers; the engine maintains this
correspondence internally. Generated-format UUIDs may map; unrecognized scalar
IDs remain exact and reserve their equality anchors. Prefixes are part of the full ID;
Target cannot choose another format branch. No authored binding or business
model group is supported.

Unordered arrays preserve complete elements and duplicate counts. Every
unselected member, protocol envelope, command argument and SQL predicate stays
strict. Native signature, derivation and causal contracts retain their own
proof, scope and finite consumption. Old resource fields, response declaration
graphs, per-API value rules and `field_ref` are rejected.

## Stateful And Source Effects

Use root `http.headers` for global header formats, for example
`x-amz-date: {kind: time, formats: [amz_date]}`. Header names are
case-insensitive; presence, multiplicity, order, transport and integrity remain
checked. Do not add one HTTP request rule per API for the same header.

Use root `async_api` for a request whose business work outlives its response:

```yaml
async_api:
  POST /jobs:
    when: {/background: true}
    end:
      - mysql: {sql: "UPDATE jobs SET status = 'completed' WHERE id = ?"}
      - redis: {operation: DEL, key: 'job:finished:*'}
```

Declare actual final accesses proved from Source. The end entries are
alternatives. SQL matches the entire normalized statement and fixed literals;
`?` selects one scalar rather than a SQL fragment or table name. Redis selects
the command and physical key, with optional `occurrence` for repeated access to
that same endpoint/database/key. Terminal entries can explicitly select a
physical database. A case-owned dependency failure or the common request deadline
also completes recording, with no authored timeout or failure switch. Keep
the finite dependencies in the Case; do not replace this lifecycle with
process-owned exemptions. See [recording](../../../../../docs/recording.md).

`redis_append_stream` grants Source-proven APPEND chunk-boundary equivalence only
under an explicit resource/database/key scope. Literal byte order, reads,
resets, expiry calls and finite consumption remain checked; APPEND responses
reflect actual Target cumulative lengths. See [APPEND streams](../../../../../docs/redis-append-stream.md).

`redis_read_commutation` permits explicitly scoped finite nil GET observations
to cross unrelated commands only after complete Source key validation. It
preserves each read's count and delivery; extra or missing reads still fail.
Use it for proven independent polling, never to suppress a cancellation value
or repair missing business reads. See [finite read commutation](../../../../../docs/redis-read-commutation.md).

Ordinary global identity formats relate complete typed Source values automatically.
Use a typed native owner for additional protocol, contextual or stateful behavior:

- `identity`: narrow capture/reference rules, embedded copies and derivation
  beyond ordinary physical identity fields;
- `redis_sequence`: atomic steps and additional
  protocol relationships beyond ordinary global formats;
- `http_request`, `mysql_values`: native query/multipart or SQL
  parameters, typed values and physical result time columns;
- `input_jwt`, `response_jwt`, `response_generated`, `response_body` and
  `response_header_date`: their dedicated execution or assertion owner;
- `input_signed_timestamp`: source-verified sorted-field MD5 JSON timestamp
  rebasing with a frozen startup signing input; see
  [signed timestamp request rules](../../../../../docs/signed-timestamp-request-rules.md);
- `capture_http`, `capture_breeze`, `capture_http_response`, `process_owned`
  and `finite_sharing`: acquisition, classification and finite sharing.

Follow discovered capability metadata for the exact effect schema. Source proof
belongs to the submitted plan proposal and its independent frozen evidence
snapshot. Published `policy.yaml` contains runtime declarations alone. Nested
permissions retain their Source explanation in the plan, whether locally
inherited or explicitly supplied; proof metadata is never needed to load a
runtime policy.
Source self-validation exercises complete traces in isolated state. It cannot
replace independent Target evidence; successful planning can still require
fresh Replay. Startup signing inputs are frozen by actual resolved file hash,
without copying secret values into a plan.

Ordinary resource identity fields already translate established mappings on
reads and anchor unknown inputs. For additional native read-back behavior when
Source reads a generated ID or preserved timestamp from Redis before reusing it,
an existing `identity` or `redis_sequence` write rule can declare
`effect.read_back`. This explicitly binds GET/LRANGE response fields to values
from successful matched Target writes to the same key. Update the original
rule and its write/read Source proof through normal plan/apply; each declaration
needs a positive Source trace witness and fresh genuine Replay. Do not introduce
a Target-local cache solely to compensate for recorded Source IDs returned by
Replay. Undeclared fields remain strict. See
[Redis read-back](../../../../../docs/redis-read-back.md) for schema and limits.

Process ownership does not prove target initialization or cache behavior.
Finite sharing does not authorize unused work, reusable snapshots, unrelated
connections or arbitrary response reuse. Protocol adapters retain framing,
authentication, lanes, request correlation, claims and consumption.
