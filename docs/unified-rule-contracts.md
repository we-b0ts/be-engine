# Unified traffic rule contracts

Task: `KCYgNKF0ZW`. Design and implementation baseline: `14439d5`
(`feat(replay): validate generated Redis timestamps precisely`).

P0 established the requirements below. P1-P4 implement the shared value kernel,
native effects and whole-policy owners; P5 cuts over the public workflow and
reference configuration. Focused validation and final repository checks are
recorded with the corresponding phase commits.
Each phase may contain several focused commits.

The objective is reusable, concise rules with complete evidence. A new
combination of an existing protocol slot, encoding and value contract must not
require another protocol-specific rule implementation. Existing configuration
files supply requirements; their layout, number and serialization are not
compatibility requirements. The final runtime must have one new-format loader,
not an old-format fallback hidden behind the new schema.

## Evidence surfaces and additional effects

Keep three value surfaces explicit:

| Surface | Values and responsibility | Default |
| --- | --- | --- |
| `dependency.request` | Compare the immutable Source dependency request with the actual Target client request before selecting an exchange. | Exact protocol identity and unselected content. |
| `dependency.response` | Select the recorded dependency input and, when explicitly authorized, materialize a delivery copy for Target. There is normally no Target-produced response to compare here. | Deliver recorded evidence with its original outcome and timing. |
| `api.response` | Compare the recorded primary response oracle with the actual Target primary response. | Strict status, headers, structure and unselected content. |

Ordinary `api.response` body contracts apply only when the Source has an ordinary
response body. SSE, NDJSON and other recorded interactions retain their separate
strict event/order/closure assertions; an empty carrier body is not JSON and body
contracts do not authorize changes inside interaction messages. Header date and
header JWT contracts still apply to interaction responses. A body rule must have
at least one complete ordinary Source witness; interaction cases never count as
successful body validations. Request-body `when` conditions use authenticated
in-memory request views, including private interaction requests. Planning freezes
the original encrypted artifacts and managed key; neither planning nor application
writes decrypted recordings. Applying a rule still requires genuine Replay.

Explicit `slot: {sse_data: <exact-event-name>}` rules provide JSON value
contracts for SSE interaction data. Data-only streams can additionally select
Source JSON `/type` with `slot: {sse_data: {event: message, json_type: response.completed}}`.
Target types remain exact. These rules use the same API selector, Source-only
request condition, proof and time kernel as ordinary bodies, with their own
field ownership. Event order/count, SSE event/id/retry, unselected data and
closure remain strict. Interaction rules never supply ordinary body witnesses.
See [SSE value contracts](sse-value-contracts.md) for authoring and limits.

Inbound request JWT translation, Source capture admission, Source response
rewrite, process ownership, API-origin attribution, finite sharing and snapshot
admission remain explicit typed effects. They are not additional permissions
obtained by decoding a value. In particular, an unordered SET value rule does
not reorder a GET response, authorize a reusable read, or classify unused work.

## Resource scope across APIs

Task: `rMyn5SlKQg`. New dependency value rules and native resource effects select
the resource, operation and value location without `match.api`. Discovery and
planning omit that field from these rules. The API that owns a rewrite issue
still identifies the transaction and its evidence; it does not limit resource
access contracts. Root inbound request-body `when` conditions cannot be used on
new resource rules. API response assertions and inbound adaptation retain their
API scopes. Existing explicitly API-scoped rules retain their original scope
when reapplied or extended; planning never silently widens a prior proof.

Resource preflight scans the complete immutable recording for matching cases,
including cases belonging to other APIs. It validates their Source values and
uses each API's published Target execution, protected witnesses and clocks when
available. Missing Target evidence remains an explicit fresh-Replay obligation;
another API's Target values or clocks cannot substitute for it. Planning freezes
the Source inventory, relevant prepared memberships and Target execution
identities, including evidence absence, and checks them again before application
or recovery. Native state remains case-local and finite. Applying a changed
policy invalidates previous API verification fingerprints and requires genuine
Replay. `calendar_date` continues to require its explicit `utc_offset`.

## Requirement inventory

The reference project is
`we-ai/Wegent-intra/backend-rs-intra/.traffic-e2e`. Only configuration and engine
source were inspected; raw recordings were not used for this inventory.
The configuration snapshots inspected during P0 had these SHA-256 identities:

| File | SHA-256 |
| --- | --- |
| `source-traffic-policy.yaml` | `5d6c1e9d1a335c58948574871a517099645e189e90d953af046a8cb69d6b3f06` |
| `verification.yaml` | `425f368e27647ef4bdbd84364ce41d4d182aa78925f04e590774201a04ca5854` |

The reference contains 185 HTTP case patterns, one Source HTTP response rewrite,
27 process-owned rules (15 MySQL, 9 Redis, 3 HTTP; 21 have API origins), and an
empty Breeze capture list. Verification contains 60 dependency entries:
53 ordinary entries (27 MySQL, 15 Redis, 11 HTTP) and 7 dynamic captures.
Response requirements cover JSON, DOCX and headers. Inbound JWT translation
uses five locations and three profiles. These counts describe this snapshot,
not a fixed engine limit or proof that other supported domains are unnecessary.

| ID | Existing requirement or reference example | New owner and invariant |
| --- | --- | --- |
| S01 | Source HTTP case path patterns and Source revision. | Typed capture admission; preserve route scope, source identity and recorded request ownership. |
| S02 | `allowed_unused_http_hosts`, empty in the reference. | Explicit unused classification scope; never repair an unmatched Target request. |
| S03 | Source HTTP response rewrite, including the sandbox `base_url` pointer. | Capture-side input effect with exact authority, method/path, status/content-type and pointer scope. Preserve original observation and transformed delivery provenance. |
| S04 | Breeze snapshot directory/resource selection and existing specialized response plugins. | Native capture/startup owners; descriptor, resource, proxy and plugin lifecycles are not generic codec behavior. |
| S05 | HTTP naming/configuration refresh and DingTalk process connections. | Source-proven process ownership, bounded by endpoint/method/path. |
| S06 | Redis HSCAN process loops and bounded key families. | Recorder ownership plus protocol cursor/session rules; a scan does not create infinite generic response inventory. |
| S07 | API-origin async Task/Subtask reads, writes, cancellation, streaming and metric scripts. | Immutable Source origin/identity/cause witnesses, including shared origin definitions and bounded references; preserve transaction and foreign-case conditions. |
| S08 | MySQL process scans, shard/table families and recovery lookback. | Native SQL selection with physical-table equality, bounded table series and complete Source request/response evidence. |
| D01 | MySQL generated timestamps in SQL values and nested JSON values. | Shared typed time contract plus SQL slot adapter; preserve nonselected parameters and statement identity. |
| D02 | MySQL response-time fields and relative lease/expiry values. | Explicit dependency input materialization, separate from SQL request comparison and final response assertion. |
| D03 | HTTP unordered department IDs; Redis JSON/PB collection values. | One multiset contract over typed collections; preserve duplicates, length, membership and element associations. |
| D04 | HTTP signing headers, raw-query timestamps and JSON request timestamps. | Header/query/body slot adapters plus shared time semantics; auth and stable URI bytes stay checked. |
| D05 | Redis GET/HGET token/session expiry rebasing. | Explicit response-copy delivery; preserve source age/offset and finite matched inventory, not implicit cache renewal. |
| D06 | HTTP OAuth initialization sharing and Redis token read sharing. | Explicit finite sharing with Source lifetime proof; independent from codec, time comparison and snapshot reuse. |
| D07 | Redis lock acquisition/release tokens. | Stateful acquisition/reference contract; preserve NX/EX/PX/options, script identity, acquisition completion and nonce uniqueness. |
| D08 | Redis PUBLISH publisher UUID plus generated JSON timestamps. | Pure value previews compose atomically; preserve channel, publisher binding, unselected JSON and timing relationships. |
| D09 | Redis SET/RPUSH JSON time, ZADD/range times and script ARGV time. | Typed slots plus shared time; command sequence, numkeys, all KEYS/ARGV and Lua digest/body stay protocol-owned. |
| D10 | Rate-limit window keys and INCRBY/EXPIRE sequences. | Typed key template and bounded time-window derivation; key/value relation and command sequence are not random exemptions. |
| D11 | VNC session and ticket key captures with JSON references. | Explicit capture/reference templates, base64url/hex shape, one-to-one identity mapping and stable TTL/options. |
| D12 | Multipart upload boundary differences. | Structured multipart comparison; only boundary delimiters change, while part order, bytes, filenames and headers stay checked. |
| D13 | Seven dynamic captures: SQL IDs/names, HTTP object paths, Redis block IDs and JWT values. | Case-scoped staged bindings with explicit references, integer/string distinction and typed path segments. |
| R01 | Primary JSON current timestamps, relative expiry and elapsed duration. | Shared time formats/relations with independent Source/Target anchors; fixed tolerance and preserved units. |
| R02 | Primary JSON UUID/random fields and string/URL identities. | Explicit shape and identity/relationship contracts where evidence permits; broad random rules require recorded limitations and cannot hide stable contents. |
| R03 | Signed JWTs, URL-contained JWTs, related expiry/issued-at/TTL fields. | Native signature/claim contract, exact stable claims and URL remainder, nonce shape/bijection, declared key provenance. |
| R04 | Embedded-IV AES-CBC response currently described as random. | Explicit crypto requirement: bounded base64/envelope, algorithm, key reference, IV/padding and plaintext comparison. Do not invent authentication guarantees absent from the Source format. |
| R05 | Content-Disposition calendar filenames and DOCX core timestamps. | Header and archive/XML typed adapters; preserve filename remainder, multiplicity, archive structure and unrelated XML. |
| R06 | Existing PB and Hessian2 response unordered/joined-string contracts. | Encoding adapters retain envelope, field/element types, references and unselected content; JSON-only configuration is not the capability boundary. |
| I01 | Inbound bearer, raw header, download-token/query and OIDC-state JWT profiles. | Engine-owned input transformation with original-signature validation and re-signing; never use an expected response or dependency output as request data. |
| E01 | All discover/plan/apply families and fresh verification. | One evidence transaction and effect-specific obligations; applying configuration is not verification success. |

Memcached, Kafka and Motan remain peer protocol domains even when absent from
the reference rules. Memcached value contracts must gain JSON/PB symmetry;
Kafka key/header/value and Motan envelopes retain their existing bounded
protocol support. No generic value adapter claims broader broker, transaction,
serialization or connection support than its protocol currently provides.

The P5 refresh uses the current reference configuration and the inspected frozen
Source image `sha256:b0e209bcab1c67a2a2c793b0c818a0964ddbf4e689618f99a1a022479a6904c7`.
Its 64 dependency requirements become part of 112 self-contained typed rules;
all 185 capture paths and 27 process selectors remain represented. The refresh
also replaces whole-value random allowances with signed download URLs,
AES-CBC plaintext contracts and shared VNC template fragments where Source
supports those stronger checks. Method-free legacy identity scopes are bound to
the actual Source generator methods, rather than a converter's default method.
Configuration loading and compilation are checked offline; this does not certify
the reference Target's behavior or renew any existing execution evidence.

## Module boundaries

| Owner | Responsibility | Must not own |
| --- | --- | --- |
| `value_contract/time` | Pure typed timestamp parsing, formats, offset relations, precision and overflow checks. | Files, clocks, configuration, protocol matching or evidence persistence. |
| `policy/schema` | Strict `traffic-policy/v1` document types, Source conditions and explicit native effect payloads. | Runtime state or protocol I/O. |
| `policy/compiler` | Validate scopes, types, ownership, capability requirements, dependencies and effect projections; produce immutable typed IR. | Infer business permission from a sample or mutate recordings. |
| `policy/capability` | Protocol-slot/codec/contract/effect capability registry and machine-readable requirements. | A hand-maintained cross-product of bespoke Redis JSON/PB rules. |
| Protocol `contract_adapter` children | Extract typed slots and supply trusted protocol context/anchors; apply validated comparison decisions or response copies. | Generic time math or user-selected arbitrary clocks. |
| Existing codec owners | Bounded JSON, PB, Hessian2, multipart, URL/JWT and DOCX/envelope parsing, typed selection and safe reconstruction where supported. | Case ownership, finite consumption or scheduling. |
| Existing evidence/feedback owners | Immutable witness manifests, complete selected coverage, proof binding and stale-safe policy transactions. | Target implementation or semantic claims inferred solely from differences. |
| Existing origin/ownership owners | Process/API origin, finite sharing, snapshot eligibility, lane/transaction proof and reversible unused overlays. | Payload equality shortcuts. |
| Coordinator/CLI | Candidate guidance, plan/apply orchestration, recovery and required real verification. | Duplicate comparator implementations or raw artifact browsing in ordinary worker flows. |

Keep the crate's current ownership rules. A native typed contract can reuse
the value kernel while retaining its Source proof and lifecycle owner. Do not
move all domain behavior into one codec DSL or a catch-all policy module.
Review these boundaries again after implementation, including the parents of
new modules and any touched file approaching 1000 lines.

## New configuration core

### Optional authoring conveniences

The typed rule/codec/contract/effect design and its full explicit spelling remain
available. Human authoring can omit repeated information within the same rule:

- A root `source_revision` supplies the shared Source identity. Source capture
  and process effects inherit it; resolved proof references include it. Explicit
  conflicting revisions reject. Documents requiring independent Source identities
  can retain the complete explicit form without a shared declaration.
- A rule's proof is required. A nested contract inherits its nearest enclosing
  proof within that rule. A local `proof` can override `source`, `fact`, or both;
  blank source/fact values and null proofs reject. Nothing inherits from another
  rule.
- Nested contracts may retain the full `contract`/`proof` wrapper or use the
  direct contract spelling. `relative_time: FORMAT` expands to typed time with
  `preserve_offset`; `request_time: FORMAT` expands to `request_window`. Both
  use the independently observed start of their own request: the HTTP request
  for API responses and the physical dependency request for dependency contracts.
  `anchor` is not a configuration field: compact, expanded and nested contracts
  reject it, including an explicit `dependency.request_start` value. The same
  rule applies to duration contracts. `clock_group` only correlates values from
  one Source-proven clock read; it never selects another clock. Relative
  comparisons of naive timestamps cancel a shared UTC offset; legacy
  `utc_offset` is validated and removed by authoring normalization. Source and
  Target must use consistent timezone behavior. Formats/units remain explicit.
  `unordered` abbreviates `{kind: unordered}`.

For example, a native SQL rule can preserve its original abstraction and scope
without repeating the same Source paragraph for every time field:

```yaml
format: traffic-policy/v1
source_revision: sha256:1111111111111111111111111111111111111111111111111111111111111111
rules:
  - id: task-update-times
    match:
      resource:
        protocol: mysql
        endpoint: db.internal:3306
        database: app
        username: worker
      operation: COM_QUERY
      sql: UPDATE tasks SET json=?, updated_at=? WHERE id=7
    effect:
      kind: mysql_values
      values:
        0:
          kind: json
          fields:
            /updatedAt:
              relative_time: iso8601_naive
              clock_group: payload
        1:
          relative_time: sql_datetime
          clock_group: audit
    proof:
      source: app/task.py:update
      fact: Source reads payload and audit clocks independently; all other values stay exact.
```

The example revision is a placeholder fixture identity; projects declare their
actual frozen Source identity. The equivalent value-rule spelling is
`/expires_at: {relative_time: unix_microseconds}`;
JSON and typed PB reuse it on each supported surface. No resource registry,
business default, new effect, dynamic macro or expression language is introduced.

`policy/authoring` performs closed schema traversal, expands inherited proofs
and named time abbreviations, and renders human-readable YAML. It never traverses
business literals, request conditions or arbitrary decoded data. The existing
typed compiler still validates capabilities, ownership and complete contracts.
Plans and effective evidence serialize fully expanded rules/proofs; only the
source-controlled authoring document is compact. Equivalent authoring forms
produce identical full/runtime/capture/classification fingerprints. Rendering
verifies the compiled identity after a parse round trip before returning output.
Writers preserve shared revision context; unchanged apply keeps original bytes
and does not manufacture a new verification obligation.

The document discriminator is `format: traffic-policy/v1`; `rules` is the
authoring list; ordinary comparison permissions are combined by explicit field
ownership. Every rule has an ID,
surface, match scope, slot, codec, contract and project proof. Rules may have a
Source `when` condition and an explicit `delivery.rebase_time` field subset.
The compiler rejects unknown fields, ambiguous overlapping ownership and
unsupported combinations before any Target traffic is admitted.

The native `capture_http_response` owner retains its existing ordered plugin
selection: the first matching plugin is selected, while ordinary matching URL
pointers are combined. Its authored relative order enters the capture and full
policy identities. Reordering unrelated comparison rules has no semantic effect.

This example uses two encodings with the same collection semantics, and
separate request, delivery and primary-response time permissions:

```yaml
format: traffic-policy/v1
rules:
  - id: session-write
    surface: dependency.request
    match:
      resource:
        protocol: redis
        endpoint: cache.internal:6379
        database: 0
      operation: SET
      key: {prefix: "session:"}
    slot: value
    codec: json
    contract:
      /members: {kind: unordered}
      /expires_at:
        kind: time
        relation: preserve_offset
        format: unix_microseconds
    proof:
      source: src/session.rs:create
      fact: Source serializes a membership set and derives expiry from this request.

  - id: protobuf-membership-write
    surface: dependency.request
    match:
      resource:
        protocol: memcached
        endpoint: membership.internal:11211
      operation: SET
      key: {prefix: "membership:"}
    slot: value
    codec:
      kind: protobuf
      fields:
        /members: {field_path: [3, 1], field_type: string, repeated: true}
    contract:
      /members: {kind: unordered}
    proof:
      source: src/membership.rs:serialize
      fact: Field 3.1 contains the membership set described by the Source schema.

  - id: session-read-expiry
    surface: dependency.response
    match:
      resource:
        protocol: redis
        endpoint: cache.internal:6379
        database: 0
      operation: GET
      key: {prefix: "session:"}
    slot: value
    codec: json
    contract:
      /expires_at:
        kind: time
        relation: preserve_offset
        format: unix_microseconds
    delivery:
      rebase_time: [/expires_at]
    proof:
      source: src/session.rs:load
      fact: Source uses the stored expiry relative to this dependency delivery.

  - id: session-response-expiry
    surface: api.response
    match: {api: POST /api/sessions}
    slot: body
    codec: json
    contract:
      /expires_at:
        kind: time
        relation: preserve_offset
        format: unix_microseconds
    proof:
      source: src/session.rs:response
      fact: The response forwards the expiry created for this request.
```

Time and duration contracts use the start of their own request: dependency
contracts use the corresponding dependency request, and API response contracts
use their own HTTP request.
The protocol adapter supplies its independently observed Source/Target pair.
The outer API request never substitutes for a dependency clock. Response
delivery, current wall time and a payload value are never fallback clocks. Missing or inadequate historical dependency clocks are
unavailable and fail the selected contract. An API response requires the independently observed start of its own HTTP
request; it does not select an arbitrary child SQL/Redis dependency. New Redis recordings retain
exact request-start observations. Lock causality uses completion before reference
start; a historical floor-millisecond duration supplies only a conservative bound
and cannot prove a submillisecond ordering. Resource endpoints use
an explicit `host:port` scalar. Resource database identity remains typed:
Redis uses an integer and MySQL uses a database-name string.

JSON paths are logical field locations. A PB binding explicitly maps each
logical location to field numbers, repeatedness and scalar/message type.
It must preserve presence, duplicate occurrences and unknown-field evidence;
converting every PB message to an ordinary JSON object is insufficient.
GET response extraction also requires preserving null/missing/error and
protocol envelope distinctions. Decoding a GET value is automatically reusable
capability; enabling a comparison, delivery change or sharing permission is not.

A comparison field absent from both sides of one Source response shape is
inactive; the complete value still compares strictly. A Target-only addition or
Source-only deletion fails. Planning requires at least one genuine Source hit
for every proposed rule across the complete selected inventory. Explicit delivery
writes additionally require the declared Source timestamp to exist before any
exchange is admitted; absence cannot authorize a synthetic dependency input.

Proof belongs to each project binding. Source revision, immutable witnesses
and schema/clock/key identity are frozen by the engine rather than copied from
a reusable example. Reusable semantic definitions may reduce authoring
duplication, but cannot carry automatically inherited project proof or scope.
Two bindings can reference one explicitly scoped Source claim only if its
declared coverage includes both locations and effects.

Native schema variants cover S01-S08, D06-D13, R03-R05 and I01 with their existing
typed proof owners. They must be representable in the final new document and
round-trip without loss; an opaque old YAML blob or dual loader is not a
completed mapping. Key provenance stays inline with its input/output binding. There is no mandatory
resource/codec/contract registry and no arbitrary reference-resolution graph.

Source `when` conditions retain scalar types and read only the immutable inbound
Source request. Missing, null, truncated, duplicate-member or undecodable inputs
cannot satisfy `not_equals` and accidentally enable a normalization. Inbound JWT
translation preserves invalid-signature requests unchanged; it must never turn
negative authentication evidence into a valid re-signed request.

## Native effects stay local to the rule

A value rule composes existing slots, codecs and pure contracts. A stateful or
cryptographic permission retains its domain owner in a typed `effect`. The outer
proof states the complete Source fact; nested `contract`/`proof` pairs are used
when distinct relaxations need independently auditable facts. These records
remain fully inline; there is no required resources/codec/contracts registry.

Source-proven nonbehavioral SDK request headers use the scoped
[`http_client_metadata` effect](http-client-metadata.md). The consumer and its
middleware must not use the selected names for business behavior; unknown headers
remain strict and the audit retains observations with the authorizing rule ID.

MySQL JSON time fields can select variable-length arrays with exact wildcard
leaves, for example `mysql_values.values.1: {kind: json, fields:
{/blocks/*/timestamp: {relative_time: unix_milliseconds}}}`. Different Cases may
have different array lengths; Source/Target length, order and all other members
within each Case remain strict. This does not permit wildcard Source predicates
or identity captures.

SQL preflight composes these time fields with already accepted native identity
bindings. It restores only same-Case fingerprints whose capture and reference
match the current API/method/Source condition and resource/database/username,
then uses the runtime SQL identity normalizer on derived comparison copies.
Source captures must precede the recorded reference. Original Source and Target
witnesses retain their hashes and values; a missing audit or wrong scope grants
no normalization. The plan records the composed identities in
`stateful_target_obligations`: fresh genuine Replay must re-establish capture,
ordering and complete request acceptance. Raw identity differences and an
uncommitted failed statement's usage count do not establish that a reference
permission is inactive. Unselected business values remain checked during plan.

A scalar Redis SET timestamp uses the same value contract: select the exact
Redis resource/database, `operation: SET` and key, then declare `slot: value`,
`codec: json` and `contract: {'': {relative_time: unix_seconds}}`. The JSON root
can be a floating Unix-seconds number. A `redis_sequence` scalar-slot restriction
does not remove this generic value capability. SET options, TTL and finite calls
remain strict.

Redis search edges are not already paired exchanges. Preflight excludes a Target
key outside every selected rule's key scope before checking value and remainder;
that edge supplies no Target validation. A related key still requires exact
unselected arguments, and a failure identifies their argument index and byte
lengths without dumping payloads. No related Target evidence keeps its explicit
missing-witness/fresh-Replay obligation. Excluding a search edge never changes
runtime matching or clears an unmatched Target command.

```yaml
format: traffic-policy/v1
rules:
  - id: response-download-token
    match: {api: POST /api/attachments/*/download-token}
    effect:
      kind: response_jwt
      pointer: /download_token
      algorithm: HS256
      signing_key:
        kind: startup
        source: {kind: target_env, name: SECRET_KEY}
    proof:
      source: app/attachments.py:create_download_token
      fact: Source signs the stable attachment/user claims with a request-relative expiry using the effective startup SECRET_KEY.

  - id: generated-vnc-links
    match: {api: POST /api/devices/*/vnc}
    effect:
      kind: response_generated
      fields:
        /session_id:
          contract:
            kind: template
            template: 'vnc-{session}'
            fields:
              session:
                contract: {format: base64url, decoded_bytes: 18, binding: session}
                proof: {source: app/vnc.py:start, fact: Source draws an 18-byte token once and shares it between session ID and URL.}
          proof: {source: app/vnc.py:start, fact: The session ID has a fixed vnc prefix.}
        /url:
          contract:
            kind: template
            template: 'wss://vnc.example/vnc-proxy/sessions/vnc-{session}?ticket={ticket}'
            fields:
              session:
                contract: {format: base64url, decoded_bytes: 18, binding: session}
                proof: {source: app/vnc.py:url, fact: This is the same session token.}
              ticket:
                contract: {format: base64url, decoded_bytes: 32}
                proof: {source: app/vnc.py:start, fact: Source independently draws a 32-byte connect ticket.}
          proof: {source: app/vnc.py:url, fact: Scheme/authority/path and the ticket query key are deployment-fixed.}
    proof:
      source: app/vnc.py:start_and_url
      fact: Only these explicitly typed fragments vary and the session identity must agree across both fields.

  - id: publication-waiting-duration
    surface: api.response
    match: {api: GET /api/admin/publications}
    slot: body
    codec: json
    contract:
      /items/*/waitingDurationSeconds:
        kind: conditional
        when:
          relative_pointer: ../status
          not_in: [published, withdrawn, closed]
        contract: {kind: duration, unit: seconds}
    proof:
      source: app/publications.py:waiting_duration
      fact: Active durations use now minus submitted_at; terminal states freeze at updated_at and therefore remain exact.
```

Plain UUID/random contracts validate only their declared shape. Use template
bindings or native identity/nonce effects when Source semantics require copied
values or a one-to-one relationship. Template bindings here correlate selected
fields within one response rule. They
do not imply a cross-request Redis binding. Integer identities are capture-only
until a typed reference adapter exists; unsupported references reject at compile
time rather than becoming silent runtime gaps. String identities retain explicit
allowed cross-resource references through their existing staged runtime owner.

`response_generated.encrypted_json` declares the cipher envelope and effective
startup key. AES-CBC decoding checks IV, key length, padding and complete JSON;
plaintext is exact except explicit nested contracts. Staged IV mappings preserve
Source/Target reuse relationships within the same rule and response, including
unordered element pairing. This is neither an entropy guarantee nor a persistent
cross-case IV registry. A Source-default cipher key
requires a file hash and literal range in the frozen Source image, and is usable
only when the selected startup field is absent. Malformed keys cannot trigger a
fallback. JWT signing never uses this cipher fallback.

The authoritative path is `project.policy` (Target-root relative). Its parent
directories must remain inside the repository and cannot be symlink aliases;
the Source owner also rejects a symlink policy file. An as-yet-uncreated nested
policy is supported during initialization. All loaders,
capture writers, configuration-commit gates, key resolution, fingerprints and
progress publication resolve this path. Writers preserve every other rule and
nested proof in the document. Only the new format is accepted; old DTOs remain
internal domain data and test fixtures, not production configuration readers.

## Time, identity and encoding invariants

The baseline already supports primary-response `request_window` and
`preserve_relative`, plus Redis microsecond precision. Do not describe those as
missing capabilities or regress them while introducing `preserve_offset` as
the unified spelling for the relative relationship.

For Source/Target values `S`, `T` and trusted anchors `As`, `At`:

- Request window checks `S` against `As` and `T` against `At`.
- Preserved offset checks `(T - At) - (S - As)` against the fixed five-second
  window. Response materialization computes the corresponding translated copy.
- Elapsed duration preserves its numeric unit and the recorded/Target request
  delta. A remaining-duration relation must be explicit, not inferred from
  the field's name or from an observed positive number.
- Parse numeric time as scaled integers with `i128` nanosecond arithmetic;
  retain integer/fractional precision and reject overflow. Seconds,
  milliseconds, microseconds, RFC3339, AMZ date and explicit-offset naive ISO
  formats remain available through their supported typed adapters.
- Naive relative timestamps need no declared UTC offset: a shared civil offset
  cancels in the Source/Target difference, including delivery translation.
  A neutral UTC origin supplies arithmetic without reading the host timezone.
  Absolute request-window checks of naive timestamps still require an explicit
  offset; zoned and Unix formats need none. Formats and units do not imply that
  a business value is generated or safe to translate.
- Preserve the baseline cross-field precision contract: equal Source instants
  require exactly equal Target instants; distinct Source instants may have
  translation-offset differences of at most one microsecond. The five-second
  anchor window is not a replacement for this relationship check.
- Integrate master `f82a7b6` clock groups without weakening this default.
  `clock_group` is optional on timestamp contracts. Absent names share a strict
  group; explicit different groups require Source proof of independent clock
  reads. Each field still satisfies its own fixed anchor window, and each group
  retains copy equality and one-microsecond shift consistency.
- Preserve sequence-level relationships for scalar and nested JSON script
  timestamps. Validate script digest/body, numkeys, KEYS, ARGV and selected
  indices together without evaluating Lua.

Identity/nonce contracts retain capture location, shape, lifetime, allowed
reference endpoints and a one-to-one Source/Target mapping. Candidate previews
stage decisions without changing live state. A failed stable field, signature,
time relation, element pairing or protocol admission discards those decisions.
PUBLISH UUID and JSON time checks commit atomically, including selectors resolved
on the original payload before canonicalization can change positions.

Unordered means multiset equality. Preserve duplicates, cardinality and element
associations. Composite unordered/time/identity matching must stage element
pairings and reject ambiguity that would produce incompatible bindings; it must
not independently sort fields and lose the relationship between them.

All unselected content remains exact under the encoding's explicit semantics.
A rule cannot relax authentication, endpoint/database/user, command options,
CAS/noreply/quiet behavior, lane order, transactions, outcomes, response timing
or finite consumption. A writable codec capability is separate from comparison
capability. Reconstructing a delivery copy must retain the protocol envelope,
unselected data and signature/encryption dependencies.

## Evidence manifest and effects

The minimal immutable manifest binds:

| Fact | Required identity and provenance |
| --- | --- |
| Recording | Completed standard recording, selected inventory/coverage, actual Source artifact and capture plan. |
| Attempt | Real Target execution artifact, startup inputs, engine semantics, Replay session/attempt and runtime policy. |
| Witnesses | Original bytes and fingerprints, complete/truncated status, outcome, exact case/connection/sequence and role on each surface. Failed Target request bytes remain protected. |
| Interpretation | Typed slot/selector, codec/schema identity, field presence/types, anchors with provenance/quality and declared key references. |
| Stateful proof | Capture/reference scope, staged decision/binding provenance, sequence/nonce/lock relationships and finite exchange identity. |
| Source claim | Source revision and source/schema references, semantic fact, scope and allowed effects. An observed difference alone is not this proof. |
| Plan | Original compiled policy, proposed effects, complete evidence digest and all relevant artifact identities; apply revalidates them. |
| Usage | Actual comparisons, bindings, delivered-copy changes, consumption, residual differences and verification result. |

Bounded worker summaries are views of this manifest. They expose selectors,
counts, representative differences, missing proof and next actions without
dumping raw bodies, JWTs, keys or complete expected responses. Summary omissions
are distinct from uninspected evidence: a plan requires complete coverage of
its selected inventory even when only one example is shown.

Effect identities are computed from compiled semantics, not configuration
filenames. A single file may contribute to several identities:

| Identity | Included effects | Consequence of change |
| --- | --- | --- |
| Capture | Source admission/input/response rewrite, capture resource selection and snapshot behavior. | Determine whether existing immutable evidence suffices or a real new recording is required. |
| Runtime | Target matching, dependency delivery, primary assertion, stateful relationships, finite sharing and live ordering admission. | Fresh genuine Replay is required; old Target output cannot become current by reclassification. |
| Classification | Report-only unused ownership explanation. | Reclassify only complete original unused evidence when the executed behavior identity remains current. |

Any effect that changes both live order and reports enters both relevant
identities. Plans also bind the complete authoring transaction to detect
concurrent edits. Source schema, key provenance, engine semantics and selected
recording changes invalidate the plans that depend on them.

The compiler fixes this execution order; workers do not author an arbitrary DAG:

```text
immutable inventory / ownership / protocol admission
  -> slot extraction -> codec/type/presence validation -> field selection
  -> pure contract preview with staged state -> strict remainder/relationships
  -> exchange selection -> protocol claim and binding commit
  -> optional response-copy materialization -> delivery/termination
  -> protocol consumption -> audit/assertion/classification/aggregate gates
```

Protocol lifecycle stays authoritative. Redis can claim an exchange and commit
bindings before response I/O; successful consumption follows delivery or the
required client termination. Failed delivery stays unsafe/dirty. Existing
protocol-specific claim/consumption behavior must not be changed accidentally
by a shared comparator.

API-origin witnesses derive only from original immutable Source evidence.
They may permit proven foreign work to stop imposing order without changing
its original Case attribution or finite consumption. Same-resource read
permission is report-only. Finite sharing explicitly changes derived admission
scope and preserves origin plus single-use inventory. Snapshot reuse separately
requires a safe Global seed, complete resource coverage and nonconflicting
original responses. Payload normalization cannot establish any of these facts.

Unused classification is reversible: restore previous overlays before applying
current rules; preserve original owner and matched proof. It must not remove
Target unmatched/unsupported/unsafe/header failures. A Case becomes Passed only
when its real primary-response assertion passed and its complete dependency
view is clean. Shared-session projections are updated with the same recording,
Source revision, inventory and attempt identity.

## Worker discovery and policy transaction

Ordinary failure output should identify candidates and their limited meaning:
surface, slot, codec/type, likely contract, selected scope, coverage, missing
Source proof and supported next action. Do not present a syntactic time/UUID/PB
candidate as an established Source semantic fact.

The intended interaction is:

```text
failure/evidence -> candidate + missing proof
  -> rule plan --file rule.yaml --evidence <current-evidence-id>
  -> reviewable policy/effect diff + obligations + plan ID
  -> rule apply --plan <plan-id>
  -> required classification / genuine Replay / real recording and Replay
```

The same CLI accepts one rule, a list, or a complete policy document. Engine-generated
scopes and codec selectors should be prefilled so workers supply only
the Source fact and genuinely missing schema/relationship choices. Plans show
what stays strict, affected coverage, residual differences and the exact next
verification action. They never ask workers to construct internal fingerprints.

Distinguish candidate, needs-proof/schema/evidence, stale, unsupported,
planned, applied-pending-verification, verified, residual-failure and
not-observed. `apply` only records a policy change. Offline preflight is not
real Replay; not-observed is not a successful validation. Idempotent apply does
not manufacture a new verification permit. Existing coordinator scheduling,
quality and Source-review gates remain in force.

## P0-P5 delivery and acceptance

| Phase | Implementation state | Deliverable and hard prerequisite | Exit evidence |
| --- | --- | --- | --- |
| P0 | Complete | Requirement map, new document vocabulary, boundaries and nonnegotiable effect/evidence contracts. | This reviewed document against baseline and reference configuration; no implementation claim. |
| P1 | Complete | Smallest complete JSON path through all three surfaces, Source proof entry, discovery/plan/apply/audit/recovery and verification. Includes the strict schema, typed IR/capability boundary, shared time core, pure decisions and frozen evidence needed for this path. | Self-contained JSON comparison/delivery examples; bounded discovery, reviewable plan, stale-safe apply/recovery, strict remainder, microsecond precision and required fresh genuine Replay. |
| P2 | Complete | PB plus Memcached/HTTP/SQL cross-protocol slot/codec reuse. Requires the complete P1 JSON transaction rather than a compiler-only foundation. | JSON/PB contract parity, explicit typed PB fields, writable envelope preservation, HTTP/Redis/Memcached/SQL symmetry and unchanged protocol lifecycle. |
| P3 | Complete | Identity, nonce, cryptographic envelopes and propagation. Requires P1 staged decisions and P2 typed extraction/reconstruction. | One-to-one capture/reference, script/PUBLISH/time composition, JWT/URL/crypto checks, stable remainder and atomic failure behavior. |
| P4 | Complete | API origin, ownership, finite sharing, snapshot and Source capture/inbound input domains. Requires independent P1-P3 value decisions and effect identities. | Immutable Source cause/identity proof; strict lane/transaction/finite gates; reversible classification; explicit input/signature transformations and capture obligations. |
| P5 | Complete for engine and offline configuration migration | Direct new-format cutover, removal of old entry points and reference-project configuration on a separate project branch. Requires all inventory rows and native domains to be mapped. | No fallback format, no lost scope/proof, checked examples/docs, repository checks and tested fresh Recording/Replay obligations. Reference-project Target execution remains unverified. |

Each phase is independently reviewable and committed. If implementation changes
a boundary or public spelling, update this document in that phase. P5 must not
declare completion while unsupported native domains remain as opaque legacy
entries, or while the reference configuration can only be made to load by
dropping rules. Preserve unrelated project progress and local artifacts.

| Acceptance axis | Positive witness | Required rejection or preserved failure | Phase |
| --- | --- | --- | --- |
| Protocol x codec x surface | Reuse one contract on HTTP/Redis/Memcached JSON/PB slots and primary JSON/PB responses where the adapter supports the envelope. | Unsupported frame/type/effect fails explicitly; missing protocol support is not inferred from codec support. | P1-P2 |
| Collection | Reordered members with identical multiplicity; disjoint time/identity fields compose. | Added/removed member, changed duplicate count, changed stable element or incompatible pairing. | P1-P3 |
| Time precision | Seconds/millis/micros and RFC3339 represent the same permitted relation; naive relative times need no offset configuration. | Lost microseconds, wrong unit/anchor or absolute-window offset, absent clocks, overflow, equal Source instants becoming unequal, or cross-field shift differing beyond 1 microsecond. | P1-P2 |
| Generated identities | Valid shape and consistent capture/reference mapping across selected calls. | Collapsed IDs, changed references, unselected substitution, wrong endpoint, or a failed candidate leaking bindings. | P3 |
| Script/nonce/PUBLISH | Declared script envelope and UUID/time fields all validate before commit. | Changed Lua digest/body/numkeys/KEYS/ARGV, nonce reuse, UUID selector ambiguity or partial commit. | P3 |
| Signed/encoded content | Both signatures validate; stable claims/URL bytes and related expiry/TTL remain checked. | Wrong signature/key/algorithm/kid, altered stable claims, duplicate URL parameter, invalid envelope/padding, or changes hidden by whole-token random. | P3 |
| Delivery | Explicit selected-field time rebase writes a derived copy and retains raw evidence/outcome. | Signed content rewritten without required reconstruction, unselected PB/JSON/envelope changes, write failure counted as success or snapshot/token renewal inferred automatically. | P1-P3 |
| Protocol lifecycle | Ordinary pool differences preserve source lane order and correct finite claim. | Stateful-lane theft/splitting, transaction/CAS/options/auth differences, extra call reusing finite inventory, wrong termination or unsafe capture. | P1-P4 |
| Ownership | Proven foreign work can be classified with original provenance retained. | Target unmatched/unsafe/header failure disappearing, same-resource report permission changing live order, or absent/ambiguous origin treated as proof. | P4 |
| Snapshot/sharing | Finite selected read or safe complete Global seed under its own proof. | Missing seed, response conflict, incomplete resource range, invented read, or normalized payload used to prove reuse. | P4 |
| Evidence/plan | Complete selected witnesses with bounded summaries; exact relevant plan inputs remain unchanged. | Summary mistaken for complete proof, truncated bytes, cross-project proof inheritance, changed recording/schema/key/artifact/policy or stale attempt. | P1-P4 |
| Publication | Real response assertion plus clean complete dependency view; reversible unused-only overlay. | Old execution made current after runtime changes, incomplete cases upgraded, failed delivery erased, or withdrawn rule leaving its overlay behind. | P1-P5 |
| Cutover | Every reference requirement has a new typed owner, scope and proof. | Dropped Source admission/rewrite/Breeze/input/JWT/codec domain or an old-format escape hatch. | P5 |

Use isolated deterministic fixtures for protocol/contract regressions, then the
existing genuine Replay path for behavior-changing effects. Real recordings
are required when a selected rule needs uncaptured or changed Source facts;
never synthesize missing historical exchanges. All normal repository checks
remain required before opening or updating an MR, including formatting, tests,
Clippy and the code-organization check against the intended target branch.

## Delivered implementation and validation

Both repositories use branch `codex/unified-rule-contracts-KCYgNKF0ZW` in
isolated worktrees. Phase anchors below identify the initial cohesive delivery;
subsequent phase-labelled commits close protocol/evidence boundaries and final
regressions rather than mixing unrelated work into a single commit.

| Phase | Initial delivery commit |
| --- | --- |
| P0 | `aa161b0` |
| P1 | `ac1428d` |
| P2 | `4542e91` |
| P3 | `1c2b63a` |
| P4 | `11e1a6f` |
| P5 | `8e0b592` |

Master commits `f82a7b6` (explicit clock groups) and `044b8c2` (literal HTTP
paths) were merged and retained, together with the baseline microsecond time
support. Final responsibility review confirms that the shared value kernel
remains pure, policy compilation owns validation and identities, protocol
adapters own complete envelopes and lifecycle, and the coordinator owns frozen
evidence and stale-safe transactions. Source writers preserve unrelated rules,
nested proofs and authored response-plugin precedence. No changed Rust product
file exceeds 1000 lines; registry settings and dependencies were unchanged.

Final repository checks passed:

```sh
cargo fmt --check
cargo test --no-fail-fast
cargo clippy --all-targets -- -D warnings
CODE_ORG_BASE=origin/master plugins/ai-software-engineering/skills/backend-rewrite/scripts/check-code-organization
git diff --check
```

All test targets together report 2381 passed, zero failed and four existing
ignored tests (two Docker-dependent host tests and two MySQL benchmarks).
The library contributes 2272 passing tests. No migration utility or additional
ignored test remains in the product tree.

Reference-project commit `337bcc0e4` changes only the four policy configuration
paths: it adds `.traffic-e2e/policy.yaml`, points `project.policy` to it and
removes the two retired rule files. The migrated policy contains 112 rules
(five shared value rules and 107 typed native rules), retaining all 64 original
dependency rule IDs, 185 capture paths and 27 process selectors. Its SHA-256 is
`cc90220a779217b045dc383b065b27d08c3422d710b0b214e34ddb342f19b36b`.
The latest source requirements include runtime-token validation, S3 GET signing
time and the OIDC CLI session key family. Loading, compilation and recorder
projection of the actual committed project configuration passed offline using
the final engine library.

The original reference checkout stays on `replay/20261017-1`; its pre-existing
uncommitted progress remains untouched. This delivery does not execute its
Target, start recording, install an engine, or renew execution evidence.
Adoption still requires the engine-issued genuine Replay obligations and fresh
Recording when capture, snapshot or missing Source evidence requires it.

The human-authoring follow-up retains the original typed abstractions and full
explicit syntax, adding only local proof inheritance, shared Source identity and
named time conveniences. Final regression after this change reports 2391 passing
tests (2282 library), zero failures and the same four pre-existing ignored tests;
strict Clippy, formatting and code organization checks pass. Public plan/apply
tests verify complete expanded proof and unchanged stale/evidence/Replay gates.

Reference-project commit `cc5d94b49` on `replay/20261017-1` retains 113 rules and
all 65 original dependency IDs. Readable rendering reduces 4988 lines / 257081
bytes to 3448 lines / 147524 bytes, keeping blocks and folded human-readable
paragraphs.
All expanded contracts, complete proofs and the four effective fingerprints are
identical; the full fingerprint remains
`sha256:9644af296ab3508ef8ad39220f3c4538bcd06a756ef1ddf3f466a9298d197b04`.
The recording Dockerfile, build/start scripts and bilingual project instructions
also adopt the unified file/env names and a container `.traffic-e2e/` layout
consistent with `project.policy`. Script syntax, an isolated deployment dry run
and actual project recorder projection pass without starting Docker or Target.
The recording image must use an engine that includes this MR; the build checks
that capability, and no image publication or running-binary update is performed.


Conditional fields also support `when: {relative_pointer: ../type, equals: text}`.
Native Redis JSON identity captures can carry the same sibling condition under
`effect.capture.when`; this controls capture without disabling later bound
references. See [conditional field contracts](conditional-field-contracts.md).
