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

## Current global field authoring

`traffic-policy/v2` declares one carrier-independent `json.fields` map. Fields
use `kind: time` or `kind: identity` with `formats`, or `kind: unordered`.
Source case capture uses `recording.case_paths` with the root `source_revision`.
Time comparisons preserve relative differences. JSON payloads are recognized
automatically in supported carriers, including MySQL columns; no per-column,
API, SSE event or cache-key JSON declaration is required. Root `mysql` enables
native time metadata inference; `mysql.tables` declares other scalar formats.
MySQL table fields and Redis key declarations need no repeated resource/database
selectors. `redis.keys` also describes supported key-local state and ordered
commands. `http.headers` formats retain strict header presence, count and order;
there is no absence waiver or generic SDK-header whitelist.
Identity correspondence is internal: equal complete typed Source IDs must be
equal Target IDs and distinct Source IDs cannot merge. Prefixes and scalar
types are preserved. Reads reuse established Target IDs and anchor unknown inputs.

Dependency lifetimes use `localcache.requests` and
`process_dependencies.tasks.<actual-Source-task-name>.requests`; HTTP entries
require a host and process classification requires immutable `source_revision`.
One task can contain requests from multiple protocols. Source-proven compound
strings use global templates; outbound paths use `http.requests`, learned
response addresses use `http.response_rewrite`, and API positions bind encrypted
JSON or shared DOCX formats while preserving applicability scope. Supported
multipart boundaries compare through the protocol engine without a project rule.
Native owners retain additional relationships, typed PB schemas and cryptography.
Named `signatures`
profiles and `api` positions deduplicate existing signing owners; global
`kind: jwt` additionally verifies HMAC signatures and claims through the same
frozen key context. The old authored identity `formats: [jwt]` syntax is rejected;
JWT declarations require `kind: jwt` and a named verification profile.
See [signature profiles](signature-profiles.md) and
[content formats and carrier bindings](content-policy-layout.md). Explicit codec
bindings and Source proof remain required where documented. Ordinary proposals
add fields and append new formats while preserving existing declarations, order
and exact deduplication. Intentional section changes or removals require an
explicit `traffic-policy-change/v1` proposal with `replace_sections` and complete
replacement maps. See [global field formats](resource-field-contracts.md)
for the current schema and complete examples. The inventory below records the
earlier design baseline.

The published `policy.yaml` contains runtime declarations only. Source file
references, facts and nested `proof` records belong to the rule plan. An annotated
proposal supplies that evidence; planning freezes its original artifact and an
independent Source-proof snapshot. Apply rechecks the snapshot hash, its runtime
permission identities, immutable Source inventory and independent Target
evidence before writing a policy without proof metadata. Loading a runtime policy
does not require evidence text. Editing an explanation alone changes neither
runtime fingerprints nor Replay obligations. Root `source_revision` remains an
explicit Source identity for capture effects.

## Evidence surfaces and additional effects

Keep three value surfaces explicit:

| Surface | Values and responsibility | Default |
| --- | --- | --- |
| `dependency.request` | Compare the immutable Source dependency request with the actual Target client request before selecting an exchange. | Exact protocol identity and unselected content. |
| `dependency.response` | Select the recorded dependency input and, when explicitly authorized, materialize a delivery copy for Target. There is normally no Target-produced response to compare here. | Deliver recorded evidence with its original outcome and timing. |
| `api.response` | Compare the recorded primary response oracle with the actual Target primary response. | Strict status, headers, structure and unselected content. |

Global JSON formats apply wherever the protocol owner recognizes complete JSON,
including ordinary bodies and SSE data. Event presence/order, SSE envelopes,
closure, status, headers and unselected content stay strict. An absent field
has no positive witness; an incomplete payload cannot invent a complete body.
Native interaction or compound contracts retain their own typed evidence and
field ownership. Planning uses protected immutable artifacts and independent
Target observations; it never rewrites recordings. See
[SSE value contracts](sse-value-contracts.md).

Inbound request JWT translation, Source capture admission, Source response
rewrite, process ownership, API-origin attribution, finite sharing and snapshot
admission remain explicit typed effects. They are not additional permissions
obtained by decoding a value. In particular, an unordered SET value rule does
not reorder a GET response, authorize a reusable read, or classify unused work.

## Resource scope across APIs

Global content declarations are independent of the API and resource carrying
the value. MySQL scalar formats select table patterns/columns; Redis scalar,
key and command declarations select bounded key patterns. The adapters still
pair actual endpoint, database, authentication and protocol identity before
comparing content. Additional native causal or cryptographic effects retain
their precise physical and API scopes. Planning must never silently broaden
those constraints when compacting a declaration.

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
| S07 | API work that continues after its HTTP response. | `async_api` selects the first matching Source request/response scenario and retains the ordinary Case until a concrete final SQL/Redis access, complete successful HTTP exchange, a case-owned dependency failure or the common deadline; all captured dependencies remain strict finite obligations. |
| S08 | MySQL process scans, shard/table families and recovery lookback. | Native SQL selection with physical-table equality, bounded table series and complete Source request/response evidence. |
| D01 | MySQL generated timestamps in SQL values and nested JSON values. | Shared typed time contract plus SQL slot adapter; preserve nonselected parameters and statement identity. |
| D02 | MySQL response-time fields and relative lease/expiry values. | Explicit dependency input materialization, separate from SQL request comparison and final response assertion. |
| D03 | HTTP unordered department IDs; Redis JSON/PB collection values. | One multiset contract over typed collections; preserve duplicates, length, membership and element associations. |
| D04 | HTTP signing headers, raw-query timestamps and JSON request timestamps. | Header/query/body slot adapters plus shared time semantics; auth and stable URI bytes stay checked. |
| D05 | Redis GET/HGET token/session expiry rebasing. | Explicit response-copy delivery; preserve source age/offset and finite matched inventory, not implicit cache renewal. |
| D06 | HTTP OAuth initialization sharing and Redis token read sharing. | Explicit finite sharing with Source lifetime proof; independent from codec, time comparison and snapshot reuse. |
| D07 | Redis scalar ownership tokens and later references. | `redis.keys` identity formats plus engine-owned complete-value correspondence; preserve NX/EX/PX/options, script identity, lane order and finite consumption. |
| D08 | Redis PUBLISH publisher UUID plus generated JSON timestamps. | Pure value previews compose atomically; preserve channel, publisher identity, unselected JSON and timing relationships. |
| D09 | Redis SET/RPUSH JSON time, ZADD/range times and script ARGV time. | Typed slots plus shared time; command sequence, numkeys, all KEYS/ARGV and Lua digest/body stay protocol-owned. |
| D10 | Rate-limit window keys and INCRBY/EXPIRE sequences. | Typed key template and bounded time-window derivation; key/value relation and command sequence are not random exemptions. |
| D11 | VNC session and ticket key captures with JSON references. | Explicit capture/reference templates, base64url/hex shape, one-to-one identity mapping and stable TTL/options. |
| D12 | Multipart upload boundary differences. | Structured multipart comparison; only boundary delimiters change, while part order, bytes, filenames and headers stay checked. |
| D13 | Generated SQL IDs/names, Redis block IDs and complete JWT values. | Global formats and the internal complete-value identity graph compose atomically across carriers; preserve integer/string distinction. Additional physical key/path templates retain their native owner. |
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
| `policy/schema`, `policy/declarations` | Strict root JSON/MySQL formats, endpoint aliases, Source conditions and native effect payloads. | Runtime state or protocol I/O. |
| `policy/authoring`, `policy/compiler` | Resolve endpoint aliases and native proofs; validate formats, ownership and capabilities; prepare immutable typed IR. | Infer business permission from a sample or mutate recordings. |
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

## Configuration core

Root `json.fields` is the sole authored description of decoded JSON fields.
Root `mysql.tables` describes scalar column formats that SQL metadata cannot
infer; root `redis.keys` describes scalar cache values and key-local behavior by
key pattern, without authored resource/database selectors. JSON-valued SQL columns and cache values need no declaration. Native SQL
DATE/DATETIME/TIMESTAMP metadata supplies ordinary temporal semantics when the
root `mysql` policy is enabled. The [field guide](resource-field-contracts.md)
defines exact syntax, null/missing behavior and format selection.

Old resource field graphs, response declarations, per-API value rules and
`field_ref` are rejected. Endpoint aliases under `resources` remain available
for native protocol, cryptographic and causal effects. Native rules retain their
stateful scope; their Source explanations remain in the separate plan evidence.

Supplied JSON/MySQL/Redis/HTTP declarations add new fields by default. Formats on
an existing field append in authored order and deduplicate exact matches, so an
existing `[format-a]` plus `[format-b]` becomes `[format-a, format-b]`. Existing
fields remain, and an ordinary empty map does not clear them. Incompatible kind,
profile, table-pattern or existing asynchronous API changes reject by default.
Explicit `replace_sections` in a `traffic-policy-change/v1` proposal authorizes
replacement only for the named, supplied sections; complete desired maps and
removed declarations must be reviewed. Native replacements retain explicit
`replace_rules` IDs and frozen Source evidence.
The renderer emits simple kind/formats fields on one line and verifies that
parsing its output preserves the compiled policy fingerprint.

Global `*` traverses arrays. Missing fields are optional, while one-sided
presence, type changes, array count/order and unselected members remain strict.
Time and identity fields accept paired null values automatically, without clocks
or mapping. Equal scalars compare exactly before parsing formats or requiring
clocks; equal identities still reserve their complete typed equality anchors.
Unrecognized differing scalars fail. Numeric epoch alternatives use Source timestamps and independent
Source clocks to resolve units; unresolved alternatives compare exactly.

Global identities join by complete typed Source values. Their format list or
JSON path does not name a group: equal Source values require equal Target values,
and distinct values cannot collapse. Candidate decisions commit atomically.
Existing dependency correspondence is reused on read delivery, while unknown
inputs anchor themselves. Internal correspondence is never authored as binding.

Within a submitted plan proposal, native proofs inherit within their own rule.
Root `source_revision` supplies a common frozen Source identity; nested proposal
proof may override its local source/fact. Rendering the runtime policy removes
these schema-owned evidence records and preserves business fields with names
such as `proof`, `source` or `fact`. The explicit runtime permission
`state_epochs: true` retains its state semantics; its separate Source explanation
belongs on the proposed read-back declaration.
Proof facts are nonempty logical single lines of at most 200 UTF-8 bytes, and
source lists contain at most three references. Native compact `relative_time`
and `request_time` contracts remain for additional causal relationships such as
read-back and signed-token companions. They do not restore ordinary per-API
field configuration.

## Native effects stay local to the rule

A value rule composes existing slots, codecs and pure contracts. A stateful or
cryptographic permission retains its domain owner in a typed `effect`. In a plan
proposal, the outer proof states the Source fact and nested `contract`/`proof`
pairs supply independently auditable facts. Published policies contain the
contracts alone. The annotated examples below describe plan inputs.

Ordinary request headers, including SDK headers, retain strict presence and
value comparison. Policies cannot waive missing headers or downgrade them to
observations. Global HTTP field formats may compare generated values while
preserving the native header presence requirement.

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
format: traffic-policy/v2
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
                contract: {format: base64url, decoded_bytes: 18}
                proof: {source: app/vnc.py:start, fact: Source draws an 18-byte token once and shares it between session ID and URL.}
          proof: {source: app/vnc.py:start, fact: The session ID has a fixed vnc prefix.}
        /url:
          contract:
            kind: template
            template: 'wss://vnc.example/vnc-proxy/sessions/vnc-{session}?ticket={ticket}'
            fields:
              session:
                contract: {format: base64url, decoded_bytes: 18}
                proof: {source: app/vnc.py:url, fact: This is the same session token.}
              ticket:
                contract: {format: base64url, decoded_bytes: 32}
                proof: {source: app/vnc.py:start, fact: Source independently draws a 32-byte connect ticket.}
          proof: {source: app/vnc.py:url, fact: Scheme/authority/path and the ticket query key are deployment-fixed.}
    proof:
      source: app/vnc.py:start_and_url
      fact: Only these explicitly typed fragments vary and the session identity must agree across both fields.

json:
  fields:
    /items/*/waitingDurationSeconds: {kind: duration, formats: [seconds]}
```

Plain native UUID/random contracts validate only their declared shape. Global
identity field formats preserve ordinary cross-resource equality and
distinctness automatically from complete typed Source values. Native template
or identity/nonce effects retain additional
embedded, derived or cryptographic relationships. Parsed template tokens participate in the same internal correspondence as
declared field identities, with complete Source token values and scalar types. Integer identities are capture-only
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
progress publication resolve this path. Writers preserve every other runtime
rule while retaining complete Source proof in independent plan records. Only the new format is accepted; old DTOs remain
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
- Ordinary global fields and declarative Redis command arguments expose no
  authored clock groups. Equal normalized Source instants in command arguments
  require equal Target instants internally; distinct Source instants remain
  independent within the fixed window. Additional native causal contracts retain
  their proven explicit clock relationships.
- Preserve sequence-level relationships for scalar and nested JSON script
  timestamps. Validate script digest/body, numkeys, KEYS, ARGV and selected
  indices together without evaluating Lua.

Declared identity formats retain their eligible complete values and
case-local one-to-one Source/Target mapping. Native identity/nonce effects also
retain their capture, lifetime and allowed reference endpoints. Candidate previews
stage decisions without changing live state. A failed stable field, signature,
time relation, element pairing or protocol admission discards those decisions.
Global PUBLISH JSON identity/time checks commit atomically. Original payload
structure determines pointer selection before reconstruction changes bytes.

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

Discovery follows actual decoded arrays when producing wildcard paths. Identical
logical JSON path/format candidates merge across carriers, indexes and cases
within the bounded scan window; their IDs do not contain a witness or concrete
array index. Each candidate reports a bounded `locations` list of witness IDs and
concrete pointers, `location_count` and `locations_omitted`. These counts explain the
sampled draft and do not establish full coverage. Summary pages retain the same
candidate IDs, and scan continuations retain the existing observation/node bounds.
Drafts contain only root `json.fields` formats; they do not introduce an API,
resource, clock group or identity group. `plan_ready` remains false until Source
intent is established, and differing identifiers never infer identity permissions.

The intended interaction is:

```text
failure/evidence -> candidate + missing proof
  -> rule plan --file rule.yaml --evidence <current-evidence-id>
  -> reviewable policy/effect diff + obligations + plan ID
  -> rule apply --plan <plan-id>
  -> required classification / genuine Replay / real recording and Replay
```

The same CLI accepts one native rule, a native-rule list, or a complete policy
document. Format changes use root JSON, MySQL or Redis maps. Workers supply the
Source fact and supported formats; the engine owns decoding and correspondence. Plans show
what stays strict, affected coverage, residual differences and the exact next
verification action. They never ask workers to construct internal fingerprints.

Ordinary documents remain additive; omitting an existing rule or field does not
delete it, and adding a supported format preserves the existing format order.
An explicit reviewed replacement uses the same plan/apply CLI with this wrapper:

```yaml
format: traffic-policy-change/v1
replace_rules: [old-a, old-b]
policy:
  format: traffic-policy/v2
  rules:
    - id: cache-stream
      match:
        resource: {protocol: redis, endpoint: 'cache.example:6379', database: 0}
        operation: APPEND
        key: {kind: exact, value: task-cache}
      effect: {kind: redis_append_stream}
      proof:
        source: source/cache.py:write
        fact: Source appends a finite ordered text stream; only chunk boundaries vary.
```

Only the listed old IDs are replaced; every unlisted rule is retained. The nested
policy must contain the complete proposed rules, each admitted through the same
Source/Target coverage preflight. Existing primary response/input rules cannot be
removed across another API's issue. This is not permission for an unproven
replacement or implicit deletion. Whole-policy compare-and-swap, durable apply
intent, stale-input rejection, recovery and required fresh Replay remain active.

The same wrapper optionally accepts `replace_sections: [json, mysql, redis, http,
async_api]`. List only the sections intentionally being changed or cleared and
provide each complete desired section under `policy`; unlisted sections keep
the ordinary additive behavior. For example, clearing JSON requires an explicit
`replace_sections: [json]` and `policy.json: {fields: {}}`. A section-only change
may omit `replace_rules`. The plan exposes additions and removals before apply;
neither mode bypasses Source proof, complete preflight or genuine verification.

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
