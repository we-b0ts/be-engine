# Rule Diagnosis

Read this after tracing Source and Target behavior. The authored
`traffic-policy/v2` document lives at `project.policy`. Workers return Source
conclusions and a proposed declaration/rule document; the coordinator plans/applies it.
The complete schema, examples and lifecycle are in
[unified rule contracts](../../../../../docs/unified-rule-contracts.md).

## Rule Discovery From Source Diagnosis

Use `facts.rule_guidance`, mechanical candidates, declared capability requirements
and the current evidence ID. A candidate establishes a possible mechanism, not
business permission. At the first relevant mismatch, inspect existing declarations
and `source_entry.bindings`, even when `candidates` is empty. Return the smallest
Source-proven scope, exact field and
encoding, Source file/symbol, and a fact explaining the allowed relationship.
An absent candidate does not mean the capability is unavailable. Ask for missing
schema or clock evidence rather than guessing from field names or values.

Declare stable physical fields under `resources`, API output fields under
`responses`, and contextual/stateful behavior under `rules`. Reuse named resource
identity and field strategy through `field_ref`. Choose the strategy from Source
semantics: time format/relation, duration unit/branch, unordered consumer behavior
or identity variability. These reuse supported scalar/JSON/Protobuf slots. See
[resource-field contracts](../../../../../docs/resource-field-contracts.md); a codec
provides decoding, while selectors and Source proof determine permission.

| Evidence and Source fact | Proposed contract/effect | Preserve |
| --- | --- | --- |
| An unordered Set becomes a JSON array or repeated PB field | Declare `unordered` once at its owning resource/response field; PB declares field numbers/types explicitly | Multiplicity, membership, element associations, presence, unknown PB fields and remainder |
| A generated timestamp or expiry | Declare time format/relation once at its owning field, using the adapter-owned request clock | Units, microseconds, TTL offset, copied instants and clock groups |
| Redis SET stores a scalar floating timestamp | Resource/DB/key `container: string`, `value.codec: json`, root `value.fields: {'': {relative_time: unix_seconds}}` | Key, options, TTL and finite calls stay strict. A native sequence adapter's scalar-slot whitelist does not imply the generic value capability is missing |
| SDK runtime headers differ, and Source consumer/middleware do not read them | Explicit API/endpoint/method/path-scoped `http_client_metadata` with exact supported names; [schema](../../../../../docs/http-client-metadata.md) | Business/authentication headers, body/query, finite requests and delivery. `protected: false` concerns confidentiality; it does not make a mismatch nonblocking |
| SSE data contains a generated timestamp | `api.response`, exact `slot.sse_data` event/type, JSON pointer and Source-proven request-time relation | Event presence/order, envelope, unselected fields and terminal state |
| Source generates an identity used in SSE, MySQL or Redis | Inventory all eligible physical locations together; declare `identity` with proven prefix/format and a shared case-local `binding` | Source equality and distinctness, fixed input anchors, exact prefixes and terminal output locations |
| Live elapsed duration that stops at terminal state | Declare the owning field's Source sibling `conditional` around `duration`, with its unit | Terminal values and status stay exact; missing/wrong-type status rejects |
| Expired recorded Redis/MySQL input | Explicit `dependency.response` time contract plus selected `delivery.rebase_time`, or typed SQL response effect | Raw Source bytes, sentinel values, protocol outcomes, finite inventory and signature dependencies |
| An ordinary generated ID is reused across resource fields | Declare each eligible resource/response location once with the same identity `binding`; SQL templates, value ordinals and generator-first capture are unnecessary | Bijection, case scope, explicit format, guarded eligibility and atomic candidate decisions |
| Redis/MySQL reads a declared identity before later use | Keep the physical identity declaration: established mappings deliver Target IDs; unknown inputs anchor themselves | Selected locations, successful delivery, original Source data flow, finite reads and fresh Replay |
| A native captured identity gains an additional consumer or special read-back behavior | Extend the existing native `effect.references` / `read_back` / `mysql_read_back` with separate proof; [details](../../../../../docs/dynamic-value-rules.md) | Existing capture/scope/proofs; native causality and templates. This is additional behavior, not the default authoring model for ordinary fields |
| SQL JSON combines identities and generated times in variable-length arrays | Declare physical JSON paths such as `/blocks/*/id` and `/blocks/*/timestamp`; use native `field_ref` only for additional contextual relations | Shared identity domain, array shape/order, business members and independent time clocks |
| LSET updates a stored JSON list element | Declare Redis list value fields once under `resources`; retain native rules only for derivation, state transitions or other extra relationships | Exact key/list index, strict remainder, command framing and finite writes |
| Source buffers ordered text into APPEND batches whose boundaries vary with scheduling | Explicit API/resource/database/key-scoped `redis_append_stream`; see [schema](../../../../../docs/redis-append-stream.md) | Literal byte order, read/reset boundaries, correct returned lengths, exact finite expiry/other calls, successful delivery and Case ownership |
| APPEND bytes match, but a changed batch count adds current-identity GETs or fixed-TTL EXPIREs | Source-proven `read_back.state_epochs` or `redis_expiry_refresh`; see [state observations](../../../../../docs/redis-state-observations.md) | Follow the earliest Target admission index; preserve SET/DEL lifetimes, generated identity binding and exact TTL. Do not infer missing key translation from a later MGET mismatch caused by an earlier rejected batch |
| SET NX lock and conditional release | `effect.kind: redis_lock` with endpoint/database/user/key scope | Successful acquisition completion before reference, token equality, NX/TTL/script and finite consumption |
| Script ARGV/time-key or INCRBY/EXPIRE chain | `effect.kind: redis_sequence` with Source-proven ordered commands | Script identity, numkeys, KEYS, stable ARGV, sequence closure and derived key relationships |
| PUBLISH UUID and JSON times | Typed publisher identity plus disjoint shared time contracts | Channel, publisher bijection and atomic commit |
| Signed JWT, including URL-contained tokens | `effect.kind: response_jwt`; body `pointer` or `location: {header: location}`, inline key provenance and nonce contracts; `echo_query_param` for a signed nonce repeated in the URL | Both signatures, stable claims/URL bytes, unique header/query values, exact signed lifetime and body expiry/issued-at/TTL |
| Encrypted JSON with random IV | `response_generated` / `encrypted_json` with declared envelope and effective startup key | Valid padding, plaintext structure and all unselected plaintext; ciphertext is not whole-field random |
| Generated URL/session fragments | `response_generated` / `template` with explicitly typed tokens and shared bindings | Fixed scheme/authority/path/query and identity equality |
| Current date in a header or DOCX field | `response_header_date` or `response_body` | Timezone, static filename/header/XML and other archive parts |
| Expired inbound JWT | `input_jwt` with exact location, algorithm and effective startup key | Original signature, invalid-authentication cases and relative validity |
| Shared process initialization recorded in another case | `finite_sharing` with complete Source lifetime proof | Same-run immutable inventory, exact request identity and single consumption |
| Detached Source work appears unused in another case | `process_owned` with Source origin/capture/predicate proof | Original attribution, lane/transaction/identity boundaries and reversible classification |
| Missing Source acquisition or IP learned from a response | `capture_http`, `capture_breeze` or `capture_http_response` | Real new Recording and provenance of original/transformed response |

Relative naive timestamps cancel a shared UTC offset; prove consistent Source/Target
timezone behavior. `calendar_date` and absolute request windows retain explicit
offset requirements. Use a conditional self guard for a fixed scalar sentinel.
For SSE, follow the `unified_value_contract` hint to discovery and inspect
`source_entry.bindings` even when `candidates` is empty. Discovery prioritizes
primary responses for response issues but remains bounded; it never infers
identity permission. `slot: {sse_data: {event: message, json_type: <Source-type>}}`
selects the decoded data JSON in data-only streams. Collect all eligible identity
locations, including MySQL/Redis and terminal output, with their Source variability
proof and one consistent binding domain. Observed Source values determine the
concrete equalities and distinctness; do not enumerate equality pairs or require
a particular SQL to capture first. Unknown delivered IDs remain input anchors.
Missing events, changed text and event order require Target diagnosis.
See [SSE value contracts](../../../../../docs/sse-value-contracts.md).

When Source uses dependency reads, preserve that data flow. Ordinary declared
identity fields use mapped read delivery; native read-back updates are for extra
protocol/stateful behavior. Do not replace the read with a Target-local cache
solely to compensate for Replay delivery.
For SQL field semantics, return physical database/table/column, Source-proven
table-family bounds, codec and logical pointer; a new SQL statement needs no
new strategy. Only a contextual native relationship needs exact statement and
parameter/value selection with `field_ref`. Schema fields default to independent
clock groups; use a shared authored group only for one proven Source clock read.
Redis declarations select the container and hash field independently of the key.
Fixed/external IDs, null, empty values and sentinels need exact handling or proven
guards. Scalar MySQL fields have no arbitrary sibling-row predicate: when one
column mixes eligible generated IDs with fixed values, retain its narrow native
owner until the permitted subset is expressible. Random shape alone grants no
identity permission. Derived text IDs, key/URL templates, hashes, signatures and
GET/EXPIRE count equivalence retain their separate typed effects.
For read/modify/write historical timestamps, preserve the delivered input: schema
fields use successful same-case physical-field/path read-copy provenance. Equal
old values alone cannot pass, and explicit native generation contracts still
validate their clocks. Do not add SQL-specific exceptions or enable blanket read
delivery to compensate for a copied historical field.

JWT diagnosis uses the failed attempt's trusted clocks and key discovery, never
current wall time or raw tokens in notes. A 401 or missing key is insufficient
proof. Trace configuration precedence. Return a variable name, or a read-only
mounted dotenv path/field; never return key bytes. Recorded public keys may verify
response signatures and cannot sign inbound requests.

## Plan And Verification Handoff

Check `facts.policy_freshness` first. If it requires Replay, return its structured
refresh action; changing evidence IDs cannot repair stale evidence. The coordinator
uses the same entrypoint for value and native effects:

```text
backend-rewrite rule plan --file rule.yaml --evidence <current-evidence-id>
backend-rewrite rule apply --plan <returned-plan-id>
```

Return the proposed authored v2 declaration/rule document, the complete physical
location inventory for a shared identity, current evidence ID, missing proof,
and residual differences. Do not execute apply or Replay as an implementer.
The plan verifies all selected complete immutable observations, freezes policy,
startup/schema/key and Source inventory, and returns an effect diff and obligations.
Source self-validation and derived delivery copies are distinct from independent
Target observations. Stateful changes always require actual Replay; acquisition
and snapshot changes may additionally require a fresh Recording. No-op plans
preserve existing policy bytes and require no artificial verification.

`dependency-rule` and the old flag-based `rule plan` interface are retired.
The engine's returned `rule recover` action safely retires old or interrupted
plans; never edit workflow state or reuse a stale plan.

Memcached `SET` exptime retains native protocol comparison: relative TTL and zero
stay exact, absolute expirations compare remaining TTL within the fixed engine
window. A value codec rule does not change exptime/CAS/noreply behavior.
