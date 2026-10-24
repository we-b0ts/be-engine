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
and `source_entry.locations`, even when `candidates` is empty. Return the smallest
Source-proven scope, exact field and
encoding, Source file/symbol, and a fact explaining the allowed relationship.
An absent candidate does not mean the capability is unavailable. Ask for missing
schema or clock evidence rather than guessing from field names or values.

Declare one global `json.fields` map with time/identity `formats` and
`unordered` semantics, independent of APIs, SSE events and storage carriers.
JSON-valued columns need no codec declaration. Enable root `mysql` for native
time inference and use `mysql.tables` for remaining explicit scalar formats.
The engine preserves complete typed Source identity equality and distinctness
internally. `redis.keys` describes scalar values, key formats, ordered commands
and supported state behavior without resource/database aliases;
`http.headers` has strict presence/count/order. `localcache.requests` describes
finite initialization reads, while
`process_dependencies.tasks.<actual-Source-task-name>.requests` groups process
dependencies across protocols. HTTP lifetime entries require a host. Additional
uncovered compound behavior remains native.
See [global field formats](../../../../../docs/resource-field-contracts.md).

| Evidence and Source fact | Proposed contract/effect | Preserve |
| --- | --- | --- |
| An unordered Set becomes a JSON array or repeated PB field | Declare `kind: unordered` once in global `json.fields`; known PB schemas remain explicit | Multiplicity, membership, element associations, presence, unknown PB fields and remainder |
| A generated timestamp or expiry | Declare `kind: time` and `formats` once in global `json.fields`; relative differences use independent request clocks | Units, microseconds, request-relative differences and Source-equal instant consistency |
| Redis SET stores a scalar floating timestamp | `redis.keys.<pattern>: {kind: time, formats: [unix_seconds]}` without resource/database selectors | Key, options, TTL and finite calls stay strict. A native sequence adapter's scalar-slot whitelist does not imply the generic value capability is missing |
| SDK request headers are missing or differ | Restore the Source-required wire headers in Target. Global HTTP formats may validate generated values; they cannot waive header presence. | Header names, stable values, business/authentication headers and finite requests remain checked. `protected: false` concerns confidentiality, not acceptance. |
| SSE data contains a generated timestamp | The global `json.fields` pointer with `kind: time` and Source-proven `formats` | Event presence/order, envelope, unselected fields and terminal state |
| Source generates an identity used in SSE, MySQL or Redis | Declare identity formats at global JSON pointers and explicit MySQL scalar fields; correspondence follows complete typed Source values internally | Source equality and distinctness, fixed input anchors, exact prefixes and terminal output locations |
| Live elapsed duration that stops at terminal state | Declare global `kind: duration` with its unit in `formats`; no business-status predicate | Units, paired absence/nulls, status and unselected members remain checked |
| Expired recorded Redis/MySQL input | Global time formats or safe native SQL temporal metadata inference; historical copied values retain read provenance | Raw Source bytes, sentinel values, protocol outcomes, finite inventory and signature dependencies |
| An ordinary generated ID is reused across resource fields | Declare JSON pointer formats globally and scalar MySQL fields under `mysql.tables`; SQL templates, value ordinals and generator-first capture are unnecessary | Bijection, case scope, explicit format, guarded eligibility and atomic candidate decisions |
| Redis/MySQL reads a declared identity before later use | Keep the global field/key format: established mappings deliver Target IDs; unknown inputs anchor themselves | Selected locations, successful delivery, original Source data flow, finite reads and fresh Replay |
| A native captured identity gains an additional consumer or special read-back behavior | Extend the existing native `effect.references` / `read_back` with separate proof; [details](../../../../../docs/dynamic-value-rules.md) | Existing capture/scope/proofs; native causality and templates. This is additional behavior, not the default authoring model for ordinary fields |
| SQL JSON combines identities and generated times in variable-length arrays | Declare root-relative JSON paths such as `/blocks/*/id` and `/blocks/*/timestamp`; retain native proof only for additional causal relations | Automatic identity correspondence, array shape/order, business members and independent time clocks |
| LSET updates a stored JSON list element | Use the global `json.fields` paths for complete JSON list values; native contracts remain only for additional relationships | Exact key/list index, strict remainder, command framing and finite writes |
| Source buffers ordered text into APPEND batches whose boundaries vary with scheduling | `redis.keys.<bounded-pattern>.append_stream: true`; see [schema](../../../../../docs/redis-append-stream.md) | Literal byte order, read/reset boundaries, correct returned lengths, exact finite expiry/other calls, successful delivery and Case ownership |
| APPEND bytes match, but a changed batch count adds current-identity GETs or fixed-TTL EXPIREs | `redis.keys` scalar identity `read_back: true` or `expiry_refresh: true`; see [state observations](../../../../../docs/redis-state-observations.md) | Follow the earliest Target admission index; preserve SET/DEL lifetimes, complete-value identity correspondence and exact TTL. Do not infer missing key translation from a later MGET mismatch caused by an earlier rejected batch |
| Generated scalar Redis token and later script ARGV | `redis.keys` identity format; known complete values propagate automatically | Existing case identity, exact script/numkeys/KEYS, TTL/options, lanes and finite consumption |
| Script ARGV/time-key or INCRBY/EXPIRE chain | `redis.keys.<pattern>.commands` with ordered operations, optional `key_format` and scalar argument time formats | Script identity, numkeys, KEYS, stable ARGV, sequence closure and derived key relationships |
| PUBLISH UUID and JSON times | Global JSON identity and time formats; no publisher-specific rule | Channel, stable members, complete-value correspondence and atomic commit |
| Additional signed JWT nonce/expiry relationships, including URL-contained tokens | `api.<METHOD path>.response.json` or `headers` position referencing a named signature, with `query`, nonce/echo and companion contracts | Both signatures, stable claims/URL bytes, unique header/query values, exact signed lifetime and body expiry/issued-at/TTL |
| JWT token reused in several locations | Global `kind: jwt` with default/named root `signatures` profile; HMAC verification and global claim formats | Valid signatures, NumericDates, stable claims and complete Source-equal/Target-equal token correspondence |
| Encrypted JSON with random IV | `response_generated` / `encrypted_json` with declared envelope and effective startup key | Valid padding, plaintext structure and all unselected plaintext; ciphertext is not whole-field random |
| Generated URL/session fragments | Global `kind: url, formats: [url]` plus global decoded query-field formats; uncovered compound templates remain native | Fixed scheme/authority/path/query and identity equality |
| Current date in a header or DOCX field | `response_header_date` or `response_body` | Timezone, static filename/header/XML and other archive parts |
| Expired inbound JWT | `api` request header/query position referencing a named signature profile; preserve exact raw/Bearer scheme | Original signature, invalid-authentication cases and relative validity |
| Shared process initialization recorded in another case | `localcache.requests` with complete Source lifetime proof; HTTP host is required | Same-run immutable inventory, exact request identity and single consumption |
| Detached Source work appears unused in another case | `process_dependencies.tasks.<actual-Source-task-name>.requests` with Source task/lifetime proof; additional API-origin causality stays native | Original attribution, lane/transaction/identity boundaries and reversible classification |
| Missing Source acquisition or IP learned from a response | `capture_http`, `capture_breeze` or `capture_http_response` | Real new Recording and provenance of original/transformed response |

Relative naive timestamps cancel a shared UTC offset; prove consistent Source/Target
timezone behavior. `calendar_date` and absolute request windows retain explicit
offset requirements. Equal scalar sentinels compare exactly without a declared fallback.
For SSE, discovery locates observed data and terminal output; declare the
needed root-relative paths in the global JSON map. The same paths apply to
ordinary responses and storage payloads. Equal complete typed Source IDs remain
equal Target IDs internally; prefixes and scalar types are preserved. Unknown
delivered IDs remain input anchors. Missing events, changed text and event order
require Target diagnosis. See [SSE value contracts](../../../../../docs/sse-value-contracts.md).

When Source uses dependency reads, preserve that data flow. Ordinary declared
identity fields use mapped read delivery; native read-back updates are for extra
protocol/stateful behavior. Do not replace the read with a Target-local cache
solely to compensate for Replay delivery.
For SQL scalar fields, return the actual table/column and Source-proven table-family
bounds. Complete JSON needs only its global pointer; a new SQL statement needs
no new strategy. Only a contextual native relationship needs exact statement and
parameter/value selection. Ordinary JSON formats stay global and use independent
clocks. Declarative Redis command arguments infer equal Source instants internally
without authored clock groups. Additional native causal contracts retain their
explicit checks. Cache JSON needs no key declaration.
Equal fixed/external IDs, nulls and sentinels compare exactly; one-sided presence
and unrecognized differing values remain failures. Source behavior must justify
every declared format; random-looking bytes alone grant no identity permission.
Supported key formats/command sequences and GET/EXPIRE count permissions belong
under `redis.keys`. Multipart, DOCX, WSS path derivation, AES envelopes and actual
signature transformations retain their existing native typed effects.
For read/modify/write historical timestamps, preserve the delivered input: schema
fields use successful same-case physical-field/path read-copy provenance. Equal
Source/Target values pass directly; changed copied historical values still need
that provenance. Explicit native generation contracts retain their clock checks. Do not add SQL-specific exceptions or enable blanket read
delivery to compensate for a copied historical field.

Named root `signatures` profiles define algorithms and effective startup keys
for global JWT verification and explicit API rewriting. Diagnose verification
using the failed attempt's trusted clocks and key discovery, never
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

Return the proposed authored v2 declaration/rule document, complete Source
coverage of its global formats/lifetimes, current evidence ID, missing proof,
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
