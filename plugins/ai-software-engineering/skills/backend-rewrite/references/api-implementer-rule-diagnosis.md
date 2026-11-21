# Rule Diagnosis

Read this after tracing Source and Target behavior. The authored
`traffic-policy/v3` document lives at `project.policy`. Workers return Source
conclusions and a proposed declaration/rule document; the coordinator plans/applies it.
Follow the [shared rule evidence contract](rule-policy.md) for API-driven hints,
evidence, additive proposals, explicit replacement and verification boundaries. The complete technical
contracts are in [unified rule contracts](../../../../../docs/unified-rule-contracts.md).

## Rule Discovery From Source Diagnosis

Use returned `rule_hints`, mechanical candidates, declared capability requirements
and the current evidence ID. A candidate establishes a possible mechanism, not
business permission. At the first relevant mismatch, inspect existing declarations
and `source_entry.locations`, even when `candidates` is empty. Return the smallest
Source-proven scope, exact field and
encoding, Source file/symbol, and a fact explaining the allowed relationship.
An absent candidate does not mean the capability is unavailable. Ask for missing
schema or clock evidence rather than guessing from field names or values.
Drafts are proof-required additive directions. Submit the new fields or formats;
existing declarations and format order are preserved with exact duplicates removed.
Use an explicit replacement proposal only for an intended change or removal, as
described in the [shared contract](rule-policy.md).

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
| Source buffers ordered text into APPEND batches whose boundaries vary with scheduling | `redis.keys.<bounded-pattern>.state.append: concatenate`; see [schema](../../../../../docs/redis-append-stream.md) | Literal byte order, read/reset boundaries, correct returned lengths, exact finite expiry/other calls, successful delivery and Case ownership |
| APPEND bytes match, but a changed batch count adds current-identity GETs or fixed-TTL EXPIREs | `redis.keys` `state.get: observe` (plus identity `read_back: true` for value mapping) or `state.expire: refresh`; see [state observations](../../../../../docs/redis-state-observations.md) | Follow the earliest Target admission index; preserve SET/DEL lifetimes, complete-value identity correspondence and exact TTL. Do not infer missing key translation from a later MGET mismatch caused by an earlier rejected batch |
| A Source loop polls nil 0..N times or a debounce flush changes body counts | Inspect the `redis_loop_state` candidate; prove each key's effects, then use `state.get: {transient: [nil]}`, `state.append: concatenate`, `state.expire: refresh` or metadata `state.set: {reduce: last, fields: [...]}`; see [state contracts](../../../../../docs/redis-state-contracts.md) | Non-nil observations, real SET/DEL, complete bytes and unrelated business side effects remain required; omitted nil reads are audited separately from physical consumption |
| Generated scalar Redis token and later script ARGV | `redis.keys` identity format; known complete values propagate automatically | Existing case identity, exact script/numkeys/KEYS, TTL/options, lanes and finite consumption |
| Script ARGV/time-key or INCRBY/EXPIRE chain | `redis.keys.<pattern>.commands` with ordered operations, optional `key_format` and scalar argument time formats | Script identity, numkeys, KEYS, stable ARGV, sequence closure and derived key relationships |
| PUBLISH UUID and JSON times | Global JSON identity and time formats; no publisher-specific rule | Channel, stable members, complete-value correspondence and atomic commit |
| Additional signed JWT nonce/expiry relationships, including URL-contained tokens | `api.<METHOD path>.response.json` or `headers` position referencing a named signature, with `query`, nonce/echo and companion contracts | Both signatures, stable claims/URL bytes, unique header/query values, exact signed lifetime and body expiry/issued-at/TTL |
| JWT token reused in several locations | Global `kind: jwt` with default/named root `signatures` profile; HMAC verification and global claim formats | Valid signatures, NumericDates, stable claims and complete Source-equal/Target-equal token correspondence |
| Source-proven encoded JSON with a random IV | Return the API decode location, Source encoding and effective key provenance; plaintext uses the global JSON formats. Consult [carrier bindings](../../../../../docs/content-policy-layout.md) | Valid padding, plaintext structure and all unselected plaintext; ciphertext is not whole-field random |
| Source-proven generated URL/session fragments | Use a global string template for compound literal/identity content, or the ordinary URL format for query-only content; consult [content formats](../../../../../docs/content-policy-layout.md) | Fixed scheme/authority/path/query, complete identity values and equality |
| Source-proven generated storage path reused by HTTP and SQL | Return the physical outbound request position and its cross-resource use under `http.requests`; consult [generated paths](../../../../../docs/content-policy-layout.md) | API scope where present, exact business fragments and resource permissions |
| Current date in a header or DOCX field | Inspect the typed candidates, prove Source generation, and keep the API header/codec position; DOCX fields are shared. Consult [carrier bindings](../../../../../docs/content-policy-layout.md) | Request-date relation, static filename/header/XML and other archive parts |
| Only the outer boundary differs in a complete supported multipart request | The engine already compares ordered parts; no boundary policy is required. Diagnose any remaining part/header/content mismatch | Ordered parts, filenames, part headers, payloads and ordinary finite calls |
| Expired inbound JWT | `api` request header/query position referencing a named signature profile; preserve exact raw/Bearer scheme | Original signature, invalid-authentication cases and relative validity |
| Shared process initialization recorded in another case | `localcache.requests` with complete Source lifetime proof; HTTP host is required | Same-run immutable inventory, exact request identity and single consumption |
| Detached Source work appears unused in another case | `process_dependencies.tasks.<actual-Source-task-name>.requests` with Source task/lifetime proof; additional API-origin causality stays native | Original attribution, lane/transaction/identity boundaries and reversible classification |
| Missing Source acquisition or IP learned from a response | Follow the returned Source-acquisition route; learned-response URL positions use `http.response_rewrite` with the original capture identity | Real new Recording and provenance of original/transformed response |

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
under `redis.keys`. Use the [content and carrier guide](../../../../../docs/content-policy-layout.md)
only when Source calls for a template, codec binding or generated header strategy.
Complete supported multipart boundaries are handled by the engine and need no rule.
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
follows the returned planner and legal actions under the [shared contract](rule-policy.md).

Return the proposed authored v2 declaration/rule document, complete Source
coverage of its global formats/lifetimes, current evidence ID, missing proof,
and residual differences. Do not execute apply or Replay as an implementer.
The engine's plan and subsequent actions own complete coverage, stale checks,
application, recovery and genuine verification. Do not recreate those decisions
from a worker report or edit workflow state.

Memcached `SET` exptime retains native protocol comparison: relative TTL and zero
stay exact, absolute expirations compare remaining TTL within the fixed engine
window. A value codec rule does not change exptime/CAS/noreply behavior.

## Foreign Dependencies And Batched Hypotheses

For ownership or hypothesis diagnosis, use
`dependency-attribution show --api <route>` on passing and failing attempts.
The full detail preserves every attempted time/identity
hypothesis, including rejected probes, and groups actionable Source questions
without treating a successful speculative match as proof. Prove value rules
for your API and return one combined proposal after the completed diagnostic
attempt. Exact request matching and finite occurrences remain mandatory.

For unused Source occurrences, submit your API's concrete exclusion evidence
with `dependency-attribution claim --file <foreign-unused.json>`. This is a
claim for independent repository analysis, not permission to ignore a call. You
do not need to search every other API. For unmatched requests, use the real
protected `target_observation_id` and `dependency-attribution investigate`; do
not invent a Source UUID or infer async behavior from a missing candidate.
The repository analyst owns process-task and foreign-API attribution. Return
its independent work to the coordinator; do not apply ownership or acceptance.
