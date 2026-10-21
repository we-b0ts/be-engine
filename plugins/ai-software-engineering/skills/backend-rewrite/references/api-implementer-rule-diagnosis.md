# Rule Diagnosis

Read this after tracing Source and Target behavior. Rules are self-contained
`traffic-policy/v1` records in the file named by `project.policy`. Workers return
Source conclusions and a proposed record; the coordinator plans/applies it.
The complete schema, examples and lifecycle are in
[unified rule contracts](../../../../../docs/unified-rule-contracts.md).

## Rule Discovery From Source Diagnosis

Use `facts.rule_guidance`, mechanical candidates, declared capability requirements
and the current evidence ID. A candidate establishes a possible mechanism, not
business permission. Return the smallest Source-proven scope, exact field and
encoding, Source file/symbol, and a fact explaining the allowed relationship.
An absent candidate does not mean the capability is unavailable. Ask for missing
schema or clock evidence rather than guessing from field names or values.

Use one proposal for one complete rule by default. Keep its resource, codec,
contracts and proof inline. The same `time` or `unordered` contract works on
supported JSON and Protobuf slots; selecting an encoding grants no permission
on other endpoints, operations or surfaces.

| Evidence and Source fact | Proposed contract/effect | Preserve |
| --- | --- | --- |
| An unordered Set becomes a JSON array or repeated PB field | `contract: {<logical-path>: {kind: unordered}}`; PB declares field numbers/types explicitly | Multiplicity, membership, element associations, presence, unknown PB fields and remainder |
| A generated timestamp or expiry | `kind: time`, explicit format, relation and trusted anchor | Units, microseconds, TTL offset, copied instants and clock groups |
| SDK runtime headers differ, and Source consumer/middleware do not read them | Explicit API/endpoint/method/path-scoped `http_client_metadata` with exact supported names; [schema](../../../../../docs/http-client-metadata.md) | Business/authentication headers, body/query, finite requests and delivery. `protected: false` concerns confidentiality; it does not make a mismatch nonblocking |
| SSE data contains a generated timestamp | `api.response`, exact `slot.sse_data` event/type, JSON pointer and Source-proven request-time relation | Event presence/order, envelope, unselected fields and terminal state |
| Source generates one fresh SSE identity and references it across frames | Explicit JSON `kind: identity`, proven prefix/format and the same `binding` at every reference | Bijection, Case lifetime, exact prefixes, terminal output references and dependency-owned identities |
| Live elapsed duration that stops at terminal state | Source sibling `conditional` around `duration` | Terminal values and status stay exact; missing/wrong-type status rejects |
| Expired recorded Redis/MySQL input | Explicit `dependency.response` time contract plus selected `delivery.rebase_time`, or typed SQL response effect | Raw Source bytes, sentinel values, protocol outcomes, finite inventory and signature dependencies |
| Identity captured in SQL/Redis/HTTP and reused later | `effect.kind: identity` with capture, shape/lifetime and exact allowed reference resources | Bijection, case scope and atomic candidate decisions |
| Redis reads back a generated ID or preserved timestamp after writing it | Add explicit `effect.read_back` to the existing `identity` / `redis_sequence` rule; see [schema](../../../../../docs/redis-read-back.md) | Successful matched write, same key/Case/resource, original Source causality, selected fields, finite reads and fresh Replay |
| LSET updates a JSON list element | JSON fields select `redis_sequence.commands[].arguments.2`; a Source-generated identity can capture Redis argument 2; see [schema](../../../../../docs/redis-generated-requests.md#lset-list-element-updates) | Exact list index, existing identity references for preserved IDs, strict remainder, three arguments and finite writes |
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

For timezone-free timestamps, prove the fixed UTC offset from Source deployment.
For SSE, follow the `unified_value_contract` hint to discovery and inspect
`source_entry.bindings` even when `candidates` is empty. Discovery prioritizes
primary responses for response issues but remains bounded; it never infers
identity permission. `slot: {sse_data: {event: message, json_type: <Source-type>}}`
selects the decoded data JSON in data-only streams. Trace each Source generator
and every reference, including IDs in terminal output; use a shared binding only
for the same entity. IDs fixed by Replay dependencies must retain their existing
ownership. Missing events, changed text and event order require Target diagnosis.
See [SSE value contracts](../../../../../docs/sse-value-contracts.md).

When Source uses Redis GET/LRANGE results, preserve that data flow. Return a
read-back rule update and write/read proof if Replay returns recorded Source
identities; do not replace the Redis read with a Target-local cache solely to
compensate for that delivery difference.
Different `clock_group` names require independent Source clock reads; omission
retains rigid copy/precision checks. For SQL, return the exact SQL template,
physical table bounds, parameter/value indices, database and authentication
identity. HGET response rules select the hash field separately from the key.

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

Return the proposed self-contained record, current evidence ID, missing proof,
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
