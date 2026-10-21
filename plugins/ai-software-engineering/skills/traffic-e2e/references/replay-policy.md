# Unified Traffic Rules

Use one `traffic-policy/v1` policy for acquisition, classification, input
adaptation and all comparisons. Managed project configuration contains:

```yaml
project:
  policy: .traffic-e2e/policy.yaml
```

The path is relative to the target repository root. Initialization creates an
empty policy; it supplies no project-specific exceptions. Old version-1/2/3
verification documents and the separate Source policy format are rejected.

## Discover, Plan, Apply

During a managed rewrite, load the backend-rewrite skill instead of operating
its state machine from this skill. Current evidence supplies a bounded rule
discovery query and capability metadata. Follow its returned command. Inspect
immutable Source code and the exact Source/Target witnesses before proposing a
rule; a mechanically explainable difference is not a semantic justification.

The coordinator accepts one rule, a list, or a complete typed document:

```bash
backend-rewrite --target-root <target> rule plan \
  --file /tmp/proposed-rules.yaml --evidence <current-evidence-id>
backend-rewrite --target-root <target> rule apply <plan-id>
```

The plan expands every selected rule, validates its whole affected payload and
reports remaining Replay, reclassification and recording obligations. Reuse the
same pending plan after an interruption; `rule recover <plan-id>` resolves an
interrupted transaction through the coordinator. Do not edit a managed policy
or recording to bypass this transaction.

Standalone traffic operations can load the same reviewed document with
`traffic-e2e replay --policy <path> <case-source>` or `record --policy <path>`.
Recording consumes only Source effects. With a project config, `--policy` must
name that project's policy and cannot override its authority.

## Three Comparison Surfaces

| Surface | Evidence and responsibility |
| --- | --- |
| `api.response` | Complete recorded and independently observed API responses |
| `dependency.request` | Complete recorded request and real Target client request |
| `dependency.response` | Complete recorded result and its explicit Replay delivery; materialization and verification remain separate |

Rules select a protocol-owned slot and then a codec. Redis SET and Memcached
SET `value`, GET/GETS response `value`, HTTP `body`, MySQL `sql_value` and
`sql_column` have explicit capability gates. A supported value slot uses the
same JSON/PB contracts; adding PB does not require another JSON-specific
protocol strategy. Unsupported operation/slot/codec combinations fail during
compilation rather than silently falling back.

SSE primary responses can select `slot: {sse_data: <exact-event-name>}` with
`codec: json`. For data-only streams, use
`slot: {sse_data: {event: message, json_type: response.completed}}` to select the
immutable Source JSON `/type`; Target types remain exact. Pointers address the decoded SSE data JSON; envelope, event order,
count and closure stay strict. Time contracts use the independent HTTP request
starts. Explicit `identity` fields share a case-local bijection by `binding`
across selected events, preserving declared prefixes and decimal/UUID or fixed lowercase hex types
(`format: {hex: 12}` for 12 hex characters).
Trace Source identity ownership first: DB-derived IDs fixed by Replay must stay
exact. See [SSE value contracts](../../../../../docs/sse-value-contracts.md).

A self-contained Redis JSON rule is:

```yaml
id: cache-members
surface: dependency.request
match:
  api: POST /tasks
  resource: {protocol: redis, endpoint: 'cache.example:6379', database: 0}
  operation: SET
  key: {kind: exact, value: task-cache}
slot: value
codec: json
contract:
  /members: {kind: unordered}
  /written_at:
    kind: time
    format: unix_milliseconds
    relation: preserve_offset
proof:
  source: src/cache.rs:write
  fact: The consumer treats members as a multiset; written_at comes from this request's clock.
```

For PB replace only the codec declaration with explicit typed bindings, for
example `codec: {kind: protobuf, fields: {/written_at: {field_path: [1],
field_type: int64}, /members: {field_path: [2], field_type: string, repeated: true}}}`.
Each selected path must have a known type. PB unknown fields, presence,
repeated order and unselected encoded fields remain protected. A codec schema
is not permission to change every declared field.

## Exact Remainder And Time

Every rule carries its own inline `proof: {source, fact}`. Default to inline
resources, codec bindings and contracts. The current format keeps these definitions inline; plans expose their complete
content without requiring an AI to traverse configuration references.

For human authoring, a document-level `source_revision` can bind the common
Source identity. Nested contracts inherit the nearest proof inside their own
rule; supply a local proof only for different facts or Source references. Partial
local proof overrides are allowed; blank source/fact values and null proofs
reject. Proof never inherits across rules. Complete `contract`/`proof` pairs
remain supported.
`relative_time: unix_microseconds` abbreviates typed `preserve_offset` time;
`request_time: rfc3339` abbreviates `request_window`. Neither accepts `anchor`.
Dependency rules always use that physical dependency's Source/Target request
starts; API response rules use their own HTTP request starts. Missing clocks
fail closed. Declare a clock group when the Source contract requires one.
`unordered` abbreviates `{kind: unordered}`. Keep complex constraints explicit.
The engine expands all these forms into complete typed rules, proofs and Source
identities in plan/evidence, with the same effective fingerprints and gates.

Unselected fields and native protocol envelope stay strict. Unordered arrays
preserve elements, types and duplicate counts. JSON null is a present value;
a protocol miss, null bulk response or quiet no-response is an unavailable slot
and retains its original outcome without counting as a successful rule match.
Missing selected JSON/PB fields or a changed type in an available payload fail.

Time contracts declare format and relation; request ownership fixes the clock. Unix seconds, milliseconds
and microseconds preserve integer precision; formatted times require their
explicit offset when necessary. Source and Target use independent clocks.
Request windows use the fixed engine boundary; preserve-offset comparisons
also check cross-field differences and declared clock groups. Do not invent an
offset, tolerance or a payload-derived clock to make a mismatch disappear.

Comparing a dependency response does not authorize rewriting it. Only explicit
`delivery: {rebase_time: [/path]}` materializes declared response time fields.
The writer revalidates the complete delivered payload and preserves unrelated
bytes, native metadata and finite consumption.

## Stateful And Source Effects

Use the typed native owner when a contract involves more than one value:

- `identity`: capture and later references with explicit resource scopes;
- `redis_sequence`, `redis_lock`, `redis_publish_identity`: atomic steps,
  successful acquisition/reference causality and nonce identity;
- `http_request`, `mysql_values`: native query/header/multipart or SQL
  parameters, typed values and physical result time columns;
- `input_jwt`, `response_jwt`, `response_generated`, `response_body` and
  `response_header_date`: their dedicated execution or assertion owner;
- `input_signed_timestamp`: source-verified sorted-field MD5 JSON timestamp
  rebasing with a frozen startup signing input; see
  [signed timestamp request rules](../../../../../docs/signed-timestamp-request-rules.md);
- `capture_http`, `capture_breeze`, `capture_http_response`, `process_owned`
  and `finite_sharing`: acquisition, classification and finite sharing.

Follow discovered capability metadata for the exact effect schema. Nested
bindings, fields and selectors retain their own resolved Source proof, whether
locally inherited or explicitly supplied by the author.
Source self-validation exercises complete traces in isolated state. It cannot
replace independent Target evidence; successful planning can still require
fresh Replay. Startup signing inputs are frozen by actual resolved file hash,
without copying secret values into a plan.

Process ownership does not prove target initialization or cache behavior.
Finite sharing does not authorize unused work, reusable snapshots, unrelated
connections or arbitrary response reuse. Protocol adapters retain framing,
authentication, lanes, request correlation, claims and consumption.
