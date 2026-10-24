# Unified Traffic Rules

Use one `traffic-policy/v2` policy for acquisition, classification, input
adaptation and all comparisons. Managed project configuration contains:

```yaml
project:
  policy: .traffic-e2e/policy.yaml
```

The path is relative to the target repository root. Initialization creates an
empty policy with `resources: {}`, `responses: {}` and `rules: []`; it supplies
no project-specific exceptions. Only `traffic-policy/v2` is accepted; former
version-numbered verification documents, v1 and separate Source policies reject.

## Discover, Plan, Apply

During a managed rewrite, load the backend-rewrite skill instead of operating
its state machine from this skill. Current evidence supplies a bounded rule
discovery query and capability metadata. Follow its returned command. Inspect
immutable Source code and the exact Source/Target witnesses before proposing a
rule; a mechanically explainable difference is not a semantic justification.

Follow discovery's `pagination.next_page.command` for omitted candidate/binding
summaries and `pagination.next_scan.command` for remaining observations. Counts
describe the current bounded scan window; Source bindings have separate
`binding_count` and `summary_omitted` fields. Explicit nonresumable limits remain
under `bounded_analysis.nonresumable_limits`. Missing drafts are not proof of a
missing capability, and supported mechanism hints never supply Source proof.

At the first relevant mismatch, inspect existing resource/response declarations
and request the physical field inventory with Source semantics. Choose time
format/relation, duration unit/branch, unordered consumer behavior or identity
eligibility before choosing a statement. MySQL database/table/column and Redis
key/container/hash-field paths own their field strategies across APIs and
supported SQL/command shapes. Response fields retain an API/output envelope.
Do not repeat the strategy by SQL template, value ordinal or caller.

For an identity, inventory all eligible MySQL/Redis/response positions together
with one case-local `binding` and a consistent format. Source observations define
the actual equality and distinctness relations; a generator-first capture is
unnecessary for ordinary field contracts. Plan this declaration inventory
together, rather than waiting for separate capture/reference Replay failures.
Unknown delivered IDs are fixed input anchors; established mappings deliver the
corresponding Target IDs. Mixed generated/fixed columns need expressible
eligibility, or their existing narrow native owner must remain. See
[identity domains](../../../../../docs/resource-field-contracts.md#identity-domains-and-read-delivery).

Draft discovery follows actual array structure: `/blocks/*/timestamp` covers
repeated elements across indexes and cases without guessing that numeric object
keys are arrays. Array time drafts use `clock_scope: array_element`. Candidate
IDs remain stable across witness cases/indexes; `bindings`, `binding_count` and
`bindings_omitted` expose bounded concrete witness pointers. These are sampled
observations, not complete coverage or Source permission: drafts retain empty
proofs and `plan_ready: false`, and differing IDs do not authorize identities.

Dependency value rules and native resource effects use resource scope without
`match.api`: the same resource access contract applies across APIs. Discovery and
planning omit API from new rules and validate complete cross-API Source coverage,
using each API's own Target witnesses and clocks where available. Missing Target
evidence requires genuine Replay; changed Source membership or foreign execution
invalidates the plan. Existing explicitly API-scoped rules retain their scope
when extended. API response assertions and inbound adaptations keep API scope.
`calendar_date` retains its required explicit `utc_offset`.

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

Authored documents are additive: omitted rules and resource/response declarations
stay in the policy. Declaration amendments preserve existing identity, proof and
fields; unsupported replacement or deletion rejects.
To consolidate existing owners, use an explicit change proposal with complete
replacement rules and their own Source proof:

```yaml
format: traffic-policy-change/v1
replace_rules: [old-a, old-b]
policy:
  format: traffic-policy/v2
  rules:
    - id: cache-write-clock
      surface: dependency.request
      match:
        resource: {protocol: redis, endpoint: 'cache.example:6379', database: 0}
        operation: SET
        key: {exact: task-cache}
      slot: value
      codec: json
      contract:
        /written_at: {relative_time: unix_seconds}
      proof:
        source: source/cache.py:write
        fact: Source writes this request-relative clock; all other values remain exact.
```

Only `replace_rules` IDs are replaced; unlisted rules remain. Each new rule still
needs complete Source/Target preflight. Existing primary response/input owners
cannot be removed across another API's issue. Whole-policy compare-and-swap,
durable intent, stale checks, recovery and fresh Replay obligations apply to the
same reviewed plan/apply transaction. This does not authorize arbitrary deletion
or a replacement without evidence.

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

Resource fields select physical data before an operation is known: MySQL
database/table/column, or Redis database/key/container/hash-field and decoded
path. Response declarations select API body or SSE data. These lower to the same
protocol slot/codec pipeline. Explicit MySQL `sql_field`, Redis `redis_value`,
HTTP `body`, Memcached `value` and contextual `sql_value`/`sql_column` slots have
capability gates. See [resource-field contracts](../../../../../docs/resource-field-contracts.md). A supported value slot uses the
same JSON/PB contracts; adding PB does not require another JSON-specific
protocol strategy. Unsupported operation/slot/codec combinations fail during
compilation rather than silently falling back.

SSE primary responses can select `slot: {sse_data: <exact-event-name>}` with
`codec: json`. For data-only streams, use
`slot: {sse_data: {event: message, json_type: response.completed}}` to select the
immutable Source JSON `/type`; Target types remain exact. Pointers address the decoded SSE data JSON; envelope, event order,
count and closure stay strict. Time contracts use the independent HTTP request
starts. Explicit `identity` fields share a case-local bijection by `binding`
across selected events and declared MySQL/Redis identity fields, preserving
declared prefixes and decimal/UUID or fixed lowercase hex types
(`format: {hex: 12}` for 12 hex characters).
Trace Source identity eligibility first; unknown historical dependency inputs
remain anchored. See [SSE value contracts](../../../../../docs/sse-value-contracts.md).

For a stable Redis JSON value, declare the carrier once:

```yaml
format: traffic-policy/v2
resources:
  cache:
    protocol: redis
    endpoint: cache.example:6379
    database: 0
    proof:
      source: src/cache.rs:write
      fact: The consumer treats members as a multiset; written_at uses this request clock.
    keys:
      - key: {exact: task-cache}
        container: string
        value:
          codec: json
          fields:
            /members: unordered
            /written_at: {relative_time: unix_milliseconds}
responses: {}
rules: []
```

For PB replace only the codec declaration with explicit typed bindings, for
example `codec: {kind: protobuf, fields: {/written_at: {field_path: [1],
field_type: int64}, /members: {field_path: [2], field_type: string, repeated: true}}}`.
Each selected path must have a known type. PB unknown fields, presence,
repeated order and unselected encoded fields remain protected. A codec schema
is not permission to change every declared field.

## Exact Remainder And Time

Resource/response subtrees and contextual rules carry Source proof. Declare
stable physical field strategies once; contextual native contracts may reuse
them through typed `field_ref` references. Plans expose the resolved permissions
and authored graph. A named resource removes identity duplication but does not
create shared exchanges, cached validation results or business equivalence.

Write `fact` as the causal conclusion in at most 200 UTF-8 bytes, not a replay
diary; never truncate existing proof mechanically. The renderer uses at most two
content lines. Keep at most three file references in `source`, using a list for
multiple files and grouping locations from each file in one entry. The root
`capture_http` proof can omit `source` because capture paths grant no comparison
permission; it still needs `fact` and an immutable revision. Other permissions
retain Source references. Serialization places capture-path rules first and
preserves other rules' authored relative order.

For human authoring, a document-level `source_revision` can bind the common
Source identity. Nested contracts inherit the nearest proof inside their own
rule or resource/response declaration subtree; supply a local proof only for
different facts or Source references. Partial
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
Source-present selected JSON/PB fields require corresponding Target presence and
type. Missing Source selections and empty Source arrays keep their shape exact;
they do not authorize Target additions. A present JSON null still needs a valid
explicit contract or an inactive exact branch.

Time contracts declare format and relation; request ownership fixes the clock. Unix seconds, milliseconds
and microseconds preserve integer precision; formatted times require their
explicit offset when necessary. Source and Target use independent clocks.
Request windows use the fixed engine boundary; preserve-offset comparisons
also check cross-field differences and declared clock groups. Do not invent an
offset, tolerance or a payload-derived clock to make a mismatch disappear.

Use `clock_scope: array_element` for Source-proven independent reads in repeated
elements, for example `/blocks/*/timestamp: {relative_time: unix_milliseconds,
clock_scope: array_element}`. Actual nested array ancestry scopes each element;
numeric object keys stay literal. The default `shared` retains existing group
relationships for explicit ordinary rules. Resource/response schema fields
without an authored group get independent per-field/path defaults; wildcard
paths separate each actual selected leaf, and repeated SQL occurrences are
independent too. Copies derived from one read keep one authored
`clock_group`. For explicit ordinary/native rules, separate reads within an
element require separate groups and Source proof; schema defaults already
separate fields and wildcard occurrences. Neither
scope nor group selects another request anchor.

For a clock repeated across SSE frames, declare an explicit identity for its
Source-owned entity, then use `clock_scope: {binding: text-block,
relative_pointer: ../id}` on the timestamp. The same SSE selector must contain a
matching sibling identity contract with that binding and its proven prefix and
format. This preserves each entity's copies without equating independent blocks;
it never infers identity permissions from a difference.

Comparing a dependency response does not authorize rewriting it. Only explicit
`delivery: {rebase_time: [/path]}` materializes declared response time fields.
The writer revalidates the complete delivered payload and preserves unrelated
bytes, native metadata and finite consumption.

Resource-owned time fields also retain bounded, case-local provenance from a
successful dependency read to the value actually delivered. A later write can
copy that historical timestamp only at the same physical field and logical path;
it cannot rely on equal old values without that read. Explicit native generation
clocks remain strict. Keep the Source read/modify/write flow instead of listing
its SQL variants or rebasing all reads. The [resource field guide](../../../../../docs/resource-field-contracts.md#time-conditions-and-delivery)
describes mapping ambiguity, typed timestamp equality, bounds and delivery order.

For Source business branches based on `date.today()` and stored `YYYY-MM-DD`
state, use a value codec field such as
`/spec/lastActiveDate: {relative_time: calendar_date, utc_offset: '+08:00'}`.
Prove the deployment's fixed local offset. This preserves the exact signed day
distance from each corresponding dependency request's local date; it does not
round elapsed seconds to days. `request_time: calendar_date` requires the local
request date itself. Both require independent clocks and a canonical date;
`clock_group` is unsupported because a civil-day relation differs from an
instant shift. Native time adapters require a value codec rule for this format.
An explicit dependency-response `delivery.rebase_time` field is needed to
translate read state before the Target evaluates its business branch. Declare
the corresponding request output date contract separately. Keep streaks,
experience, totals, row identity and all other business fields strict; never
normalize their downstream differences as time or generated values.

MySQL resource fields select physical database/table/column plus an explicit
scalar or JSON/PB codec. They cover supported direct writes, predicates and
result origins across new SQL shapes; no `match.sql` is required. Discovery
reports bounded `physical_fields` suggestions without raw SQL or values. Missing
or ambiguous origins never grant permission. A table family still needs Source
construction proof; do not infer a family from observed numeric suffixes.

Native contextual effects may retain `match.sql` and `{{table}}` with explicit
`tables`, bounded `table_patterns` or `table_series`. Preserve the actual shard,
aliases, predicates and row identity. At supported native contract sites,
`field_ref` reuses a declared strategy while a proven `clock_group` adds the
statement's relation; do not duplicate the strategy per observed SQL. Refer to
the [resource-field guide](../../../../../docs/resource-field-contracts.md) for
references, supported expressions and old-recording origin fallback.

Use the existing conditional value contract for nullable branch-specific clocks,
for example `/status/completedAt: {kind: conditional, when: {relative_pointer:
../status, equals: COMPLETED}, contract: {relative_time: iso8601_naive,
clock_group: completed}}`. The Source predicate selects the time comparison;
inactive values, including `null`, stay exact. Other JSON members and native SQL
arguments retain their contracts. Explicit ordinary/native contracts need
separate groups for independent Source clock reads; schema defaults already
separate them. A completion field is not an unrestricted nullable timestamp.

A scalar sentinel can use `when: {relative_pointer: '.', not_in:
['1970-01-01 00:00:00']}` around its time contract. The inactive Source value
stays exact and Target must remain in the same branch. For a nullable scalar,
include `null` in `not_in` as well; an active time contract rejects a present
null rather than skipping it.

A Source sibling may condition an individual value contract with
`kind: conditional`, `when: {relative_pointer: ../type, equals: text}` and an
inner `contract`. Native Redis identity captures accept the same predicate under
`effect.capture.when`; inactive captures create no binding, while later reference
operations use existing bindings. Predicates are Source-only and Target siblings
stay exact. See [conditional field contracts](../../../../../docs/conditional-field-contracts.md).

## Stateful And Source Effects

`redis_append_stream` grants Source-proven APPEND chunk-boundary equivalence only
under an explicit resource/database/key scope. Literal byte order, reads,
resets, expiry calls and finite consumption remain checked; APPEND responses
reflect actual Target cumulative lengths. See [APPEND streams](../../../../../docs/redis-append-stream.md).

`redis_read_commutation` permits explicitly scoped finite nil GET observations
to cross unrelated commands only after complete Source key validation. It
preserves each read's count and delivery; extra or missing reads still fail.
Use it for proven independent polling, never to suppress a cancellation value
or repair missing business reads. See [finite read commutation](../../../../../docs/redis-read-commutation.md).

Ordinary identity fields relate several values through their shared binding.
Use a typed native owner for additional protocol, contextual or stateful behavior:

- `identity`: narrow capture/reference rules, embedded copies and derivation
  beyond ordinary physical identity fields;
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

For extra native behavior involving an identity read back from MySQL JSON, append
`effect.mysql_read_back` to the existing `identity` rule with its own Source
proof. Select an already declared reference resource, complete SELECT/table
scope, physical result column and JSON pointers (array `*` is supported).
The engine delivers only previously captured, same-Case Target identities;
each pointer needs a positive Source read after capture. Other values stay
strict, and fresh Replay is required. See
[MySQL identity read-back](../../../../../docs/mysql-identity-read-back.md).

Process ownership does not prove target initialization or cache behavior.
Finite sharing does not authorize unused work, reusable snapshots, unrelated
connections or arbitrary response reuse. Protocol adapters retain framing,
authentication, lanes, request correlation, claims and consumption.
