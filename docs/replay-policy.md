# Dependency Replay And Response Verification Policy

Each target repository owns one source-controlled
`.traffic-e2e/verification.yaml`. Pass it explicitly to every recorded replay
and comparison verification:

```bash
traffic-e2e config init --source-pod <pod> --namespace <namespace>
traffic-e2e replay --policy .traffic-e2e/verification.yaml /path/to/case-group
```

Initialization, evidence-driven application, and replay each validate the
policy.

This policy is independent of recorder `case_path_patterns`:

- `case_path_patterns` groups recorded inbound API paths.
- verification policy matches legitimate runtime-generated dependency fields
  and owns reviewed response-comparison rules.

## Required Contract

Every policy starts with:

```yaml
version: 1
expected_response: assertions_only
dependency_rules: []
```

Version three enables runner-owned response assertions:

```yaml
version: 3
expected_response: assertions_only
dependency_rules: []
response_settings:
  comparison:
    source_match: before
response_rules:
  json: {}
  protobuf: {}
  hessian2: {}
  docx: {}
```

Rules are grouped by body codec, canonical API, and concrete rule kind.
Standard replay loads JSON `timestamp`, `duration`, `uuid`, `random`, and
`unordered` rules plus configured protobuf, Hessian2, and DOCX rules. Comparison also
loads JSON `counter` rules. Rule kinds selecting JSON must use disjoint
subtrees.

`response_settings.comparison.source_match` controls which complete source
observation may serve as the comparison oracle. `before` is the default. Set
`before_or_after` only for runs that record `expected-response-after.json` for
every case. The candidate must match either complete source response under the
active response rules; fields from the two source observations are never
combined. Standard replay ignores this comparison-only setting.

`expected-response.json` is an assertion oracle only. Target product code,
dependency mocks, E2E setup, and verification policy generation must not read its
status, headers, or body to create the actual response, dependency result,
branch decision, cache result, or side effect. The policy parser requires this
declaration; migration review must also verify the target harness obeys it.

The same version 3 `response_rules` also apply to offline comparison recording
verification. `traffic-e2e compare <comparison-recording-run> --policy
<verification.yaml>` treats the baseline `expected-response.json` as the
oracle and the candidate `response.json` as actual output. When
`expected-response-after.json` exists, it also checks source-before against
source-after. With `source_match: before_or_after`, a complete candidate match
against source-after also passes and is recorded as `matched_source: after`.
When the candidate matches neither observation, a source change makes only
candidate differences at the same response location inconclusive; unrelated
candidate differences remain target differences. Replay dependency rules are
ignored during this file-only operation, and no interception or isolation is
enabled.

Do not put recorded values, response bodies, secrets, absolute case paths, or
case-id exceptions in the policy. Use selectors and semantic validation only.
In particular, ordinary mutable business data observed at different times is
not a generated-scalar exemption. Re-record it under comparable state. Add a
response rule only after source semantics prove current-time/random generation
or order-insensitive collection behavior.

## Rule Scope

The coordinator exposes exactly two rule classes:

- `backend-rewrite rule plan|apply` changes response verification semantics.
- `backend-rewrite dependency-rule plan|apply` changes dependency replay semantics.

The policy mirrors that split with the top-level `response_rules` and
`dependency_rules` keys. The former generic `rules` key is intentionally
rejected; this fast-iteration contract has no compatibility alias.

HTTP and Motan are gateway protocols, not rule classes. JSON, protobuf,
Hessian2, and exact bytes describe response-body codecs; a response rule may
combine either gateway with any supported body codec. Dependency-rule
subcommands use protocol names only to select the recorded dependency wire
contract.

Dependency rules select one operation by protocol and a narrow dependency
identity. HTTP rules require a target host, dependency method and dependency
path. MySQL rules require a SQL pattern plus at least one target host, database,
or username. Memcached timestamp rules require a supported resource kind,
`set`, and a bounded numeric key shape. The recorded exchange remains strictly
identified by target domain plus port. A `cache_service` resource uses protocol
plus port only to select the applicable policy rule; it neither accepts nor
exposes a cache namespace or deployment group. Reuse one unscoped rule for the
same dependency operation instead of copying it for every inbound API.

`case` is optional. Add it only when the same dependency operation has
different dynamic-field semantics in different request contexts and a narrower
dependency selector cannot distinguish them. Bindings remain isolated by
active case for both scoped and unscoped rules.

Case paths, when present, and HTTP dependency paths use segment-aware patterns:
`*` stays inside one segment and `**` crosses segments. SQL patterns are
normalized for whitespace, case, and backticks; `*` and `?` are wildcards.
Multiple rules may match one dependency only when they select disjoint dynamic
fields.

## Dynamic Fields

Version one supports scalar MySQL parameters, single-occurrence HTTP query
parameters, and the narrowly defined Memcached protobuf timestamp fields below:

- `bind`: capture the actual runtime value in the current case.
- `ref`: require the actual value to equal a value bound earlier in that case.
- `validate: uuid`, `uuid_v4`, or `non_empty`: validate shape without comparing
  the recorded literal.
- `time`: require a timestamp relative to `replay_now`, with an offset and
  tolerance.

Example:

```yaml
version: 1
expected_response: assertions_only
dependency_rules:
  - id: audit-insert
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "INSERT INTO request_log_* (uuid, request_time) VALUES (?, ?)"
      params:
        0:
          bind: audit_id
          validate: uuid_v4
        1:
          time:
            relative_to: replay_now
            tolerance: 2s
            format: "%Y-%m-%d %H:%M:%S"
            timezone: "+08:00"

  - id: audit-update
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "UPDATE request_log_* SET response_status=? WHERE uuid=?"
      params:
        1:
          ref: audit_id

  # Optional context-specific field composed with the unscoped update rule.
  - id: resource-token-audit-response
    case:
      method: GET
      path: /api/resource/token
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "UPDATE request_log_* SET response_status=? WHERE uuid=?"
      params:
        0:
          validate: non_empty
```

Durations accept integer `ms`, `s`, `m`, `h`, and `d` units. A time value may
be RFC 3339, Unix seconds, or use an explicit Chrono format and numeric
`+HH:MM`/`-HH:MM` timezone.

Memcached `set` rules may select top-level protobuf varint fields that source
code proves contain the current Unix time in seconds:

```yaml
dependency_rules:
  - id: user-info-cache-writeback
    protocol: memcached
    memcached:
      resource:
        kind: cache_service
        port: 11211
      command: set
      key:
        prefix: u
        suffix: ''
      protobuf:
        timestamp_fields:
          50:
            mechanism: unix_seconds
            source_evidence: UserInfoServiceBase.java:438 loads the current time
```

The key selector requires a nonempty ASCII-digit middle between its byte-exact
prefix and suffix. The resource, command, key, flags, byte length, CAS,
quiet/noreply mode, and every protobuf field not selected by the rule remain
exact. Target host is deliberately not a policy-rule selector; it is already
enforced by recorded-exchange matching. Only `kind: cache_service` is
supported. `kind: breeze` is rejected until traffic evidence requires its
namespace-based, dynamic-port contract. Each selected field must occur exactly
once with protobuf wire type varint. Protobuf groups are unsupported and fail
closed.

The engine owns a fixed, symmetric five-second window. It validates the
recorded field against that exchange's recorded `SET` timestamp and validates
the target field against the time Replay observes the target `SET`. The two
field values are never compared to each other, so recording-to-Replay delay is
irrelevant. The policy contains only field identity, mechanism, and one-line
source evidence; it never stores or reports either timestamp literal. Missing,
repeated, malformed, or out-of-window fields remain mismatches. The five-second
window is intentionally not configurable by the rule author.

Memcached `SET` expiration uses protocol-owned matching and does not require a
rule. Equal values match first. `0` and relative expirations through 30 days
must otherwise remain exact. When both values are absolute Unix timestamps,
Replay compares each expiration with that same `SET` exchange's observed time;
the two remaining TTLs may differ by at most five seconds. A relative value
never matches an absolute value. Text protocol arguments and binary protocol
extras use the same behavior; every non-expiration component remains exact.

## Evidence And Failure

Replay reports include the canonical policy path, content fingerprint,
`assertions_only` declaration, rule applicability, match counts, field
operation counts, and unused applicable rules. An applicable rule with zero
matches is dirty evidence and fails `end`, `finalize --fail-on-dirty`, and
aggregate dirty checks. A rule is applicable only when a selected case-owned
recorded dependency exchange matches its stable dependency selectors and its
optional `case` selector. Selecting an inbound API alone and matching bootstrap
evidence do not make a dependency rule applicable.

A query field cannot be both policy-managed and passed through the global
`--http-ignore-query-param` option. Replay rejects that configuration at
startup.

Version three supports exact scalar JSON response locations whose runtime value
is intentionally generated from a source-proven mechanism. Use the concrete
mechanism as the rule-kind key:

```yaml
response_rules:
  json:
    "GET /api/resource/token":
      uuid:
        - pointer: /content
          source_evidence: src/token.rs:issue_token UUID generation
          source_example: <redacted source UUID>
          target_example: <redacted target UUID>
```

The field must exist in both responses and keep the same scalar JSON kind.
When both responses omit it, the rule does not participate and creates no
coverage requirement; a one-sided omission remains an exact structural
difference. UUID/random skip literal equality; timestamp/duration instead
validate the time relationship below. Status, structure, other fields, and
non-JSON bodies stay exact. Every generated field persists a single-line
source citation and distinct redacted source/target examples in the policy.
These audit fields do not prove the business generation mechanism; verify it
through source review, unit tests, or real-traffic integration tests.

JSON response Pointers also support a whole `*` segment for array elements,
for example `/data/*/created_at` or `/data/*/items/*/id`. This is shared by
`timestamp`, `duration`, `uuid`, `random`, `unordered`,
`unordered_joined_string`, and Comparison-only `counter` rules. A numeric
segment still selects one exact index; `/*` selects each element of a root
array. Object keys remain exact (including a literal `*` key); `*` does not
expand object members. Standard `~0` and `~1` escaping still applies.

Each selected value is checked independently. UUID and random rules require
matching non-null scalar types and skip literal equality. Timestamp and duration
rules parse and validate time values as described below. Array length, order,
missing fields, and undeclared values remain checked. Empty arrays or fields
absent on both sides create no coverage requirement. Reports keep concrete
numeric Pointers for differences and one rule ID for the wildcard selector.
Plan/apply accepts the same pattern against concrete difference evidence; the
source citation must justify every selected element. Overlapping patterns,
explicit indexes, and ancestor rules are rejected when they could select the
same subtree.

Time rules use a fixed ±5 second tolerance and the engine's captured request
start times. Replay reads source `request.json.timestamp` and target
`request_sent_at`; Comparison uses each capture's request-start `timestamp`.
No current wall-clock fallback or configurable tolerance is allowed.

- `timestamp` requires `format: unix_seconds`, `unix_milliseconds`, or
  `rfc3339`. Each source/target timestamp must be within five seconds of its
  own request start, even if the two field literals are equal.
- `duration` requires `unit: milliseconds`, `seconds`, `minutes`, or `hours`.
  After conversion to the same unit, it requires
  `abs((target_duration - source_duration) - (target_request_time - source_request_time)) <= 5 seconds`.
  This describes elapsed time since a shared origin, not processing latency or
  a decreasing expiry countdown. The deltas are signed.
- Numeric formats accept JSON numbers or numeric strings, including decimals;
  both sides must retain the same JSON type. RFC3339 requires strings with a
  timezone. Boolean/null/container values, invalid formats, overflow, and
  missing request-time evidence fail comparison. Empty selectors remain
  inapplicable. Old timestamp/duration declarations must add format/unit;
  they never silently fall back to scalar-only comparison.

```yaml
response_rules:
  json:
    "GET /api/items":
      timestamp:
        - pointer: /data/*/generated_at
          format: unix_seconds
          source_evidence: src/items.rs:generated_at uses the current time
          source_example: "1700000000"
          target_example: "1700003600"
      duration:
        - pointer: /data/*/elapsed_hours
          unit: hours
          source_evidence: src/items.rs:elapsed_hours measures time since creation
          source_example: "1.5"
          target_example: "2.5"
```

CLI planning/application uses `--timestamp-format unix-seconds`,
`--timestamp-format unix-milliseconds`, or `--timestamp-format rfc3339` for
`--kind timestamp`, and `--unit hours` (or another supported unit) for
`--kind duration`. Quote wildcard Pointers, e.g. `--json-pointer '/data/*/elapsed_hours'`.
These settings also persist through `backend-rewrite rule plan` / `rule apply`.

Never use a generated-scalar rule for a difference caused by process-local
cache state or implementation. Do not exempt an entire scalar when it contains stable
structure that the target omitted. Use evidence-backed apply only after source
review proves the concrete generation mechanism and redacted source/target
examples demonstrate the same stable structure. Supported
rule kinds are `timestamp`, `duration`, `uuid`, and `random`. A nonce or random
salt uses `random`; those names describe a value's business use, not a separate
comparison strategy. Time rules select actual time values and cannot exempt
an entire signed URL, digest, or other encoding derived from time. For values
derived from UUID/random generation, explain the derivation in `source_evidence`. It replans against current evidence before writing; `plan`
is optional diagnostics with
the same strategy and arguments. Multiple Pointers may be submitted together
only when the same citation, rule kind, and examples prove each selected
field; otherwise plan and apply them separately:

```bash
traffic-e2e config replay apply response-rule \
  --target-root . \
  --kind uuid \
  --source-evidence 'src/token.rs:issue_token UUID generation' \
  --source-example '<redacted UUID from source>' \
  --target-example '<redacted UUID from target>' \
  --api 'GET /api/resource/token' \
  --json-pointer /content \
  --case-source <exact-finalized-case-source>
```

Version three also supports arrays whose product contract does not assign
meaning to element order:

```yaml
response_rules:
  json:
    "GET /api/config/ansible_facts":
      unordered:
        - pointer: /general/sudo_users
          source_evidence: src/config.rs:sudo_users is built from a Set
```

Both selected values must be arrays. They are compared as multisets: length,
elements, and duplicate counts must match, while only their outer order is
ignored. Nested JSON values remain exact, as do every undeclared response
location. Generated-scalar and unordered rules cannot overlap the same JSON
subtree.

An exact reorder-only mismatch produces an `unordered_candidates` diagnostic.
After source and target review proves the array is semantically unordered, use
the same evidence-backed workflow:

```bash
traffic-e2e config replay apply response-rule \
  --target-root . \
  --kind unordered \
  --source-evidence 'src/config.rs:sudo_users is built from a Set' \
  --api 'GET /api/config/ansible_facts' \
  --json-pointer /general/sudo_users \
  --case-source <exact-finalized-case-source>
```

JSON strings that encode a joined unordered collection use the same semantic
rule with an explicit separator:

```yaml
response_rules:
  json:
    "GET /api/members":
      unordered_joined_string:
        - pointer: /member_names
          separator: ","
          source_evidence: src/member.rs:member_names joins a Set
```

The comparator splits both strings, preserves empty elements and duplicate
counts, and ignores only token order. A reorder-only mismatch produces an
`unordered_joined_string_candidates` entry containing both the JSON Pointer
and the matching separator. Apply it with `--kind unordered-joined-string` and
`--separator`; source evidence remains mandatory.

Both actions accept only the difference kind selected by `--kind`, runner-owned
assertions using the current policy fingerprint, exact focused-case coverage,
and complete aggregate evidence. Generated-scalar rules may be planned while
dependency evidence is dirty and report every unrelated difference as an
independent failing gate; unordered rules require clean aggregate evidence and
no undeclared response differences. Apply is additive, sorted, and atomic.
These JSON response-rule changes require rerunning
the entire affected API group.

Structured response bodies can opt into codec-aware comparison independently
of the gateway protocol. The following Motan API happens to carry protobuf in
a simple byte-array body envelope:

```yaml
response_rules:
  protobuf:
    "MOTAN /rpc/AlchemyRpcService-getExperimentTrafficRule-byteArray-8cd698b4fea1fb48":
      unordered:
        - field_path: [3, 1, 6, 3]
          display_path: rule_collection.experiments.groups.white_list
          element_type: string
          source_evidence: src/rule.rs:white_list is a Set
        - field_path: [3, 3]
          display_path: rule_collection.group_config
          element_type: message
          source_evidence: src/rule.rs:group_config order is irrelevant
```

Hessian2 uses value names rather than protobuf field numbers. `"*"` traverses
every element of an intermediate list; an empty `value_path` selects a
top-level list:

```yaml
response_rules:
  hessian2:
    "MOTAN /rpc/AlchemyRpcService-getExperimentTrafficRule-long-long-095f05367f122cf4":
      unordered:
        - value_path: [result, ruleCollection, groups, "*", whiteList]
          display_path: cache_result.rule_collection.groups[].white_list
          source_evidence: src/rule.rs:white_list is a Set
```

Some business fields carry a `Set` that has been joined into a single string
(for example `"alice,bob,carol"`). Such a field is a scalar string, not a
list/repeated field, so `unordered` cannot relax it. Use
`unordered_joined_string` instead:
the selected string is split on
`separator` and compared as a multiset (element order is ignored, but
duplicate counts are preserved, matching the List semantics above).
`separator` is required and must be non-empty:

```yaml
response_rules:
  protobuf:
    "MOTAN /rpc/ExampleService-getMembersProto-long-long-095f05367f122cf4":
      unordered_joined_string:
        - field_path: [3, 1]
          display_path: result.member_names
          field_type: string
          separator: ","
          source_evidence: src/cache.rs:member_names joins a Set
  hessian2:
    "MOTAN /rpc/ExampleService-getMembers-long-long-095f05367f122cf4":
      unordered_joined_string:
        - value_path: [result, whiteList]
          display_path: cache_result.white_list
          separator: ","
          source_evidence: src/cache.rs:white_list joins a Set
```

When a structured body mismatches only on such a joined string, the codec-aware
comparison report surfaces `unordered_joined_string_candidates` with the
codec-specific path and the separator that makes the two sides compare equal.
Protobuf requires `field_type: string` so length-delimited message/bytes fields
are never implicitly treated as text. A selected field may be either an
unordered collection or a joined string, but not both.

Gateway protocol, response component, body envelope, and body codec are
separate dimensions. Gateway protocol is currently `http`, `motan1`, or
`motan2`; response comparison distinguishes status, gateway metadata, and
body. A body can then use JSON, protobuf, Hessian2, DOCX, or exact bytes. Protobuf
comparison currently accepts the simple byte-array envelope. Hessian2 accepts
either `envelope: simple_byte_array` or `envelope: raw`. Both compared bodies
must use the same envelope because an envelope change is a response-shape
difference, not a body-value difference.

Motan1 `value` responses are a protocol-defined exception to manual codec
selection: after removing the Java ObjectStream wrapper, replay and comparison
use Hessian2 semantic equality by default. This makes alternate wire encodings
and map entry order non-semantic while list order and business values remain
exact. A matching explicit protobuf or Hessian2 response-body rule still takes
priority, and Motan1 `void`, `exception`, and `attachment` bodies keep their
existing exact handling. `body_diagnosis.used_for_verdict` distinguishes a
structured verdict from decoder-only diagnostic evidence.

The configured rule relaxes only the ordering of the declared repeated
protobuf fields or Hessian2 lists inside the business body. For Motan gateways,
the outer frame metadata remains exact after removing only the
framework-generated `M_pt` process-time entry: protocol version, flags,
request ID, response status, serialization, and every other metadata entry
must still match.

This is a response rule, not a Motan rule. Planning is available whenever
current runner-owned focused E2E evidence or current comparison evidence
contains the required body diagnosis; it is not gated on entering the
Comparison phase. Except for protocol-defined Motan1 `value` responses, when
no body codec is configured, evidence reports the syntactically valid
`protobuf`, `hessian2`, and/or `docx` candidates. They are decoding candidates
rather than schema claims, so application or schema context must select the
codec. The same plan may configure the codec and add reviewed selectors in one
step.
Planning and apply reuse immutable response artifacts and do not start source
or target processes or record new traffic.

For protobuf, adding
unordered fields must provide every newly discovered `field_path` together
with a source/proto-reviewed semantic `display_path`, an explicit repeated
`element_type`, and one-line `source_evidence` proving order is irrelevant. A
packed numeric array is wire-ambiguous without its protobuf
type, so it first appears as a field-level value difference; the reviewed
numeric type is accepted only when offline typed comparison proves that the
same field is reorder-only.

The reported paths and successful offline multiset comparison are mechanical
candidates, not authorization that order is absent from the product contract.
Every selected protobuf path, Hessian2 list, joined string, and DOCX timestamp
must persist its own source citation. Codec-only selection is evidence-light:
for DOCX it ignores only standard ZIP packaging metadata; for protobuf and
Hessian2 it enables decoding without ignoring a body value. It may remain
nonpassing until a later source-proven selector accounts for diagnosed content
differences.

Use the unified response-rule planner:

```bash
backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec protobuf

backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec protobuf \
  --unordered-path '{"field_path":[3,1,6,3],"display_path":"rule_collection.experiments.groups.white_list","element_type":"string","source_evidence":"src/rule.rs:white_list is a Set"}'

backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec protobuf \
  --unordered-joined-string-path '{"field_path":[3,1],"display_path":"result.member_names","field_type":"string","separator":",","source_evidence":"src/cache.rs:member_names joins a Set"}'

backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec hessian2 \
  --unordered-path '{"value_path":["ruleCollection","groups","*","whiteList"],"display_path":"rule_collection.groups[].white_list","source_evidence":"src/rule.rs:white_list is a Set"}'

backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec hessian2 \
  --unordered-joined-string-path '{"value_path":["result","whiteList"],"display_path":"result.white_list","separator":",","source_evidence":"src/cache.rs:white_list joins a Set"}'

backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec docx \
  --docx-timestamp '{"part":"docProps/core.xml","element":"dcterms:created","format":"rfc3339","source_evidence":"src/docx.rs:generate sets core created from the current request clock","source_example":"2024-01-02T03:04:05Z","target_example":"2024-01-02T04:04:05Z"}'
```

DOCX rules compare the exact set of OPC ZIP entries and each decompressed part.
ZIP entry timestamps, compression bytes, entry order, offsets, and
central-directory layout are packaging metadata and do not affect equality. A
selected XML timestamp is accepted only when source and target values are each
within the engine-owned five-second window around their own request time.
Every other byte in that XML part, and every unselected package part, remains
exact. Invalid, duplicate-name, unsafe-path, oversized, or incomplete DOCX
packages fail closed. The codec is explicit, so generic ZIP downloads are not
normalized. The bounded package layer can support later XLSX/PPTX codecs
without broadening the DOCX contract.

Only selected repeated fields ignore element order. Element contents,
duplicate multiplicity, status, undeclared fields, and all other business-body
bytes remain exact. Intermediate field numbers are interpreted as embedded
messages.
Supported terminal types are strings, messages, booleans, enums, and protobuf
integer/fixed-width numeric types, including packed numeric encodings.
`bytes` is deliberately unsupported: neither the outer response-body envelope,
a protobuf `bytes` field, nor `repeated bytes` can be declared unordered.

For Hessian2, `value_path` walks object field names and string-valued map keys;
`"*"` is permitted only to traverse an intermediate list. The selected
terminal must be a Hessian2 list. A path absent from both bodies is a no-op, so
null or smaller cases can share a rule; a one-sided occurrence still differs,
and selecting a present non-list fails closed. Hessian2 maps compare by key
independent of their wire entry order, while list order changes only at an
explicitly reviewed `value_path`. Elements, duplicate multiplicity, types,
unselected values, and binary values remain exact; Hessian2 binary data cannot
be declared unordered.

For joined-string paths, JSON uses `pointer`, protobuf uses `field_path` plus
explicit `field_type: string`, and Hessian2 uses `value_path`. The terminal
must be a string. It is split on `separator` and compared as a multiset, so
element order is ignored while empty elements and duplicate multiplicity are
preserved. A path absent from both bodies is a no-op; selecting a present
non-string fails closed. Joined-string selectors never overlap an `unordered`
selector on the same field.

Comparison-only live counter semantics use the `counter` kind under the JSON API:

```yaml
response_rules:
  json:
    "GET /api/users/show":
      counter:
        - pointer: /followers_count
          source_evidence: src/user.rs:load live follower count
          source_example: "100"
          target_example: "101"
```

Standard replay ignores this subtree. Do not infer counter behavior from the
field name. After source inspection proves a live count and a current
comparison report contains differing observations, use:

```bash
traffic-e2e config comparison plan response-rule \
  --target-root . \
  --kind counter \
  --source-evidence 'src/user.rs:load live follower count' \
  --source-example '100' \
  --target-example '101' \
  --api 'GET /api/users/show' \
  --json-pointer /followers_count \
  --comparison-run .traffic-e2e/local/artifacts/comparison-recordings/<run-id>
```

Review the plan, then repeat with `apply`. Number matches only number. String
matches only string, and empty strings match only empty strings. Presence and
all unsupported JSON kinds remain exact.

## Process-output target-missing allowances

Target-specific metrics-profile allowances live at
`process_output_rules.<output-id>.allow_target_missing`. Each rule selects one
canonical `<type>.<name>` interaction and carries `source_revision`, an ordered
`dependency_path` with at least a direct dependency and its indirect emitter,
and structured `emitter_evidence`. The evidence contains at least two paths the
target AI inspected in source or dependency source plus one single-line
description of the independently emitted interaction.

Use `traffic-e2e config comparison plan|apply allow-target-missing`; do not
hand-edit these entries. Planning requires an exact finalized comparison run
whose raw captures prove a positive source metric and the entire logical
interaction absent on target. Apply rejects project, policy, or capture changes
since planning. The rule is valid only for an independently emitting indirect
dependency. A direct endpoint call, client construction, bean registration,
initializer, or startup hook in repository code requires target implementation.
An interaction that affects source behavior also requires target
implementation. These two eligibility conclusions are preconditions for
submitting rule evidence and are not persisted as boolean fields. The rule
never applies to exact-count metrics and never suppresses target extras.

HTTP `all_http://x`/`http://x` and `all_https://x`/`https://x` canonicalize to
one allowance, without merging their observed counts. The four Motan client
types canonicalize to `RPC_SERVICE_CLIENT`; they are still checked separately
and reported with one logical representative.
