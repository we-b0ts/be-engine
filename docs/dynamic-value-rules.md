# Case-local dynamic dependency values

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v2` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.

For current ordinary fields, prefer [global identity formats](resource-field-contracts.md#automatic-identity-correspondence).
Declare JSON pointers once globally, explicit MySQL scalar formats by table
pattern/column only where needed, and scalar Redis formats by bounded key pattern.
Redis key declarations need no resource/database selectors; complete JSON uses
the global map. The engine infers correspondence from complete typed Source values;
rules do not name identity groups. Native key/template tokens participate in
the same internal case correspondence. The capture/reference mechanisms below
remain only for additional typed relationships not covered by the current
global formats or compact Redis key behavior. Finite initialization dependencies
use `localcache.requests`; actual process task dependencies use
`process_dependencies.tasks.<Source-task-name>.requests`, with an explicit host
for HTTP entries. The remainder of this page documents native/historical
mechanisms, not the ordinary declaration workflow.

A source-generated name can appear in a uniqueness SELECT, an INSERT's scalar
and JSON values, and a Redis cache key. One capture binds its recorded value to
the target's generated value. Later references are discovered in decoded
requests on explicitly allowed endpoints, without configuring each use.

This is a dependency request comparison rule. It belongs in `dependency_rules`,
with `kind: dynamic_value`; there is no separate top-level `dynamic_values`
section. Its case-local binding is shared internally across protocol adapters.
It does not bind inbound API requests or final API responses.

MySQL identity normalization accepts one SQL statement up to 8 MiB and 32,768
tokens. Inline SQL string/JSON values and prepared string parameters use the
8 MiB value budget, including Source reference coverage and binding audit.
Configured SQL templates retain their separate 64 KiB bound.

With native `identity` rules, add a newly proven reference resource to the
existing rule's `effect.references`; keep the same rule ID, capture, API/resource
scope, root proof and all prior relationships. The unified planner permits
append-only references and `read_back` declarations, including both in one
proposal. Put the new Source proof on the appended reference:

```yaml
references:
  # Preserve existing entries here, unchanged and in their original order.
  - contract:
      resource: {protocol: mysql, endpoint: 'db.example:3306', database: app, username: writer}
    proof:
      source: app/completion.py:store_result
      fact: The completed SQL JSON reuses the identity previously captured in Redis.
```

This authorizes references to a committed capture, including strings inside SQL
JSON parameters. It does not generate a second identity or relax other JSON
members. Complete Source preflight must witness every added resource after a
capture; missing or premature references are rejected. Plan/apply freezes the
evidence and requires fresh genuine Replay. Do not create a duplicate capture
rule to add a consumer, and do not modify the old root proof to describe the new
consumer. Removal, reordering or replacement of existing relationships is not an
additive update.

MySQL scalar columns use `mysql.tables`; JSON result values use the global
`json.fields` declaration. Reads reuse complete identities already established
in the same Case and retain unknown historical inputs. No per-SELECT read-back
rule or embedded template is required.

```yaml
version: 3
expected_response: assertions_only
dependency_rules:
  - kind: dynamic_value
    id: generated-name
    api: /api/items
    targets:
      - {host: db.internal, port: 3306}
      - {host: redis.internal, port: 6379}
    capture:
      protocol: mysql
      target: {host: db.internal, port: 3306}
      database: app
      sql: "SELECT id FROM items WHERE name=? AND user_id=?"
      value_index: 0
    source_evidence: "NameFactory:create generates a random name reused in storage and cache keys"
```

`api` is an inbound HTTP path/pattern without METHOD. Targets require exact hosts
and nonzero ports; include the capture target and every allowed reference target.
An optional top-level `when` limits the rule to a Source request branch:

```yaml
when:
  request_body_json:
    /event_type: {equals: item.delta}
```

The predicates read the original recorded inbound body, not dependency JSON or
Target output. They limit capture and reference eligibility without changing the
recording. An event that supplies a fixed block ID must retain its ordinary exact
comparison; a generated-ID rule should select only the Source generation branch.
Missing, malformed, truncated or oversized JSON and scalar type mismatches do not
match either `equals` or `not_equals`. Conditions are ANDed. See the shared
[request-condition contract](dependency-request-rules.md#source-request-conditions)
for bounds and disjoint ownership. Omitting `when` preserves route-only scope.

Choose one of these capture locations:

- **MySQL**: the complete business SQL template replaces literals with `?`.
  `value_index` is zero-based among its placeholders. An optional `json_pointer`
  selects a string inside the selected SQL value. Text queries and prepared
  string parameters use the same capture contract.
- **Redis**: select a `SET` or `HSET` value or `RPUSH`/`LSET` element, a key selector and database. The index
  is zero-based among arguments after the command: `SET` value is index 1;
  `HSET` values are even indices starting at 2; `RPUSH` element indices are 1..128;
  `LSET key index element` selects only argument 2. Its key and signed list index
  retain their existing matching, and the list index is always byte exact even
  when its text happens to equal a captured identity. LSET requires exactly three
  arguments in Source and Target; conditional JSON captures, copies and integer
  derivations use the same contract as RPUSH elements.
  An optional JSON pointer selects a string inside that value; an integer
  capture requires an explicit pointer and `value_type: integer`. Other
  arguments and options remain checked.
- **HTTP dependency**: select method, dependency path/pattern and exact JSON
  pointer in its request body, or an explicit `path_segment` template. This method identifies the outbound capture;
  the enclosing inbound `api` remains route-only.

For source-proven MySQL shards, the capture can use `{{table}}` with explicit
`tables`, `table_patterns`, or `table_series`, using the same selectors as
[MySQL time rules](mysql-time-rules.md):

```yaml
capture:
  protocol: mysql
  target: {host: db.internal, port: 3306}
  database: app
  sql: SELECT id FROM {{table}} WHERE {{table}}.name=? AND user_id=?
  table_series: {prefix: items_, start: 0, end: 15, width: 4}
  value_index: 0
```

Source proof must justify the table family and its bounds; observed table names
alone do not establish the range. Exact `tables` and bounded `table_series`
cover at most 4096 distinct names. Series require canonical zero-padding with
width at most 10. Up to 64 `table_patterns` may use one `*` between ASCII
identifier affixes; a bare wildcard is rejected. The selectors may be combined.

Every marker selects a whole table identifier or table qualifier. The recorded
statement binds one physical table, and Target must match that same bound table,
including every qualifier. Two allowed shards never substitute for each other.
Literal, column, alias and identifier-fragment markers are unsupported. A marker
requires declared bounds, and bounds require a marker; concrete legacy SQL needs
no changes. Automatic references still preserve ordinary SQL table identities.
Captures with overlapping API, endpoint, database, SQL and selected field are
rejected; disjoint JSON pointers retain separate ownership.

Alternative capture examples (include their targets in `targets`):

```yaml
capture:
  protocol: redis
  target: {host: redis.internal, port: 6379}
  database: 0
  command: SET
  key: identity:current
  argument_index: 1
# Or:
capture:
  protocol: http
  target: {host: service.internal, port: 8080}
  method: POST
  path: /items
  json_pointer: /name
```

Redis `capture.key` shares the existing Redis key selector syntax. A string
keeps exact matching; an object selects a prefix, suffix or both. Set
`numeric: true` to require a nonempty ASCII-digit middle between those affixes:

```yaml
key: identity:current                         # exact, unchanged syntax
key: {prefix: 'identity:'}                    # prefix
key: {suffix: ':current'}                    # suffix
key: {prefix: 'identity:', suffix: ':current', numeric: true}
```

For task-owned keys, `key: {prefix: 'task:', numeric: true}` selects the family
`task:<id>`. Selection does not exempt the ID: each source/target capture must
have identical complete key bytes, even when both keys match the pattern.
Capture keys are not rewritten during value normalization. Full keys are
bounded to 1024 bytes. Plain strings do not interpret `*`, and arbitrary regex
selectors are unsupported. Overlapping key selectors cannot own the same
argument/JSON capture location in overlapping API scopes; request-contract
overlap checks use the same selector semantics.

Discovery continues to publish an exact key in each capture witness; it never
infers a prefix from similar keys. A proposed pattern must cover a concrete
same-case immutable witness, and source evidence must justify the selected
family. Binding consistency, the 256-identity limit and reference behavior stay
case-local to the rule across its selected keys.

No format declaration is required. Values must be nonempty UTF-8 strings of at
most 1024 bytes. Structured JSON requires an explicit pointer to a string;
whole objects and arrays cannot be captured as opaque identities. Optional
`format: uuid` or `format: uuid_v4` validates both captured values. Source evidence
must prove generation, lifetime and intended uses. A differing argument alone
does not prove randomness.

HTTP and Redis integer correlation IDs use `value_type: integer` with an exact capture
JSON pointer. The default remains string. Integer rules preserve type and do
not infer references outside that selected request location. See the complete
[dependency request rule examples](dependency-request-rules.md).

## HTTP path-segment capture

An object-store key can first appear in an HTTP PUT path before it is written
to SQL. Select its decoded filename segment and declare which components are
source-proven dynamic. The complete segment becomes one identity, so later
SQL JSON values such as `attachments/<filename>` retain the same complete typed identity correspondence.

```yaml
dependency_rules:
  - kind: dynamic_value
    id: attachment-storage-key
    api: /api/attachments/upload
    targets:
      - {host: storage.example.test, port: 9100}
      - {host: db.example.test, port: 3306}
    capture:
      protocol: http
      target: {host: storage.example.test, port: 9100}
      method: PUT
      path: /bucket/attachments/*
      path_segment:
        index: 2
        template: "{nonce}_{created_at}_{user_id}_{attachment_id}"
        fields:
          nonce: {kind: random, format: hex, length: 12}
          created_at:
            kind: timestamp
            format: "%Y%m%d%H%M%S"
          user_id: {kind: exact}
          attachment_id: {kind: exact}
    source_evidence: >-
      Storage:generate_key uses UUID hex[:12], current UTC time, owner ID and
      the inserted attachment ID, then reuses that key in storage and SQL.
```

`index` is zero-based after the leading `/`: `bucket` is 0, `attachments` is 1,
and the filename is 2. It must select a whole-segment `*` in `capture.path`.
HTTP captures require exactly one of `json_pointer` and `path_segment`;
integer captures remain JSON-only. Overlapping path captures for the same
endpoint, method, API and segment are rejected.

Every template field must be declared once. Fields require nonempty values;
adjacent or repeated placeholders are invalid. Literal separators use `_`,
`-`, `.` or `:`. Templates and decoded identities are limited to 1024 bytes,
32 fields and path indices below 64. Invalid escapes, non-UTF-8 segments,
decoded slashes, backslashes and control characters are rejected.

- `exact` requires equal source and target components.
- `random` currently requires `format: hex` and an explicit length (1–1024);
  both values must have that shape. Shape alone does not prove randomness.
- `timestamp` currently requires the strict 14-digit UTC format
  `%Y%m%d%H%M%S`; `timezone` defaults to UTC. When the **entire decoded path
  identity** is byte-identical, a valid historical timestamp is accepted by
  default. Existing keys reused by overwrite requests need no additional mode.
  All template fields still require their declared shapes and valid dates.

  When any identity component differs, both timestamps must be within the shared
  inclusive ±5-second window of their own dependency HTTP request start.
  This is independent of the inbound API clock. For older recordings, a
  missing request start can be estimated from that exchange's completion
  timestamp minus integral nonnegative `duration_ms`, as with header rules.
  Changed keys with missing clocks or out-of-window timestamps fail. Invalid
  calendar dates always fail. There is no configurable tolerance.

  Explicit `mode: preserve_or_request_window` remains accepted and has the same
  behavior as omitting it. `mode: request_window` explicitly requires the window
  even for identical identities. Canonical contracts retain the effective mode,
  so changing it changes the execution fingerprint. Do not relabel an old
  calendar date as random hex to bypass its contract.

Capture changes only the declared path identity. Uploaded bodies retain
ordinary strict comparison, including text that contains the filename.
Surrounding path segments, queries, headers and finite exchange inventory keep
their existing checks. HTTP signing-time headers require their own existing
header rules. Bindings commit only after the complete request matches and stay
within the current case; subsequent SQL must use the filename bound by PUT.
Include every allowed reference endpoint in `targets`.

Path-only failures produce mechanical `dynamic_capture_candidates` when exactly
one segment differs and body bytes and query contracts agree. The witness
contains the segment index, selectors, fingerprints and target request clock;
it does not infer nonce fields, timestamp semantics or generation. Selected
token values are not added to the candidate. Plan verifies the target path
against the existing unmatched HTTP observation and the immutable source
exchange, then validates the proposed template, fixed fields and time windows.
Header differences are audited independently after a matching Replay; a path
rule does not grant a header exemption. Use the same `rule plan --dynamic-value`
and `rule apply` workflow below, followed by fresh Replay.

## Authoring and discovery

MySQL `unmatched_target` dirty clusters offer a `dynamic_value` hint. Redis and
HTTP single-string or integer differences provide `dynamic_capture_candidates` in finalized
Replay reports and dirty-cluster evidence. These bounded witnesses contain
selectors and fingerprints, not newly logged token values. They offer the same
planner hint; source review is still required.

```bash
backend-rewrite rule plan --evidence-id CURRENT_EVIDENCE_ID \
  --dynamic-value '{"id":"generated-name","targets":[{"host":"db.internal","port":3306},{"host":"redis.internal","port":6379}],"capture":{"protocol":"mysql","target":{"host":"db.internal","port":3306},"database":"app","sql":"SELECT id FROM items WHERE name=? AND user_id=?","value_index":0}}' \
  --source-evidence 'NameFactory:create generates a random name reused in storage and cache keys'
backend-rewrite rule apply RETURNED_PLAN_ID
```

The coordinator supplies the active API route and wraps the entry with `kind`.
Plan requires finalized evidence under the current policy, a complete same-case
recorded response, and a target capture differing only at the selected value.
JSON captures preserve unselected members. Apply checks immutable evidence and
policy fingerprints and requests fresh Replay. Existing recordings are reusable;
old reports are not retroactively changed. Other dependency planners preserve
these entries when editing the common rule list.

If another rule or a comment changed the policy since Replay, follow the
evidence's coordinator refresh command and obtain new evidence using the same
recordings before planning. Stale evidence suppresses planner hints and reports
both policy fingerprints; it does not indicate an unsupported capture or
recording version. See [policy freshness](replay-policy.md#policy-freshness-before-rule-planning).

## Plan ordinary generated fields

Declare generated scalar MySQL IDs under root `mysql.tables` and all decoded
JSON fields under root `json.fields`. Native SQL temporal columns are inferred
from metadata. For example:

```yaml
format: traffic-policy/v2
json:
  fields:
    /item_id: {kind: identity, formats: [uuid]}
    /created_at: {kind: time, formats: [unix_seconds]}
mysql:
  tables:
    items:
      pattern: items
      fields:
        id: {kind: identity, formats: [uuid]}
rules: []
```

Use `backend-rewrite rule plan --file … --evidence-id …`, inspect its concrete
preview, then apply its plan ID. No authored binding or generator-first capture
is required. Native key/URL derivations and signed values keep their additional
Source proof; ordinary field formats remain global. See the
[field guide](resource-field-contracts.md) for optional/null semantics, exact
equal scalar anchors and verified read delivery.

## Runtime contract

- Capture decisions commit only after the exchange matches. A failed candidate
  cannot authorize later calls. Each source identity has one target identity;
  distinct source identities cannot collapse into one target value.
- Bindings stay within one case and rule, and reset when that case restarts.
  Global and shared cross-case exchanges cannot use them.
- Automatic references cover MySQL text literals/prepared string parameters,
  JSON string values and member names, Redis decoded arguments including key
  substrings, and HTTP dependency paths, queries and JSON bodies. Surrounding
  bytes, object members, array order and scalar types remain checked. Duplicate
  JSON members and ambiguous translations fail.
- Headers, hashes, signatures and opaque binary encodings are not inferred.
  References must follow a successful capture. Inbound and final response
  contracts continue to use their respective explicit rules.
- Finite consumption, response delivery, connection ordering, authentication,
  database and case ownership remain enforced. Redis value and MySQL time
  rules retain their own validations.
- Each rule supports at most 256 distinct identities per case. Applicability
  and binding counts appear in the dependency rule report; unused applicable
  captures fail verification. Binding audits contain fingerprints. The SQL time
  planner restores only same-case bindings proven by the finalized report.

The rule changes request comparison only. It never rewrites recordings,
recorded dependency responses, target responses or expected assertions.
