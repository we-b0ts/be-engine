# Resource-owned field contracts

`traffic-policy/v2` separates resource identity, the location of data, its value
contract and protocol effects. Declare persistent data semantics once under
`resources`, API output semantics under `responses`, and contextual or stateful
behavior under `rules`. Loaders accept this format only. An empty document is:

```yaml
format: traffic-policy/v2
resources: {}
responses: {}
rules: []
```

## Choose the contract before the statement

At the first relevant mismatch, inspect existing declarations and trace the
Source field's meaning. Record its physical location, codec, permitted branch
and Source proof before choosing a strategy:

| Source meaning | Field contract | Evidence to retain |
| --- | --- | --- |
| A clock value or expiry | `relative_time` or `request_time`, with its format | Units, independent request clocks, TTL offset and fixed sentinels |
| A live elapsed value | `duration`, with its unit and a conditional branch when needed | Terminal values, status and the Source duration formula |
| A collection consumed without order | `unordered` | Element associations, types, membership and duplicate counts |
| An eligible generated identity reused in several places | `identity`, with a shared `binding` and explicit format | Source variability, eligible locations, equality and distinctness |

The MySQL column or Redis value owns these semantics across APIs and supported
SQL/command shapes. A new statement, parameter index or caller does not require
another copy of its field strategy. Response declarations still identify the
output's API and body or SSE envelope. A codec supplies decoding; it grants no
permission to change a field.

Discovery may have no mechanical draft for a valid Source-proven contract.
Inspect `source_entry.bindings` and its inventory requirements in that case.
For an identity, collect all eligible locations together rather than waiting
for separate capture and reference failures. Native effects describe additional
behavior such as one shared clock, ID derivation, signatures, state transitions
or finite consumption. They can reuse field strategies with `field_ref` at
supported contract sites.

## Resource identity and physical data

Resource names are local authoring references. Endpoint, database and user are
resolved before compilation; Replay receives typed resource identities and
compiled field selectors. Renaming a reference while preserving its resolved
meaning preserves effective policy fingerprints. It does not merge resources,
share exchanges or establish cross-protocol business identity.

```yaml
format: traffic-policy/v2
resources:
  task_database:
    protocol: mysql
    endpoint: db.internal:3306
    database: app
    username: worker
    proof:
      source: models/task.py:save
      fact: Generated task UUIDs are copied to links, payloads, cache and responses; each row generates its audit time.
    tables:
      task_rows:
        tables: [tasks]
        table_series: {prefix: tasks_, start: 0, end: 1023, width: 4}
        fields:
          id: {kind: identity, binding: task-id, format: uuid}
          updated_at: {relative_time: sql_datetime}
          payload:
            codec: json
            fields:
              /task_id: {kind: identity, binding: task-id, format: uuid}
              /saved_at: {relative_time: rfc3339}
              /members: unordered
              /members/*/created_at:
                relative_time: rfc3339
                clock_scope: array_element
      task_links:
        fields:
          owner_id: {kind: identity, binding: task-id, format: uuid}
  task_cache:
    protocol: redis
    endpoint: cache.internal:6379
    database: 0
    proof:
      source: cache/task.py:write
      fact: Stored documents copy the generated task UUID and preserve request-relative times and member multiplicity.
    keys:
      - key: {prefix: 'task:document:'}
        container: string
        value:
          codec: json
          fields:
            /task_id: {kind: identity, binding: task-id, format: uuid}
            /updated_at: {relative_time: unix_seconds}
            /members: unordered
responses:
  task_details:
    api: GET /tasks/*
    proof: {source: 'api/task.py:read', fact: 'The response copies the stored generated task UUID'}
    body:
      codec: json
      fields:
        /id: {kind: identity, binding: task-id, format: uuid}
rules: []
```

The MySQL declaration selects the physical database, table family and column.
It applies to supported accesses across APIs and SQL shapes, including a new
statement absent from the configuration. It does not enumerate recorded SQL.
An unqualified table uses the observed connection database; a qualified table
retains its explicit database. A configured resource database never supplies a
missing observed default. Without that observed identity every relation must be
fully qualified; an unqualified relation fails closed. Aliases resolve to their
physical relation.
Source and Target must still use the same physical shard and preserve every
unselected SQL token/value, predicate and finite exchange.

The SQL resolver covers direct INSERT values, UPDATE assignments, comparisons,
BETWEEN and IN operands, including direct JOIN conditions and HAVING. It never
treats an arbitrary expression argument as the value of a referenced column.
Ambiguous bare columns in joins, nested query scopes, wildcard projection
fallbacks and unsupported expressions grant no field permission. Existing
native SQL effects retain explicit statement selection when their causal
behavior needs it. Prove a table family from Source construction; observed
numeric suffixes alone do not justify a `table_series`.

MySQL scalar declarations use native scalar values. A JSON/PB column declares
its codec and logical fields explicitly. For PB, provide numeric field paths,
types and repeatedness through the existing typed codec. JSON/PB paths are
locations inside that column, rather than placeholder ordinals.

Result columns use recorded physical database/table/original-column metadata,
independently of projection aliases. New recordings preserve the wire schema.
When older recordings lack it, only a proved direct projection can supply the
missing origin. A connection default alone cannot identify a cross-database
result column.
Time nullability follows values observable from Source queries as well as the
stored schema. An outer join can project NULL for a NOT NULL column. Such
projections need the same inactive self guard shown below for nullable values;
unconditional time contracts require a timestamp and reject NULL.

## Redis carriers

Redis fields select the resource, DB, key, logical container and decoded path.
Key selectors support `exact`, `prefix`, `suffix` and a canonical `numeric`
segment between affixes. Hash fields have their own `hash_field` selector.

```yaml
resources:
  task_cache:
    protocol: redis
    endpoint: cache.internal:6379
    database: 0
    proof: {source: 'cache/task.py:write', fact: 'These cache entries store task JSON with generated update times'}
    keys:
      - key: {exact: 'task:documents'}
        container: hash
        hash_field: {prefix: 'task:'}
        value:
          codec: json
          fields: {/updated_at: {relative_time: unix_seconds}}
      - key: {prefix: 'task:events:'}
        container: list
        value:
          codec: json
          fields: {/created_at: {relative_time: rfc3339}}
```

Installed carriers are `string`, `hash` and `list`. String values map SET,
SETEX/PSETEX and MSET writes to GET/MGET reads. Hash values map HSET/HMSET to
HGET/HMGET/HGETALL; list elements map LPUSH/RPUSH/LSET to LINDEX/LRANGE.
This locates values inside protocol commands. Keys, hash field names, list
indexes, argument counts, TTL/options, order, null/error outcomes and finite
consumption retain their protocol contracts. A declared value does not imply
SET/GET equivalence, unordered list elements or permission to add calls.
RESP field extraction accepts at most 1 MiB per response, 16384 frames or request
arguments, and 64 nesting levels. Each selected value also retains the codec's
1 MiB limit. Exceeding a bound reports an error rather than skipping validation.

Scripts, lock tokens, Pub/Sub ownership, APPEND batching, expiry refreshes and
read-back causality remain explicit native effects. A JSON path does not define
which Lua argument, sorted-set score or stream field carries that data.

## API responses and contextual rules

API response fields retain method/path and output-envelope scope:

```yaml
responses:
  task_details:
    api: GET /tasks/*
    proof: {source: 'api/task.py:read', fact: 'The response emits its generated time and an unordered membership collection'}
    body:
      codec: json
      fields:
        /data/generated_at: {relative_time: rfc3339}
        /data/members: unordered
  task_events:
    api: POST /tasks/events
    proof: {source: 'api/events.py:stream', fact: 'Each selected event carries the request-relative generated timestamp'}
    sse:
      - event: {event: message, json_type: task.created}
        codec: json
        fields: {/created_at: {relative_time: unix_seconds}}
```

SSE event/type, count, order, closure and unselected content remain checked.
Identity bindings and entity clock scopes still need their existing Source
generation/lifetime proof. Outbound HTTP bodies retain endpoint, method/path,
surface and explicit codec selection; headers, signatures, multipart and inbound
adaptations use their installed native owners. Named resources can be referenced
from `rules[].match.resource` without duplicating their identity.

A field's strategy and a statement's clock relationship are separate facts.
Resource field contracts apply across APIs and supported SQL/command shapes.
Do not add statement rules or parameter ordinals merely to repeat independent
field strategies. A native rule needs an additional Source-proven relationship
or effect. Use `field_ref` when that behavior must refer to a declared field:

```yaml
rules:
  - id: update-task-clock-relation
    match:
      resource: task_database
      operation: COM_QUERY
      sql: UPDATE tasks SET updated_at=?, payload=? WHERE id=7
    effect:
      kind: mysql_values
      values:
        0:
          field_ref: {resource: task_database, table: task_rows, column: updated_at}
          clock_group: save-clock
        1:
          kind: json
          fields:
            /saved_at:
              field_ref: {resource: task_database, table: task_rows, column: payload, pointer: /saved_at}
              clock_group: save-clock
    proof:
      source: service/task.py:save
      fact: This update copies one save clock into updated_at and payload.saved_at; other payload fields and row identity remain exact.
```

`table` names the declaration key (`task_rows`), while `column` is physical.
A decoded column also supplies `pointer`. Redis references use a resource,
zero-based `key` declaration index and `pointer`. These are typed local
references; unknown resources, columns, pointers and incompatible strategies
reject. A contextual use may override `clock_group` and local proof; it cannot
replace the referenced strategy. References remain readable references after
rendering and re-resolve when the declaration changes.

## Time, conditions and delivery

`relative_time` preserves the Source/Target request-relative offset within the
fixed five-second engine boundary. A SQL time type alone does not prove that
semantics. Historical dates, sentinels, units, copied values and independent
clock reads require their actual Source behavior.

Schema instant timestamps without an authored `clock_group` have independent generated
groups per physical field/path. Wildcard paths give each selected actual leaf
its own default scope, and repeated SQL occurrences also remain independent.
Equal coarse Source timestamps do not imply one shared clock.
The generated `schema.` namespace is reserved. An authored group or contextual
`field_ref` group explicitly preserves a Source-proven relationship; copied
values retain equality and correlated shifts must agree within one microsecond.
Groups never choose a clock anchor. Each dependency uses its own independently
observed request start; API responses use their own HTTP request start.
`calendar_date` instead preserves civil-date distances with an explicit
`utc_offset` and has no clock group.

Use a self condition for a fixed scalar sentinel:

```yaml
writer_lease_expires_at:
  kind: conditional
  when: {relative_pointer: '.', not_in: ['1970-01-01 00:00:00']}
  contract: {relative_time: sql_datetime}
```

The Source sentinel stays exact, and Target must remain in the same branch.
An active expiry follows its time contract. Sibling conditions such as
`relative_pointer: ../status` continue to protect business discriminators.
For a nullable scalar, include `null` explicitly in the inactive branch, for
example `not_in: [null, '1970-01-01 00:00:00']`. Without a matching inactive
condition, a time contract rejects a present null; it does not silently skip it.
Source/Target additions, deletions and type changes do not gain permission from
a field being absent in another observation.

Comparison and dependency input rewriting remain separate. Only an explicit
`delivery: {rebase_time: [...]}` changes selected dependency response times.
For a scalar column the selected path is `''`; decoded payloads use their logical
paths. Without delivery, a read declaration preserves the recorded input.
Stateful read-back, signatures, sentinel preservation and successful wire
delivery retain their own checks. Original recordings are never rewritten.

A later write may copy a historical timestamp from a dependency read. For example,
a task read delivers its stored `createdAt`; the application changes `updatedAt`
and writes the document back. The engine retains the Source-read time and the
actual delivered time as a pair. A subsequent schema field comparison can reuse
that pair only in the same case, at the same physical field and declared logical
path. MySQL uses the observed endpoint, database, table and column; Redis also
retains the concrete key, container and hash field. A new SQL shape or command
does not change that identity. Unselected content and the enclosing value's
ordinary element/identity matching still have to pass.

This permission requires successful response delivery. Preparing a response,
seeing equal old timestamps, or reading a different table in the same family
provides no permission. If one Source time has been delivered as different Target
times in that scope, its copy mapping becomes ambiguous and cannot authorize a
write. Explicit native generation contracts, including contextual `field_ref`
clock relationships, still validate their own time shifts. The copy proof cannot
satisfy those contracts. Driver spelling differences such as SQL `.000` versus
no fractional suffix preserve the same timestamp; JSON scalar types remain
strict. No policy switch enables arbitrary equal historical values.

## Identity domains and read delivery

An identity `binding` names one case-local domain shared by declared MySQL,
Redis and response fields. It preserves the partition observed in Source:

```text
Source: table_a.id = table_b.owner_id = cache.task_id = S, response.id = U, S != U
Target: table_a.id = table_b.owner_id = cache.task_id = T, response.id = V, T != V
```

Source and Target IDs may differ. One Source ID must always map to one Target
ID, and different Source IDs cannot collapse into one Target ID. There is no
need to configure every equality pair or designate an INSERT as the first
capture. A first eligible independent observation may establish the mapping;
failed candidate comparisons do not commit it.

For example, these are ordinary field contracts, with Source proof inherited
from their enclosing declarations:

```yaml
# resources.task_database.tables.task_rows.fields
id: {kind: identity, binding: task-id, format: uuid}

# resources.task_database.tables.task_links.fields
owner_id: {kind: identity, binding: task-id, format: uuid}

# resources.task_cache.keys[...].value.fields
/task_id: {kind: identity, binding: task-id, format: uuid}

# responses.task_created.body.fields
/id: {kind: identity, binding: task-id, format: uuid}
```

The comments locate separate declaration fragments; they are not one YAML
mapping. A decoded JSON field uses its logical pointer, while a scalar MySQL
column selects the scalar itself. Formats and any literal prefixes must match
the declared Source construction. A shared binding needs a consistent format.
Supported forms are `uuid`, positive `decimal`, `{hex: N}` and `{base64url: N}`;
fixed token lengths range from 1 to 256. Decimal values can be strings or unsigned
integers, preserving the type at each physical location. Prefixes remain literal
at each location while the suffix token supplies the shared entity identity.

Dependency reads preserve data flow. A selected read field with an established
mapping delivers the corresponding Target ID. An unknown recorded ID delivered
as input anchors itself, so a later write or response cannot arbitrarily rename
that historical input. Delivery is not independent Target evidence. Ordinary
read ordering, protocol outcomes and finite consumption still apply; declaring
an identity does not authorize extra GETs, arbitrary SELECTs or cache reuse.
Each case starts fresh identity state. Repeated configuration declarations do
not create a process-global or cross-case ID map.

An ID supplied by the immutable API input is fixed before the first dependency
read or write. The engine lazily indexes exact JSON string/unsigned-integer
scalars, decoded path segments and query values, then checks the declared
domain's literal-prefix forms. It never matches substrings or grants identity
permission from input shape. This input index is bounded to 16384 visited
positions and 1 MiB and is released with case identity state. Empty identity
comparisons do not build it. Incomplete captures and nonempty opaque bodies
cannot authorize free renaming; keep their typed native owner. Headers,
arbitrary embedded text/URLs and primary interaction input frames are not
automatically indexed by this fixed-input check.

Source proof authorizes eligible **locations**, while observed values determine
the concrete equality relationships. A UUID-looking string or equal values in
one trace alone do not authorize renaming. Fixed business IDs, externally supplied
IDs, null, empty values and sentinels need their exact behavior. JSON sibling
conditions can select a proven branch. A scalar MySQL declaration cannot inspect
an arbitrary sibling row column: when a shared physical column mixes generated
and fixed/external IDs and the eligible subset cannot be expressed, retain its
existing narrow native owner rather than widening the column permission.

Identity relations do not prove `id == "text-" + timestamp`, a SHA256 digest,
an embedded key/URL template, JWT validity or a lock's lifetime. Keep these
additional relationships in their typed native effect. Independent random
booleans, status codes and low-cardinality values also do not become entity
identities merely because they happened to be equal in Source.

Identity state is bounded to 4096 entities per case and 32768 across retained
cases; each domain admits at most 64 literal prefix variants. Selector traversal stops after 16384 visited positions or 4096 selected
leaves. Matching validates a small proposal against indexed forward/reverse maps;
only an accepted observation commits the complete proposal. Read delivery reuses
the decoded value and resolves declared leaves, with no search through unrelated
strings. Runtime tokens stay private; diagnostic reports omit them. Response
assertion submits its identity constraints to Replay before case cleanup, so a
response cannot invent another mapping for an ID already written to storage.

## Compilation, Replay and evidence

The authored graph lowers to the same typed value/native pipeline. Compilation
resolves references/proofs, rejects conflicting field ownership and prepares
endpoint buckets, physical table matchers and codec plans once. Replay does not
look up resource aliases or expand declarations into recorded SQL templates.

The MySQL resolver caches immutable, literal-free statement analysis: physical
origins, token positions and column indexes. Positive and unsupported parses
share bounds of 256 entries, 8 MiB total and 1 MiB per entry. Parsing and eviction
destruction occur outside the shared lock. Source/Target analysis is reused
across selected rules; unrelated statement shapes skip AST work. Native lexer
reuse remains bounded separately. Complete result origins avoid SQL parsing on
the ordinary response path; older metadata uses bounded cached projection
analysis. Request selection reuses that analysis across its applicable rules.

Literal/bind values, decoded live payloads, clocks, rule applicability, identity
bindings, claims, availability, consumption and comparison decisions are never
part of this cache. Every real candidate still validates its live values and
permissions. Codec preparation caches schema, rather than successful validation.

Read-copy provenance is separate case state, cleared when a case begins and
released when it successfully ends. It holds
bounded SHA-256 fingerprints of typed timestamps and physical/path identities,
with at most 4096 retained clock observations per case and 32768 in total.
Repeated observations dominated by an earlier read on both clocks share one
entry; conflicting delivered values disable that mapping. A MySQL pending response
retains only declared active time leaves and carrier hashes, bounded to 4096
leaves across its selected rows and columns. An ordinary unchanged read decodes
each selected carrier once and reuses those leaves after delivery; a rewritten
carrier decodes the delivered value once more. Changed carriers pair leaf paths
through an index, rather than comparing every pair of array elements. After a
successful wire flush, all of that read's fingerprints are published atomically
through a separate synchronous store before awaiting the shared replay ledger.
These facts neither cache comparison outcomes nor consume an exchange. Offline
validation reconstructs the same pairs from protected delivery witnesses and
requires the Source read completion to precede the Source write request and the
actual Target delivery to precede the Target write request. Both independently
observed pairs must be present; render-time anchors cannot prove wire delivery.
The two cutoffs must hold for the same read observation. Redis also requires
the protected read request and completed input to share their observation ID;
equal clocks alone cannot join different requests.
The protected `delivered_input` witness role records that successful wire fact,
separately from `derived_delivery` materialization evidence. Managed witness
retention also keeps the complete protected Source/Target response envelopes;
when an explicit delivery already owns the Source envelope, MySQL shares its
immutable bytes. Ordinary Replay retains only the selected leaves and hashes.

Discovery can report observed physical fields before a declaration exists.
Those suggestions provide no codec, table-family, generation or clock proof.
Managed changes use the existing `rule plan --file ... --evidence ...` and
`rule apply --plan ...` lifecycle with complete Source coverage, protected Target
witnesses, stale checks, durable recovery and genuine Replay obligations.
Offline identity comparisons validate each retained payload's format, local
equality partition and strict remainder. The inventory also contains speculative
Source candidates, so their pairs are not merged into a purported accepted
case-wide identity graph. Selected identity rules remain explicit
`stateful_target_obligations`; fresh genuine Replay must establish the shared
domain, delivered input anchors and successful exchange admissions together.
An independently observed payload passing preflight does not discharge that
relationship obligation.
Resource/response amendments retain unrelated declarations and authored rules.
Amendments are additive and preserve existing identity, proofs and fields.
Omission never deletes a declaration; unsupported declaration replacement or
deletion rejects. Explicit `traffic-policy-change/v1` proposals can replace named
authored rule IDs with independently proven declarations or rules.
