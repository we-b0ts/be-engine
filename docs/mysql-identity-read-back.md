# MySQL identity read-back

Replay returns recorded dependency responses by default. When Source persists a
generated identity and later reads it from MySQL, a native `identity` rule can
declare `effect.mysql_read_back`. Selected JSON result fields then carry the
identity already bound by the corresponding successful Target capture. Target
can copy that result into a later request without using recorded Source IDs.

Append the declaration to the existing identity rule. Preserve its ID, capture,
API, resource, references, previous declarations and proofs. The read resource
must already appear in `effect.references`. Give each appended read its own
Source proof of the capture, stored result and later read:

```yaml
mysql_read_back:
  - resource:
      protocol: mysql
      endpoint: db.example:3306
      database: app
      username: writer
    sql: SELECT payload FROM {{table}} WHERE id=?
    table_series: {prefix: results_, start: 0, end: 1023, width: 4}
    column: payload
    json_pointers: [/blocks/*/id]
    proof:
      source: app/store.py:create_and_read
      fact: Source stores the generated block id, reads the result and copies it into Task JSON.
```

`column` identifies the physical result column, independent of its alias. The
SQL is a bounded complete SELECT; explicit tables, patterns and series use the
ordinary SQL table selector. `{{table}}` must be a complete identifier or
qualifier. It cannot replace fragments inside aliases such as `results_0001_id`;
use separate exact physical SQL declarations for those statements. SQL text and
prepared execution share the same finite recorded exchanges. Query matching,
predicates, authentication, physical shard selection and consumption retain
their ordinary owners.

Only string leaves at the declared JSON pointers are translated. `*` selects
array elements. By default the entire string must equal a captured identity;
sharing its prefix is insufficient. Missing fields, nulls, historical IDs without a current binding,
other JSON members and unselected columns remain unchanged. Embedded copies
such as a content key require an explicit template, for example
`templates: {'/blocks/*/key': 'content:{value}'}` together with that JSON pointer.
Exactly one `{value}` slot is permitted; the surrounding text remains exact.
For conditional Redis captures, the same sibling condition selects each
read-back leaf; the stored JSON must retain that discriminator.
The source identity must already have a committed Target
binding in this Case, and its immutable Source capture must complete before the
Source read starts. A capture from another Case, method, resource or future
Source event cannot authorize delivery. Existing request identity consistency
checks remain strict.

Each declaration supports at most 32 unique, non-root JSON pointers; a rule
supports at most 16 declarations. Source preflight requires positive causal
evidence for every selected pointer in every declaration. Incomplete, truncated
or ambiguous result evidence is rejected. Overlapping field owners are rejected;
disjoint fields can compose with ordinary JSON time delivery contracts. The
planner checks those delivered copies using the same attested identity pairs,
and retains fresh Replay obligations for stateful identities. Derived delivery
does not count as independent Target request evidence.

Use the ordinary unified rule plan/apply flow and run fresh Replay after apply.
`replay_policy.mysql_identity_read_backs` records successful delivery relationships
with Case/rule/declaration, physical column, selected pointers, original Source
connection/query sequence and response fingerprints. It does not expose the raw
identities. Preview, failed matching and failed wire delivery do not publish a
successful read-back. Original recordings are never rewritten.
