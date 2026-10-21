# Redis write-to-read delivery

Replay normally returns the immutable Source response. An `identity` or
`redis_sequence` rule can explicitly declare `effect.read_back` to return
selected values from an earlier successfully matched Target write to the same
key. This supports ordinary Redis clients that write a generated block ID or
creation timestamp, read it, and reuse it in subsequent writes.

Update the existing write rule. Keep its ID, API, resource, database, key,
capture, references and request contracts. Add a read declaration and Source
proof of both the write and subsequent read. The planner permits a same-ID
update only when it appends `read_back` declarations and preserves the entire
existing rule, including prior declarations and proofs. Put the new read proof
on its declaration rather than changing the existing write proof. No declaration
means no change to existing delivery behavior.

For an `identity` rule capturing SET argument 1 as a raw block ID:

```yaml
effect:
  kind: identity
  value_type: string
  capture: {kind: redis_argument, index: 1}
  references:
    - resource: {protocol: redis, endpoint: 'cache.test:6379', database: 0}
  read_back:
    - operation: GET
      write_operation: SET
      argument_index: 1
```

The containing rule must select an API, explicit Redis database and key, and
`match.operation: SET`. If Source SET writes `old` and Target SET writes `new`,
a later matching Source GET returning `old` delivers `new`. Subsequent commands
still have to match their recorded exchanges using the existing identity rule.

For a `redis_sequence` rule already owning JSON timestamp fields in SET
argument 1, add only the preserved field to its read declaration:

```yaml
read_back:
  - operation: GET
    write_operation: SET
    argument_index: 1
    json_pointers: [/started_at]
```

The delivered `/started_at` equals the exact Target timestamp previously
written. It is not recalculated using the GET clock. Other fields, including
`/last_activity_at`, retain their original Source values. Target remains
responsible for updating those fields according to Source behavior.

For list metadata owned by a conditional RPUSH identity capture, declare:

```yaml
read_back:
  - operation: LRANGE
    write_operation: RPUSH
    argument_index: 1
    json_pointers: [/id, /_content_key]
```

Each selected field must already belong to that rule's capture or declared
copies. The writer's Source sibling condition, such as `/type == text`, also
selects LRANGE elements. Other element kinds remain unchanged. LSET argument 2
can similarly authorize LRANGE delivery when the write contract supports it.

## Evidence and limits

Bindings are scoped to the Case, API, endpoint, database, authenticated user,
Source key and its matched Target key. A fully matched write must have a
successful recorded response. The read must follow the original write on the
same Source connection, or start after its completion on another connection.
Its selected Source value must equal a bound Source write value. Conflicting
Target values for the same Source value are rejected. This is a bounded value
reference, not a general Redis emulator: expiration, deletion, list mutations,
request order and finite consumption keep their recorded contracts.

Null and error responses are unchanged and provide no positive read witness.
Selected JSON values must be non-null scalars. RESP responses and write values
are limited to 1 MiB, LRANGE to 1024 elements, RPUSH to 128 elements, declarations
to 16 per rule, JSON pointers to 32 per declaration, and runtime bindings to
4096 / 16 MiB. Public audits retain fingerprints and original write/read
identities; derived response evidence uses the existing protected witness store.
Shared, Global and snapshot inventory cannot gain read-back permissions.
Combining read-back with another time/value delivery owner on the same exchange
is rejected. Existing delivery overlap requires a separately reviewed policy change.

Use the ordinary coordinator transaction:

```text
backend-rewrite rule plan --file updated-rules.yaml --evidence <current-evidence-id>
backend-rewrite rule apply --plan <returned-plan-id>
```

Planning exercises complete Source traces and requires a positive successful
write-to-read witness for every new declaration. Source self-validation cannot
certify the Target. Applying this update retains a fresh genuine Replay
obligation and leaves original recordings unchanged.
