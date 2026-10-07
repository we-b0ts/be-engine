# Redis PUBLISH UUID identity rules

PUBLISH payloads can contain source-proven random publisher identities such as
`uuid4().hex`. Exact argument matching rejects the target's new identity. A
PUBLISH rule selects a textual UUID v4 by an exact field marker, or by its
zero-based position among UUIDs, on one exact host, port and channel. The rule binds each
recorded identity to one target identity and preserves distinct identities.
Repeated messages from the same recorded publisher must use the same target UUID.

Replay scans bounded byte payloads rather than executing or interpreting a
message serializer. JSON, MessagePack and pickle payloads containing textual
UUIDs can use the same rule. Hex and dashed UUID forms are supported; source and
target must retain the same byte layout and UUID representation. Binary UUID
values, other UUID versions, variable-width replacements and arbitrary dynamic
fields are outside this capability. The channel, every unselected byte, Redis
session identity, source lane order and finite consumption remain strict.

Use finalized `dirty_clusters` evidence to inspect
`facts.redis_publish_candidates`. A candidate proves that the payload differs
only at one UUID position; it does not prove that this location is semantically
random. Trace that position's generation and lifetime in source. Candidate
reports contain fingerprints and selectors, not payloads or UUID values. Old
reports require fresh Replay to collect these witnesses.

```sh
backend-rewrite --target-root /path/to/target dependency-rule plan redis publish \
  --evidence-id evidence-current --rule-id publisher-identity \
  --host redis.example.test --port 6379 --channel socketio --uuid-field host_id \
  --source-evidence 'publisher.py:host_id uses uuid4().hex once per publisher'
backend-rewrite --target-root /path/to/target dependency-rule apply PLAN_ID
```

Each plan requires a same-case UUID-only mismatch witness and immutable source
exchange verification. Apply rechecks the policy, source exchanges and finalized
report, then invalidates verification and requires fresh Replay. It retains
request ownership. It neither changes recordings nor ignores the whole argument.

Generated policy:

```yaml
dependency_rules:
  - id: publisher-identity
    protocol: redis
    target: {host: redis.example.test, port: 6379}
    redis:
      publish:
        channel: socketio
        uuid_field: host_id
        source_evidence: 'publisher.py:host_id uses uuid4().hex once per publisher'
```

`--uuid-field` requires one unique ASCII identifier marker in each payload. The
selected UUID must follow it within eight non-word bytes, covering ordinary
JSON field delimiters and compact binary string framing. Other UUIDs can precede
the field, and the field can move between messages; they remain exact. Duplicate
markers, embedded identifier fragments and non-UUID field values are rejected.
For another fixed layout, use `--uuid-index` instead. These selectors are mutually
exclusive. Fields are byte markers, not a general serializer or JSON Pointer.

Payloads are limited to 1 MiB and 32 textual UUIDs. Distinct positions can have
separate rules; overlapping selectors are rejected. Index and field selectors
cannot be mixed on the same channel. Ambiguous runtime positions fail matching.
Failed previews and lane blockers do not bind UUIDs. Ordinary PUBLISH uses a
pooled connection; a lane containing transaction, subscription or retained
session state still requires its original physical connection affinity.

`cargo test redis_publish` covers real RESP plan/apply, JSON and binary payloads,
multiple sockets, strict channel/content checks, identity consistency, distinct
publishers, lane blockers, stale evidence and finite consumption.
