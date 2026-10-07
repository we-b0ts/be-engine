# Redis value comparison and unordered rules

Replay recognizes JSON and Protobuf in the value argument of `SET`, `SETNX`,
`SETEX`, and `PSETEX`. It compares JSON objects by keys and values, independent
of object member order or formatting. This needs no rule. Nested arrays remain
ordered. Duplicate JSON members are rejected by semantic decoding, so they can
only match identical bytes. Unknown encodings retain byte matching. Semantic
value decoding is bounded to 1 MiB; larger values retain byte matching.

Protobuf uses the existing body decoder and typed repeated-field comparator.
Detection does not establish a schema or authorize repeated-field reordering.
Without an explicit rule, Protobuf values retain their wire identity. Raw bodies
and supported byte-array envelopes must use the same envelope on both sides.

All other command arguments remain exact, including the actual key, TTL, and
SET options. Commands, target, database, authentication, case/Global scope,
connection restrictions, source lane order, and finite consumption are retained.
A key pattern selects where a value rule applies; it never makes different keys
match each other. Recorded GET responses are replayed unchanged. Partial string
writes and collection-member writes do not use this comparator.

## Discovery, plan, apply, verification

Use the existing coordinator `dirty_clusters` evidence query. For Redis
mismatches it includes `facts.redis_unordered_candidates`, rule hints, and an
applicable `dependency_value` planner when bounded evidence is available.
Candidates describe an exact source endpoint/key, JSON Pointer or typed Protobuf
path, other collection differences, and fingerprints; they do not expose value
contents. Old reports require fresh Replay to collect these witnesses.

A witness requires an available exchange in the active case or Global with the
same target, command, session and all non-value arguments. The complete value
must differ only in discovered collection ordering. Candidates do not establish
that ordering is irrelevant: trace source construction and consumers. For
Protobuf, confirm the field numbers, element type and semantic name from source
schema; more than one wire-compatible type may appear in discovery.

```bash
backend-rewrite --target-root /path/to/target dependency-rule plan redis unordered \
  --evidence-id evidence-current --rule-id membership-ids \
  --host redis.example.test --port 6379 --key-prefix 'erp:membership:' \
  --json-pointer '/groups/*/ids' \
  --source-evidence 'service.py:216 IDs come from a set; consumers use membership lookup'
backend-rewrite --target-root /path/to/target dependency-rule apply PLAN_ID
```

The plan validates source proof, finalized Replay witnesses, and immutable source
exchanges, then shows the `.traffic-e2e/verification.yaml` dependency-rule diff.
Apply rejects changed policy, report, or recorded request/response evidence. It
uses the existing coordinator plan ID and verification invalidation, without
classifying the command as process-owned or rewriting traffic records. Run fresh
Replay afterward; applying a rule is not acceptance.

Selectors require an exact host and port plus one of:

- `--key KEY`: exact key.
- `--key-prefix PREFIX` and/or `--key-suffix SUFFIX`: byte affixes.
- `--numeric-key-pattern 'cache:<id>:members'`: one nonempty decimal digit segment,
  matching the existing process-owned Redis key-shape semantics.

For JSON, `--json-pointer ''` selects a root array; an entire `*` segment selects
array elements. Unselected arrays keep their order. Sorting preserves element
counts, duplicates, types and contents. Overlapping selector/path rules are
rejected to keep authorization unambiguous.

For Protobuf, replace `--json-pointer` with:

```bash
--protobuf-path '{"field_path":[3],"element_type":"string","display_path":"value.department_ids"}'
```

The rule uses the existing Protobuf repeated element types and compares each
selected collection as a multiset. Paths traverse nested messages; siblings and
unselected repeated fields retain their comparison behavior. Each plan adds one
field. Multiple independent field rules can be applied before fresh verification.

Example generated policy fragment:

```yaml
dependency_rules:
- id: membership-ids
  protocol: redis
  target: {host: redis.example.test, port: 6379}
  redis:
    key: {kind: affix, prefix: 'erp:membership:', suffix: ''}
    unordered:
    - field: {codec: json, pointer: '/groups/*/ids'}
      source_evidence: 'service.py:216 IDs come from a set; consumers use membership lookup'
```

In the `all-grouped` capability gap, the Redis value is a department-to-boolean
JSON object. Automatic JSON object comparison resolves that mismatch; no array
unordered rule is needed for that object.

Source-proven random ownership tokens use separate [Redis lock rules](redis-lock-rules.md).
These correlate SET NX values with recorded references while every other argument
remains exact; they do not use JSON/Protobuf collection normalization.

Source-proven UUID identities in PUBLISH payloads use separate
[Redis PUBLISH rules](redis-publish-rules.md), with exact channel and payload UUID
positions. Every other payload byte remains exact, including serializer framing.
