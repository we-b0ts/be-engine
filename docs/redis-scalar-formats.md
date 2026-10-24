# Redis scalar formats

Structured JSON values always use the single root `json.fields` strategy.
Scalar stored values use physical key patterns and the same format vocabulary:

```yaml
redis:
  database: 0
  keys:
    'device:identity-lock:*': {kind: identity, formats: [{hex: 32}]}
    'task-run-monitor:v2:as-of': {kind: time, formats: [unix_seconds]}
```

The engine maintains complete typed Source-to-Target identity correspondences
inside each case. A matched write can establish one; later physical keys,
opaque EVAL/EVALSHA ARGV and DELEX IFEQ values may consume an established pair.
Script contents are never interpreted. Failed candidates publish no identities.

Commands, script bytes, numkeys, KEYS, TTL modes/options, lane order and finite
inventory retain their protocol checks. Relative TTLs remain exact. Protocol
absolute expiry parameters preserve remaining lifetime against independent
Source and Target request clocks without a user-authored time field.

Successful JSON writes also retain bounded temporal counterparts at their exact
physical key/container/hash field. A later read can reuse one only when the
Source value agrees, both request timelines follow the completed write, and the
Target counterpart is unambiguous. Immutable recordings remain unchanged.
