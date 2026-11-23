# Redis scalar formats

Structured JSON values always use the single root `json.fields` strategy.
Scalar stored values use bounded key patterns and the same format vocabulary,
without resource aliases or database selectors:

```yaml
redis:
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

For supported string and hash operations, Replay delivers the actual Target
bytes after a proven successful write, including timestamps stored inside JSON.
See [write-to-read delivery](redis-read-back.md).

Scalar formats and ordered commands can share the same `redis.keys` entry.
Initialization sharing is a
dependency lifetime under `localcache.requests`; JSON value fields stay global.
Actual endpoint/database/authentication partitions remain exact. See
[key declarations](redis-key-contracts.md) for the current syntax.
