# Redis key declarations

Use `redis.keys` for bounded key-local formats and behavior, without API,
resource aliases or database selectors:

```yaml
redis:
  keys:
    'chat:streaming:text_block:*':
      kind: identity
      formats: [{prefix: text-, format: decimal}]
    'task:counter:*': {commands: [INCRBY, EXPIRE]}
    'task:events:*':
      commands:
        - operation: ZADD
          arguments:
            1: {kind: time, formats: [unix_seconds]}
    'request:*':
      key_format: {kind: identity, formats: [{hex: 32}]}
      commands: [SET]
localcache:
  requests:
    - redis: {operation: HGET, key: token_v2, field: '3061639762'}
```

`kind`/`formats` describe scalar values; complete JSON values are recognized
and use `json.fields`. `key_format` describes the wildcard segment of a key
and requires its ordered `commands` list. A time-window key uses
`key_format: {kind: time_window, seconds: 60}`. Command arguments are one-based
value positions after the key. Time arguments declare one format; the engine
infers equal Source instants internally without authored clock groups. EVALSHA
requires its exact `script: {sha1: ...}`; EVAL requires `script: {sha256: ...}`.
Scripts, numkeys, KEYS and unselected ARGV remain strict.

Finite Replay delivers the actual Target write bytes for supported string and
hash operations. See [Redis write-to-read delivery](redis-read-back.md).

Each recorded Redis call retains its own matching and delivery requirements,
including APPEND batch boundaries, EXPIRE calls and GETs that return nil. Actual
endpoint, database, authentication, protocol and causal ordering are checked
independently. See [Replay timers](replay-timers.md) for coordinating Target waits
with the recorded dependency sequence.

`localcache.requests` separately identifies finite process initialization reads.
It does not declare value formats or arbitrary reusable cache responses.
Source proof belongs on annotated plan declarations; runtime rendering omits
it. Use the normal `rule plan --file … --evidence …` transaction and fresh Replay.
The native semantic notes below describe additional derivations not covered by
the compact key syntax; their old commands and YAML are not current authoring.

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v3` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


Declare key differences only when Source code proves their generation.
These are Redis request contracts under version-three `dependency_rules`,
planned with `rule plan --dependency-request RULE_JSON`, applied through the
returned plan, and verified by fresh Replay. They use an exact endpoint,
database and inbound `case: {method, path}`. Published recordings stay unchanged.
Keys outside a declared contract keep byte equality.
An overlapping legacy `dynamic_values` capture cannot be combined with a key
contract on the same command; declare selected JSON references in that key
contract so comparison and correspondence commit stay atomic.

## Fixed time windows

```yaml
- id: counter-window
  protocol: redis
  case: {method: GET, path: /documents/*/file}
  target: {host: cache.internal, port: 6379}
  source_evidence: 'Limiter:check uses floor(current Unix seconds / 60) before authentication'
  redis:
    database: 0
    key: {prefix: 'rate:'}
    key_contract:
      kind: time_window
      window_seconds: 60
    commands:
    - command: INCRBY
      argument_values: {}
    - command: EXPIRE
      argument_values: {}
```

The default delimiter is `:` and the selected slot is the last segment.
An explicit `separator` and zero-based `segment_index` select another slot.
The window is a canonical integer computed from each side's own inbound
request clock, with the existing fixed inclusive five-second allowance for
generation delay and clock precision. A period must be 1..31536000 seconds;
there are at most 64 segments. Missing clocks, stale windows, noncanonical
integers and changed static segments fail even if the two keys are equal.

Only INCRBY and EXPIRE are selected. The increment, TTL and all other arguments
remain exact. The command list preserves per-key order and requires the same
target key throughout the sequence, including at a clock boundary. MULTI and
EXEC remain ordinary finite, ordered recording exchanges; the rule does not
execute Redis or bypass transaction/connection ownership. This contract is for
windows computed near inbound admission, rather than arbitrarily delayed jobs.

## Generated key identities and JSON references

```yaml
- id: session-write
  protocol: redis
  case: {method: POST, path: /devices/*/session}
  target: {host: cache.internal, port: 6379}
  source_evidence: 'Session:create generates an 18-byte URL-safe nonce, stores it in key and JSON, and sets expiry from current time'
  redis:
    database: 0
    key: {prefix: 'sessions:'}
    key_contract:
      kind: capture
      template: 'sessions:{value}'
      format: {kind: base64url, bytes: 18}
    commands:
    - command: SET
      argument_values:
        1:
          json:
            /session_id:
              identity: {template: '{value}'}
            /expires_at: {time: preserve_relative, format: rfc3339}
```

A key template has one `{value}` slot with fixed affixes. Supported shapes are
canonical unpadded `base64url` with an explicit decoded byte count, lowercase
`hex` with an explicit byte count, and canonical `uuid_v4`. Byte counts are
1..256. Shape does not prove randomness or hash generation; provide Source proof.

The key and selected JSON identity fields are verified together. An identity
reference may add fixed affixes, such as `session-{value}`. The JSON time rule
uses its existing independently captured inbound anchors and preserves the
recorded expiry offset. Other JSON members, presence, scalar types, arrays,
SET options and TTL remain exact. Null, missing and empty values do not collapse.

Correspondence commits only when the complete exchange matches and consumes its
recorded response. A failed key, JSON field, time, TTL or stable argument commits
nothing. Reusing a Source identity with a different target identity, or collapsing
distinct Source identities onto one target identity, fails. Correspondence is scoped to
the replay case; a later case starts fresh.

A later SET can capture another key identity while referencing the earlier
session value in its JSON. For example, a digest-shaped ticket key can use
`format: {kind: hex, bytes: 32}` while its `/session_id` field references
the same Source value. A captured digest is an opaque identity: the format alone does
not verify the preimage. If the preimage is already bound, an explicit reference
can instead verify SHA256 derivation:

```yaml
key_contract:
  kind: reference
  template: 'session-hash:{value}'
  transform: sha256
```

JSON references also accept `transform: sha256`. A reference always requires a
previous committed capture or a capture in the current successfully validated
request; it cannot introduce an unrelated identity.

## Evidence, planning and audit

Failed SET/INCRBY/EXPIRE key comparisons expose bounded
`redis_key_request` candidates. Discovery gives command/endpoint selectors and
fingerprints, without inferring generation or leaking new key/token values.
Complete target argument witnesses are encrypted using the existing project
recording key. Plan verifies the protected current witness against a complete,
same-case Source exchange and every declared stable field. Apply rechecks
evidence and policy identity and requires fresh Replay.

For native key references whose evidence depends on an earlier committed capture,
apply that capture and Replay before planning the dependent key reference.
Ordinary global JSON and scalar MySQL identity formats infer correspondences
from complete typed values internally; they do not require staged key planning. Reports retain native `key_bindings` as case/endpoint/name
and Source/target fingerprints, without plaintext identities. A later plan can
check its reference against that committed evidence. It cannot change or collapse
an existing pair. Rule audits count matched captures and references separately.

Authentication, database, case ownership, connection/transaction lanes and
finite consumption are enforced by the ordinary Replay matcher. Extra SETs,
changed prefixes, identity mismatches and reordered/duplicate commands remain
failures. These rules do not accept target-only writes or generated responses.
