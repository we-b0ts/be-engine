# Redis keys and value formats

Declare decoded JSON fields once in root `json.fields`, regardless of the API,
Redis command, key, argument number or read/write direction:

```yaml
json:
  fields:
    /id: {kind: identity, formats: [uuid]}
    /headers/id: {kind: identity, formats: [uuid]}
    /properties/correlation_id: {kind: identity, formats: [uuid]}
    /timestamp: {kind: time, formats: [unix_seconds, unix_milliseconds]}
    /items: {kind: unordered}
```

The engine detects complete JSON values in supported Redis value positions,
including SET, HSET, list elements, PUBLISH and complete script ARGV values.
Unknown bytes remain exact. JSON objects reject duplicate member names. Scripts,
script digests, key counts, hash fields, list indexes, command options and
unselected values remain subject to their ordinary protocol comparison.

Both absent fields pass; a field present on only one side fails. Both null values
pass. Exact equality is implicit, so fields do not need `null`, `literal` or
`exact` format alternatives. Time fields compare request-relative differences.
Numeric units are selected from immutable Source evidence, never by trying
Target alternatives until one passes.

## Scalar values selected by key

For a value that is a plain scalar, declare its format under `redis.keys`:

```yaml
redis:
  database: 0
  keys:
    task-run-monitor:v2:as-of: {kind: time, formats: [unix_seconds]}
    device:identity-lock:*: {kind: identity, formats: [{hex: 32}]}
    chat:streaming:text_block:*: {kind: identity, formats: [{prefix: text-, format: decimal}]}
```

These entries select scalar formats. They do not declare an application lock,
a business model, a Lua program or an extra command sequence. Database selection
is shared by the key map. Structured JSON values use the global JSON map instead
of repeating fields for each key.

## Identity consistency

The engine owns one bounded, case-local correspondence between complete typed
Source and Target identity values. Equal Source values must have equal Target
values across JSON fields, scalar values and protocol key positions. Distinct
Source values cannot collapse to one Target value. Prefixes remain part of the
identity; a JSON string and a JSON number are distinct values.

A successful SET may establish a scalar identity. A later EVAL/EVALSHA ARGV or
DELEX IFEQ value can consume that already established complete-value relation.
The engine does not need to recognize a lock or interpret the Lua script. Script
bytes, keys, options, TTLs, source lanes and finite invocation counts remain
checked. Failed matching candidates never publish an identity relation.

## Signed JSON values

Signature-bearing fields also belong to the global content strategy:

```yaml
json:
  fields:
    /data/*/plugins/*/download_path: {kind: url, formats: [aws_sigv4]}
    /access_token:
      kind: jwt
      formats:
        - algorithm: HS256
          signing_key: {kind: startup, source: {kind: target_env, name: SECRET_KEY}}
          nonces: [{pointer: /jti, format: {kind: uuid_v4}}]
```

Source token metadata selects the signature format. A changed Target token must
satisfy that algorithm, the frozen selected key, claim checks and nonce identity
consistency. Optional nonce claims are selected from Source presence. Other
claims remain strict. Declared signed companion fields retain their relationship
to the token, including in derived cached deliveries. Key bytes stay private.

AWS SigV4 URL comparison validates its declared date/signature shape and strict
URL remainder; without the signing secret it does not authenticate the S3 HMAC.

## Protocol behavior

Relative Redis TTLs compare exactly. Absolute expiration timestamps use their
native protocol units and independent request clocks. No TTL rule is required.

JSON reads can reuse times from an accepted earlier write at the same physical
key/container/hash field. This requires successful delivery and ordering proof
on both Source and Target. An unpublished, ambiguous or future write cannot
supply a cached time. This mechanism does not grant extra reads or mutations.

Rules that authorize finite shared initialization reads, known stream chunking,
read commutation or expiry refresh remain under `redis.rules`. They describe
recording/replay admission differences and do not duplicate JSON field formats.
There is no authored `redis_lock` effect or separate lock-token state machine.

Use the ordinary `backend-rewrite rule plan --file … --evidence …` and
`rule apply <plan-id>` transaction for policy changes. Applying a format strategy
retains the obligation to run genuine Target replay; derived deliveries do not
count as independent Target evidence. Recordings remain immutable.
