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
  keys:
    task-run-monitor:v2:as-of: {kind: time, formats: [unix_seconds]}
    device:identity-lock:*: {kind: identity, formats: [{hex: 32}]}
    chat:streaming:text_block:*: {kind: identity, formats: [{prefix: text-, format: decimal}]}
```

These entries select scalar formats. They do not declare an application lock,
a business model or a Lua program. Key patterns have no resource/database
selectors; actual physical Source/Target identity remains checked. Ordered
commands and key-local behavior can be declared on the same entry when Source
proves them. Structured JSON values use the global JSON map.

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

## Tokens and URL values

Verified tokens reference the shared root signing profiles:

```yaml
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}
json:
  fields:
    /access_token: {kind: jwt}
    /metadata/auth_token: {kind: jwt}
    /authorize_url: {kind: url, formats: [url]}
    /session_id: {kind: identity, formats: [uuid]}
    /data/*/plugins/*/download_path: {kind: url, formats: [aws_sigv4]}
```

`kind: jwt` defaults to the explicit `signatures.default` profile. It verifies
HMAC signatures, relative NumericDates and stable/declared claim content using
a frozen private key context. Complete Source-equal tokens require complete
Target-equal tokens across carriers. Global RS256 currently rejects; exact
native recorded-public-key assertions remain available. Old authored identity
`formats: [jwt]` is rejected; a JWT field needs its named verification profile.

Generic `url` comparison reuses global field formats for decoded query text
values and keeps unselected URL bytes exact; it needs no business URL template
or binding name. AWS SigV4 comparison checks date/signature shape and strict
URL remainder, without claiming to authenticate its HMAC without the secret.

API request positions explicitly authorize re-signing. Additional response
nonce echoes and signed expiry companions retain their API-position declarations
and existing native checks. See [signature profiles](signature-profiles.md).
Multipart, DOCX, WSS path derivation and AES envelopes retain their typed owners.

## Protocol behavior

Relative Redis TTLs compare exactly. Absolute expiration timestamps use their
native protocol units and independent request clocks. No TTL rule is required.

JSON reads can reuse times from an accepted earlier write at the same physical
key/container/hash field. This requires successful delivery and ordering proof
on both Source and Target. An unpublished, ambiguous or future write cannot
supply a cached time. This mechanism does not grant extra reads or mutations.

Key-local APPEND, read commutation, expiry refresh and current-identity
read-back behavior belong under `redis.keys`. Finite process initialization
reads belong under `localcache.requests`; actual process tasks use
`process_dependencies.tasks.<Source-task-name>.requests`. HTTP lifetime entries
require an explicit host. These lifetimes do not duplicate value formats.
There is no authored `redis_lock` effect or separate lock-token state machine.

Use the ordinary `backend-rewrite rule plan --file … --evidence …` and
`rule apply --plan <plan-id>` transaction for policy changes. Applying a format strategy
retains the obligation to run genuine Target replay; derived deliveries do not
count as independent Target evidence. Recordings remain immutable.
