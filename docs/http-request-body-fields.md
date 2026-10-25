# HTTP JSON fields

HTTP request bodies use the same `json.fields` formats as responses, SSE data,
SQL JSON columns and Redis JSON values. Declare each path once, without an API,
endpoint, request effect or business model. JWT fields reference named profiles:

```yaml
format: traffic-policy/v2
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}
json:
  fields:
    /metadata/request_id: {kind: identity, formats: [{hex: 8}]}
    /metadata/auth_token: {kind: jwt}
    /metadata/skill_identity_token: {kind: jwt}
```

`kind: jwt` uses the explicit `default` signature profile, or a named
`signature` reference. A frozen key context verifies HMAC signatures and relative
NumericDates; stable claims and globally declared claim formats remain checked.
The internal correspondence applies to the complete token across carriers:
equal Source tokens require equal Target tokens. Recognized equal JWTs still
authenticate. The old authored identity `formats: [jwt]` syntax is rejected;
there is no keyless JWT policy mode. See
[signature profiles](signature-profiles.md).

Equal scalar values pass directly. Unknown scalar formats remain exact. A field
missing on both sides is irrelevant; a field present on only one side differs.
Null is exact and creates no timestamp or identity observation. Unselected JSON
fields, array contents and native HTTP endpoint, method, query, headers and finite
exchange consumption keep their existing comparisons.

Time and array ordering use the same global section:

```yaml
json:
  fields:
    /requested_at: {kind: time, formats: [unix_seconds]}
    /tools: {kind: unordered}
```

Use unified `rule plan --file ... --evidence ...` and `rule apply`. The transaction
checks the complete Source scope and protected Target observations, then requires
a fresh Replay. Verified JWT fields require their explicitly declared startup
signing profile; ordinary time/identity fields do not.

Native `http_request` effects retain transport-specific query and multipart
contracts. Their former `json` field is rejected. Only the declared `api` request
header/query/body positions authorize input time translation and re-signing;
those positions reuse the existing strict native transformation owner.
