# HTTP JSON fields

HTTP request bodies use the same `json.fields` formats as responses, SSE data,
SQL JSON columns and Redis JSON values. Declare each path once, without an API,
endpoint, request effect, signing key or business model:

```yaml
format: traffic-policy/v2
json:
  fields:
    /metadata/request_id: {kind: identity, formats: [{hex: 8}]}
    /metadata/auth_token: {kind: identity, formats: [jwt]}
    /metadata/skill_identity_token: {kind: identity, formats: [jwt]}
```

A JWT is one complete token identity. The format checks its compact token shape;
comparison does not verify its signature, inspect claims or change token contents.
The internal case-local correspondence applies across all selected fields and
payloads: equal Source values require equal Target values, and distinct Source
values cannot collapse into one Target value. No binding declaration is needed.
The same mechanism applies to UUID, hexadecimal and base64url identifiers.

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
a fresh Replay. Global field formats do not require startup signing inputs.

Native `http_request` effects retain transport-specific query and multipart
contracts. Their former `json` field is rejected. If Replay actually modifies a
recorded input JWT before sending it to Target, the separate `input_jwt` rewrite
flow still owns its explicit key and re-signing operation.
