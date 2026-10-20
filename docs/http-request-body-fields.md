# Generated HTTP dependency request fields

An explicit native `http_request` effect can validate selected JSON body fields
without changing the request, recording, or delivered dependency response.
Use it for Source-proven generated request identifiers and HMAC JWTs.

```yaml
id: chat-request-fields
match:
  api: POST /tasks
  resource: {protocol: http, endpoint: 'chat.example:8100'}
  operation: POST
  path: /v1/responses
effect:
  kind: http_request
  json:
    /metadata/request_id: {kind: random, format: hex, length: 8}
    /metadata/auth_token:
      kind: jwt
      algorithm: HS256
      signing_key: {kind: target_env, name: SECRET_KEY}
    /metadata/skill_identity_token:
      kind: jwt
      algorithm: HS256
      signing_key: {kind: target_env, name: SECRET_KEY}
proof:
  source: src/client.rs:build_request
  fact: The client generates the request ID and signs both tokens from this request's clock.
```

Each field may supply its own inline proof. Pointers must be exact, non-root,
nonoverlapping JSON Pointers; at most 32 fields may be selected. Missing fields,
duplicate JSON members, malformed or over-budget JSON fail closed. The request
endpoint, method, path, query, headers, unselected body fields, and finite
dependency consumption retain their existing checks.

Random fields validate both Source and Target values against their declared
encoding and exact length. They do not create a cross-request identity binding.
Use a native `identity` rule when later dependencies must reference that value.

JWT fields support HS256, HS384, and HS512. These algorithms use a symmetric
HMAC secret, not an asymmetric private key. The secret is resolved privately from
an explicit existing Target startup environment or a declared read-only startup
file. It never enters policy, plans, diagnostics, or Target request rewriting.
Both Source and Target signatures must verify using the selected startup input;
algorithm, signed headers, and stable claims must agree.

`exp` is required; `iat` and `nbf` retain their presence and types. Each timestamp
must preserve its offset from its own physical dependency request start within
the existing five-second bound. Historical Source tokens are evaluated at their
recorded request clock, not at current wall time. No synthetic JSON timestamp
anchor is required, and an authored `anchor` is rejected.

Optional explicit `nonces` use the existing typed UUID-v4/base64url nonce claims
and staged case-local bijections. Without such a declaration every non-time
claim remains exact. A failed field or unselected business-field difference
commits neither bindings nor rule usage and cannot consume an exchange.

Signature validation always reads the original signed bytes before identity
normalization. After field validation, only the selected fields are masked in
private comparison copies. Ordinary strict body matching and any nonoverlapping generic JSON time
or unordered rules compare the remainder. This composes with existing native
HTTP identity bindings. Overlapping ownership or incompatible body codecs are
rejected before Replay.

## Planning and verification

Use the existing unified `rule plan --file ... --evidence ...` / `rule apply`
transaction. Source preflight exercises the original complete body, validates
every declared field, and freezes signing-input witnesses. Changed startup keys
invalidate a pending plan. Source self-validation retains the obligation for a
fresh genuine Target Replay; it cannot establish Target correctness.

Recordings containing complete HTTP request bodies, dependency clocks, and the
original startup signing input can be reused. Missing or truncated bodies and
unavailable signing inputs remain evidence errors.

Validation includes `cargo test http_json_jwt`, `cargo test http_body_jwt`, and
`cargo test policy::native_compile::tests::http_request`.
