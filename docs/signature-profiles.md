# Signature profiles and API positions

Define a signing format once under `signatures`, then reference its name from
content formats or API positions. Algorithms and private key provenance are not
repeated in JSON field declarations:

```yaml
format: traffic-policy/v3
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}
  oidc: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: OIDC_STATE_SECRET_KEY}}
  aidesk: {kind: md5_sorted_fields, key: {kind: target_env, name: AIDESK_SECRET_KEY}}
json:
  fields:
    /access_token: {kind: jwt}
    /metadata/auth_token: {kind: jwt}
    /state: {kind: jwt, signature: oidc}
    /auth_url: {kind: url, formats: [url]}
    /nonce: {kind: identity, formats: [{base64url: 22}, {base64url: 43}]}
```

`kind: jwt` uses the explicit `default` profile when `signature` is omitted.
There is no inferred environment variable or fallback secret. Keys use existing
startup sources: `target_env`, or `target_file` with its path and field. Runtime
initialization resolves the required keys once into an immutable private
snapshot. Payload comparison performs no environment/file I/O, and reports do
not expose key bytes. Planning freezes the relevant key evidence and checks it
again before application.

## Automatic authentication comparison

Set `infer: true` on trusted JWT profiles to let Replay try those keys for
changed credentials. Each profile uses a startup key reference. Up to 16
profiles can participate, so different businesses can supply different keys.
An RS256 profile accepts a trusted RSA public key or a local JWKS snapshot.

```yaml
signatures:
  session: {kind: jwt, algorithm: HS256, infer: true, key: {kind: target_env, name: SECRET_KEY}}
  oidc: {kind: jwt, algorithm: HS256, infer: true, key: {kind: target_env, name: OIDC_STATE_SECRET_KEY}}
  dex: {kind: jwt, algorithm: RS256, infer: true, key: {kind: target_env, name: DEX_JWKS}}
```

Automatic comparison uses structured credentials from HTTP Authorization and
query values, Location URLs, and logical string values provided by installed
codecs. The source and target JWTs must verify under the same unambiguous
profile and agree on their protected headers and stable claims. NumericDates
use each side's observation clock. Parsed and verified tokens are cached in
the private key snapshot. URL query comparisons retain the unselected bytes.
Recognizable SigV4 presigned URLs can use built-in structure and time
comparison with no JWT profile.

An explicit rule retains ownership of its value, including authentication of
equal tokens and any companion fields. Automatic comparison authorizes no
credential rewriting. Request renewal and custom signed layouts retain their
explicit rules.

## Global JSON JWT verification

A declared JWT field verifies both signatures against its selected profile,
compares the protected headers, validates relative NumericDate claims and uses
the global field formats for decoded claim content. Undeclared claims remain
strict. The engine preserves complete-token correspondence as well as any
declared claim identity relationships: equal complete Source tokens require
equal complete Target tokens. A failed signature, stable claim, related field
or candidate comparison publishes no identity decisions.

Global formats also cover historical expired tokens and future `nbf` values.
Equal NumericDates pass after authentication without a clock; differing dates
must preserve the Source/Target request-time difference. Explicit API response
contracts retain their stronger checks for newly issued, currently valid tokens.

Recognized JWTs authenticate even when Source and Target bytes are equal.
Paired absence/nulls retain ordinary global optional-field semantics; malformed
or unsupported differing values cannot choose another key or algorithm.
Global JWT verification currently supports HMAC HS256/HS384/HS512. Global RS256
verification fails closed; recorded-public-key native RS256 assertions remain
available with their existing exact provenance. SQL key discovery is not part
of this profile authoring change.

The same declaration applies to supported JSON carriers, including dependency
requests/responses and SSE data. A generic `url` field reuses global formats for
decoded query parameters: `/state` above can therefore verify the state token
inside `/auth_url`. Unselected scheme, authority, path, query and fragment stay
exact. Nested JWT/URL protocol values inside authenticated JWT claims remain
exact; global verification does not recursively infer another signed protocol.

The old authored `{kind: identity, formats: [jwt]}` syntax is rejected. Use
`kind: jwt` and an explicit signature profile; there is no keyless JWT policy
mode. Missing keys and invalid signatures require fixing the declared inputs or
Target behavior. The complete-token identity representation remains internal
for authenticated token correspondence and delivery.

## Explicit inbound changes

Only declared API request positions authorize time translation and re-signing:

```yaml
api:
  '*':
    request:
      headers:
        authorization: {signature: default, scheme: bearer}
        x-wegent-download-token: {signature: default}
      query:
        token: default
        download_token: default
        state: oidc
  POST /api/internal/auth/aidesk/login:
    request:
      body:
        signature: aidesk
        fields: {source: /source, timestamp: /timestamp, username: /username}
        timestamp_pointer: /timestamp
        signature_pointer: /sign
        secret_parameter: secret_key
```

Header scheme defaults to raw; `bearer` selects its existing strict Bearer
parser. Query entries accept a profile name or an object with `signature` and
proposal `proof`. The `'*'` selector is allowed only for request positions;
specific entries use the ordinary method/path API selector. A missing or empty
profile reference selects the explicitly declared `default`, never a guessed key.

These positions lower to the existing `input_jwt` and
`input_signed_timestamp` owners. They preserve original-invalid-signature
behavior, invalid-authentication cases, relative validity, exact unselected
request content and private transformation witnesses. Merely recognizing a JWT
inside JSON does not authorize changing or re-signing it. A dependency read
cannot manufacture a new signed input from an unknown historical token.
The MD5 body layout stays at its API position because the field names and
secret parameter are part of that request's exact signed representation.

## Additional response relationships

Ordinary JSON token fields need only `json.fields` with `kind: jwt`. Do not
repeat them under every API when no additional protocol relationship applies.

Keep API-specific nonce echoes and expiry companions at their response
positions when those extra relationships are required:

```yaml
api:
  GET /api/auth/oidc/login:
    response:
      headers:
        location:
          signature: oidc
          query: state
          nonces:
            - pointer: /nonce
              format: {kind: base64url, decoded_bytes: 32}
              echo_query_param: nonce
  POST /api/smart-apps/*/download:
    response:
      json:
        /downloadUrl:
          signature: default
          query: token
          nonces:
            - pointer: /nonce
              format: {kind: base64url, decoded_bytes: 16}
          expires_at: /expiresAt
```

`query` selects the unique token-bearing URL parameter. Nonce formats and the
outer `echo_query_param` preserve the original independently checked nonce
copy. `expires_at`, optional `issued_at` and `ttl` retain the existing signed
expiry derivation checks. Header JWT positions cannot own body companion
fields. Response positions require a concrete method/path API selector; `'*'`
does not waive primary-response scope.

These declarations lower to the existing native response JWT contract. They
add causal/companion checks to global content formats; they do not replace
ordinary global JSON formats or permit extra headers, URL components or calls.
Header presence, multiplicity and order remain strict, including SDK metadata.
There is no header-absence waiver.

## Planning and limits

Annotated proposals put independent Source `proof` on each API position;
nonce evidence can inherit from its owning position. Runtime rendering removes
proof metadata. Generated IDs depend on resolved semantic contracts, not
explanation text. Unknown profiles, conflicting positions, case-insensitive
header duplicates and unsupported profile/position combinations reject before
execution. Existing native rules with extra constraints remain intact when
they cannot be represented losslessly by this compact syntax.

Use ordinary `rule plan --file … --evidence …` and
`rule apply --plan …`, then genuine Replay. Existing profile definitions cannot
be silently overwritten in an incremental plan: introduce a new name and
explicitly replace the affected positions. Editing the complete authored policy
reparses its API positions against its current definitions. Source self-checks,
private delivery copies and signature verification do not certify Target
behavior by themselves.

AES envelopes, multipart, DOCX and WSS path derivation use the
[content formats and carrier bindings](content-policy-layout.md). They are not covered by a signature profile or by
automatic JSON recognition.
