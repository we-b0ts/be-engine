# Signed JWT response rules

An HTTP JSON response can contain a newly signed JWT such as `/access_token`.
Recording and Replay occur at different times, so a correctly generated token
can differ in its time claims and signature. An explicit `jwt` response rule
validates that signed contract instead of requiring identical encoded tokens.
Do not use `random` or `timestamp` to exempt the complete JWT string.

```yaml
response_rules:
  json:
    "POST /api/session/token":
      jwt:
        - pointer: /access_token
          algorithm: HS256
          signing_key_source:
            kind: target_env
            name: SECRET_KEY
          source_evidence: 'Connector:issue signs stable identity claims with a 30-minute expiry'
```

Trace the source's generator and configuration precedence before choosing the
algorithm, key source, or dynamic claims. The field name `access_token` alone
does not prove that a credential is a JWT. Representative evidence offers
`response_jwt` guidance when it contains a compact HMAC JWT candidate and
projects `signing_key_discovery` without secret values. A decoded candidate is
not proof of a valid signature or source semantics.

## Plan, apply, verify

Use the coordinator-issued evidence for the selected API. Choose its HTTP
method from recorded inventory; the route name does not determine the method:

```bash
backend-rewrite --target-root /path/to/target rule plan \
  --evidence-id <current-evidence-id> \
  --response-jwt '{"pointer":"/access_token","algorithm":"HS256","signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"source_evidence":"Connector:issue signs stable claims and a 30-minute expiry"}'
backend-rewrite --target-root /path/to/target rule apply <plan-id>
```

The planner verifies both source and target signatures, stable claims and time
relationships against complete, current-policy focused-E2E or Comparison
evidence. Every selected rule needs an observed token difference. Unrelated
response differences remain failures. Source changes cannot authorize a rule.
Apply rechecks the policy, referenced artifacts and private signing input;
changes require fresh evidence and planning. The workflow invalidates previous
acceptance and requires fresh execution using existing recordings. Offline
planning does not turn old failed responses into successful runs.

## Comparison contract

- HS256, HS384 and HS512 compact JWS are supported. Both signatures must verify
  with the declared startup key and algorithm. Unsupported algorithms,
  duplicate JSON members, critical extensions and malformed tokens fail.
- Decoded headers and all stable claims must agree exactly, including identity,
  audience, issuer, roles and scopes. JSON member order is irrelevant; array
  order and claim presence stay strict.
- `exp` is required and must be after each token's own request start. Existing
  `iat` and `nbf` retain presence and cannot be more than five seconds in the
  future. Each time claim preserves its offset from its own request start
  within an inclusive five-second tolerance. There is no wall-clock fallback,
  configurable tolerance or rewriting of tokens. NumericDate claims must be
  integers. Replay uses recorded `request.json.timestamp` and actual
  `request_sent_at`; Comparison uses each capture's request-start `timestamp`.
- `dynamic_claims: [/jti]` explicitly permits a UUID v4 nonce. Repeated selected
  values retain one consistent bijective source/target mapping inside each
  response; array selectors such as `/items/*/access_token` share that mapping.
  Other dynamic claims are rejected. Without this declaration, `jti` is exact.
- Missing fields, JSON types, array structure, status, headers and other
  response values remain checked. A selector absent on both sides is
  inapplicable. Overlapping JWT, random, timestamp or other subtree rules fail
  policy validation.

Signing keys use the existing startup-input references. `target_env` selects
the effective target environment, not the engine's environment. A mounted
dotenv file can use
`{kind: target_file, path: /app/.env, field: SECRET_KEY}` only within a declared
read-only startup mount. Keys stay in private memory and are never written to
plans, policy previews or diagnostics. Assertion differences report a pointer
and reason without token or claim values. JWE and asymmetric algorithms remain
outside this contract.

This rule compares an HTTP response only. Inbound credential translation uses
[JWT request rules](jwt-request-rules.md); generated JWTs sent in Redis writes
use [dependency request contracts](dependency-request-rules.md).
