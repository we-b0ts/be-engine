# JWT request rules

Recorded JWTs can expire between capture and Replay. A `401` status mismatch
is a reason to investigate, not permission to bypass authentication. The
engine can preserve the original relative lifetime of a signed HMAC JWT while
leaving source/target authentication code and recorded artifacts unchanged.

## Coordinator workflow

For a response issue, run the coordinator-issued `jwt-time-validity` evidence
query. It checks the actual failed attempt, returns at most 20 candidate
observations with an omitted count, and never returns tokens or identities.
Candidates require actual HTTP 401, a different recorded status, a supported
Bearer JWT, and `exp` after recording but before Replay. Missing keys or
unverified signatures are not proof of expiry as the cause of the response.

The same evidence includes `signing_key_discovery`: effective target variable
names, captured startup mount paths with `writable` access modes, existing key
references, and commands to inspect those inputs again. It exposes no values
or file contents and works without a running target. The AI does not need to
guess which files are mounted. An unavailable input is labelled separately;
it does not suppress time evidence or other available key sources.

```bash
backend-rewrite --target-root /path/to/target startup env list
backend-rewrite --target-root /path/to/target startup mount list
```

For example, a returned `/app/.env` mount with `writable: false` permits the
file-source option below. A directory mount may contain that file. The field
name and whether environment values override dotenv still come from the
application's authentication and startup code; mount presence alone does not
select a signing key.

New HTTP response artifacts include `request_sent_at`. For older attempts,
the case-begin counter sample, or finally the attempt start, is used as an
explicitly labelled lower bound. Diagnosis never substitutes the current
time for the failed attempt's time.

Trace the source and target authentication path and actual expiration leeway,
then use the returned evidence id:

```bash
backend-rewrite --target-root /path/to/target rule plan \
  --request-kind jwt \
  --evidence-id <coordinator-evidence-id> \
  --rule-id session-jwt \
  --header authorization \
  --algorithm HS256 \
  --signing-key-ref session-jwt \
  --target-env SECRET_KEY \
  --jwt-leeway-seconds 60 \
  --source-evidence 'auth.rs validates session JWT with SECRET_KEY and 60s expiration leeway'
backend-rewrite --target-root /path/to/target rule apply <plan-id>
backend-rewrite --target-root /path/to/target next --api 'GET /api/example'
```

Use the leeway proven in the actual application, not the example value. Plan
verifies the original evidence signatures using the selected key, checks
expiration beyond that leeway, and scans the recording for global coverage.
Apply repeats those checks and rejects changes to the policy, evidence, key
bindings, or key value. The plan previews the policy section and key source;
it stores no raw secret. Reusing an existing binding needs no key-source flag.

Apply writes this policy section:

```yaml
request_rules:
  jwt:
    - id: session-jwt
      header: authorization
      scheme: bearer
      algorithm: HS256
      time: preserve_relative
      signing_key_ref: session-jwt
```

Rules apply across all APIs; they do not require an API list or initialization
changes. Apply invalidates API acceptance and returns the ordinary `next`
command. This is a Replay policy change: it requires real request execution
using existing recordings, not a fresh standard recording or offline
reclassification of old 401 responses. Existing workflow requirements for
Comparison remain in force.

## Signing key sources

`--target-env NAME` resolves the same merged source environment plus target
overrides that the engine passes to Docker. It does not read the engine's own
environment or assume the target is currently running.

When the application loads a mounted dotenv file itself, explicitly select:

```bash
--target-key-file /app/.env --target-key-field SECRET_KEY
```

The file must be in a declared read-only startup snapshot mount. There is no
implicit fallback from an environment variable to a dotenv field: the source
must agree with the application's configuration precedence. Imports performed
by application startup scripts are not automatically inferred.

The alias/source binding and a key-change verifier are stored in
`.traffic-e2e/local/secrets/jwt-signing-keys.json` (0600, parent 0700). The key
value stays in its existing target startup source; it is never copied into
verification YAML, plans, output, or CLI arguments. The recording AES key and
the application's JWT signing key are separate keys. A changed key requires
fresh plan/apply before request transformation.

## Replay semantics and bounds

At request send, the engine verifies the original signature and adds
`send_time - recorded_request_time` to each existing `exp`, `nbf`, and `iat`.
It preserves the JWT header, other claims, and the signing algorithm, then
signs with the verified key. The original recording is immutable. Response
and dependency values never drive the transformation.

HS256, HS384, and HS512 Bearer JWS are supported. The initial implementation
requires integer NumericDate claims. Encrypted JWT/JWE, asymmetric signing,
critical JWS extensions, cookies, and tokens derived inside the application
are outside this rule. Duplicate header values are rejected as ambiguous.
Malformed or unsupported tokens, unrelated Bearer credentials, and invalid
signatures are left unchanged. Valid signatures with unsupported time claim
representations produce an explicit diagnostic. Originally expired or
not-yet-valid tokens retain their relative invalidity; missing time claims
are never added. Multiple key-rotation rules may share a header/algorithm;
the first verifying rule transforms the original token once.

Actual response artifacts record rule ids, outcomes and offsets, without
tokens or claims. Finite recording-input Comparison transforms once before
the gateway fans the same request to source and candidate. Live Comparison
does not refresh frontend credentials. Forwarding or hashing the changed
token in downstream business calls can require additional compatibility
work; dependency verification remains strict.
