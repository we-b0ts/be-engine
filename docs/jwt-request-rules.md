# JWT request rules

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v1` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


Recorded JWTs can expire between capture and Replay. A `401` status mismatch
is a reason to investigate, not permission to bypass authentication. The
engine can preserve the original relative lifetime of a signed HMAC JWT while
leaving source/target authentication code and recorded artifacts unchanged.

## Coordinator workflow

For a response issue, run the coordinator-issued `jwt-time-validity` evidence
query. It checks the actual failed attempt, returns at most 20 candidate
observations with an omitted count, and never returns tokens or identities.
Candidates require a failed response assertion, a supported bearer-header,
raw-header or named-query-parameter JWT, and `exp` after recording but before
Replay. Recorded 401/403 responses are excluded. The target status is not an
expiry gate: an application can render a failed-login HTML page with 200, or
an earlier dependency can fail with 503 before authentication runs. These are
time observations, not proof of authentication causality. Source review,
signature verification, configured leeway and fresh execution remain required.

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
backend-rewrite --target-root /path/to/target next --api '/api/example'
```

For a source contract that carries the token directly in a URL query parameter,
replace `--header authorization` with `--query-param download_token`. The
planner binds the evidence to that exact parameter name; header and query
selectors are mutually exclusive.

For a compact JWT carried directly in a custom header, use
`--header x-download-token --header-scheme raw`. The generated policy uses
`header: x-download-token` and `scheme: raw`; the runtime replaces only that
single header value without adding a Bearer prefix. Header names remain
case-insensitive; multiple values, unsupported schemes and ambiguous selectors
are rejected. Expired-at-recording and invalid-signature inputs retain their
failure behavior. Raw-header evidence uses `raw_header` to distinguish its
representation from bearer evidence, and generated planner commands preserve it.

Custom JWT headers contain credentials. Projects must include their configured
names in `recording.redact_headers` so existing recording encryption applies.
The engine does not guess project-specific credential header names.

Use the leeway proven in the actual application, not the example value. Plan
verifies the original evidence signatures using the selected key, checks
expiration beyond that leeway, and scans the recording for global coverage.
Apply repeats those checks and rejects changes to the policy, evidence, or key
value. The plan previews the policy section and key source; it stores no raw
secret.

Apply writes this policy section:

```yaml
request_rules:
  jwt:
    profiles:
      session:
        signing_key_ref: session-jwt
        signing_key_source:
          kind: target_env
          name: SECRET_KEY
        algorithm: HS256
        time: preserve_relative
    rules:
    - id: session-bearer-header
      header: authorization
      scheme: bearer
      profile: session
```

Header and query selectors can share the same profile. For example, the same
session key can also transform a download token without duplicating the key
reference, source, algorithm, or time policy:

```yaml
request_rules:
  jwt:
    profiles:
      session:
        signing_key_ref: session-jwt
        signing_key_source:
          kind: target_env
          name: SECRET_KEY
        algorithm: HS256
        time: preserve_relative
    rules:
    - id: download-jwt
      query_param: download_token
      profile: session
```

Rules apply across all APIs; they do not require an API list or initialization
changes. Apply invalidates API acceptance and returns the ordinary `next`
command. This is a Replay policy change: it requires real request execution
using existing recordings, not a fresh standard recording or offline
reclassification of old 401 responses.

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

The profile's `signing_key_source` is a reviewed pointer to the target startup
input; it does not contain the key value. It is persisted in
`verification.yaml`, which is the sole configuration the request runtime uses
to locate the key. The key value stays in its existing target startup source;
it is never copied into verification YAML, plans, output, or CLI arguments. The
recording AES key and the application's JWT signing key are separate keys. A
changed key or source requires fresh plan/apply before request transformation.

## Replay semantics and bounds

At request send, the engine verifies the original signature and adds
`send_time - recorded_request_time` to each existing `exp`, `nbf`, and `iat`.
It preserves the JWT header, other claims, and the signing algorithm, then
signs with the verified key. The original recording is immutable. Response
and dependency values never drive the transformation.

HS256, HS384, and HS512 JWS are supported in either a Bearer header or one
named query parameter. Query replacement changes only the selected raw value;
parameter order, unrelated percent encoding, and the URI fragment remain
byte-for-byte unchanged. Duplicate matching query parameters fail as
ambiguous. The initial implementation requires integer NumericDate claims.
Encrypted JWT/JWE, asymmetric signing,
critical JWS extensions, cookies, and tokens derived inside the application
are outside this rule. Duplicate header values are rejected as ambiguous.
Malformed or unsupported tokens, unrelated Bearer credentials, and invalid
signatures are left unchanged. Valid signatures with unsupported time claim
representations produce an explicit diagnostic. Originally expired or
not-yet-valid tokens retain their relative invalidity; missing time claims
are never added. Multiple key-rotation rules may share a token
location/algorithm; the first verifying rule transforms the original token
once.

Actual response artifacts record rule ids, outcomes and offsets, without
tokens or claims. Forwarding or hashing the changed token in downstream business
calls can require additional compatibility work; dependency verification remains strict.
