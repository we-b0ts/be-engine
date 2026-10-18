# Signed timestamp request rules

A recorded custom login signature can expire with its JSON timestamp. The
`input_signed_timestamp` effect verifies the original signature with a private
startup key, shifts the timestamp by `send_time - recorded_request_time`, then
signs the delivery copy. It preserves the original clock offset: an originally
expired or future request stays equally expired or future. It never changes
application authentication, recordings, response assertions or dependencies.

Submit a self-contained proposal through the ordinary coordinator
`rule plan --file ... --evidence ...` and `rule apply` workflow. Source review
must establish the exact signature recipe, timestamp representation, trimming
and startup key source. Plan verifies complete immutable Source requests and
freezes the private signing-input witnesses. Apply requires fresh Replay;
Source signature self-validation cannot certify a Target response.

```yaml
id: login-signed-time
match:
  api: POST /login
effect:
  kind: input_signed_timestamp
  algorithm: md5_sorted_fields
  fields:
    source: /source
    timestamp: /timestamp
    username: /username
  timestamp_pointer: /timestamp
  signature_pointer: /sign
  secret_parameter: secret_key
  signing_key:
    kind: target_env
    name: LOGIN_SECRET
  time: preserve_relative
proof:
  source: source/login.py:verify_signature
  fact: The application checks the timestamp window and the MD5 of sorted trimmed fields plus its startup secret.
```

This bounded algorithm uses 1..8 named JSON string fields, sorted by ASCII
parameter name. It trims each value, joins `name=value` pairs with `&`, appends
`&secret_parameter=<startup secret>`, then computes lowercase MD5 hex. Signature
comparison accepts uppercase hex as the Source contract does. The timestamp
must be a decimal integer string in Unix seconds. The secret can also use an
explicit `target_file` reference within a declared read-only startup mount.
No secret value belongs in the proposal or command arguments.

An explicit API scope is mandatory. `when` tests the immutable Source body.
Pointers must be exact and disjoint; the signature and all signed input fields
are protected from overlapping input rules. UTF-8 and base64 JSON envelopes are supported; duplicate
JSON members, truncated bodies and unsupported shapes are never re-signed.
Invalid original signatures remain unchanged. Only the selected timestamp and
signature values change. A separately signed response token still requires its
own `response_jwt` contract with the application's actual key and stable claims.
