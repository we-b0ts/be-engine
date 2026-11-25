# Traffic E2E Recorded Case Format

Use this reference when parsing recorded artifacts, driving target requests,
or diagnosing recorder-owned dependency replay.

## Contents

- Directory and files
- HTTP boundary files
- Body capture

## Directory And Files

Canonical published case layout:

```text
recordings/<run-id>/traffic.jsonl
recordings/<run-id>/recording-run.json
recordings/<run-id>/recording-network.json
recordings/<run-id>/errors.jsonl
recordings/<run-id>/global-dependencies.jsonl
recordings/<run-id>/global-dependencies-summary.json
recordings/<run-id>/global-dependencies-debug.jsonl
recordings/<run-id>/apis/<api-directory>/<case-id>/request.json
recordings/<run-id>/apis/<api-directory>/<case-id>/expected-response.json
recordings/<run-id>/apis/<api-directory>/<case-id>/dependencies.jsonl
recordings/<run-id>/apis/<api-directory>/<case-id>/dependencies-summary.json
recordings/<run-id>/apis/<api-directory>/<case-id>/dependencies-debug.jsonl
recordings/<run-id>/failed/<api-directory>/<case-id>/
```

Each recorder process creates one `YYYYMMDDHHMMSS` run directory. Do not scan
`failed`, `staging`, or `.replay` as case collections. Failed case directories
may contain `.partial`, `.truncated`, and `recording-error.json` files. They are
evidence for recorder configuration or recorder implementation fixes, not E2E
replay fixtures.

`recording-network.json` is the required Replay network boundary. It contains
the deduplicated DNS names resolved during recording and the exact `host:port`
endpoints actually accessed through the recording gateways. During Replay, an
unrecorded domain may resolve to a quarantine fake IP and the target may open a
TCP connection to it. DNS resolution and connection establishment alone are
not dirty. If the target sends payload bytes to an endpoint absent from this
manifest, Replay closes the connection and reports
`访问了录制时没有访问过的域名:port` in evidence. Do not reconstruct this
allowlist from `dependencies.jsonl`; re-record runs created before this artifact
existed.

`uri-group` is usually built from the full request URI path joined by hyphens,
for example `/api/users/list` becomes `api-users-list`. When the global HTTP
policy defines `case_path_patterns`, the matching pattern defines the group instead.
`*` matches exactly one non-empty path segment; a final `**` is a catch-all
matching one or more remaining path segments. For example,
`/api/users/123/xxx` with `/api/users/*/xxx` becomes
`api-users-wildcard-xxx`.

A path ending at `recordings/<run-id>/apis/<api-directory>` is a case collection,
not a single case. A path ending at `recordings/<run-id>` is a run collection
and may contain HTTP and Motan API directories. To select cases, open each
published child `request.json` and match the recorded `uri` path against the
requested API/function scope. Multiple matches for the same scope are a case
set and must all be considered. Do not infer the selected API from `uri-group`
alone.

Treat `expected_response.json` as a tolerated user spelling only. Prefer
`expected-response.json` in new references and test names. Do not rename or
rewrite recorded files during replay work.

Load order:

1. run-level `recording-network.json`
2. `request.json`
3. `expected-response.json`
4. `dependencies.jsonl`
5. `dependencies-summary.json` when present
6. run-level `global-dependencies.jsonl` when present
7. run-level `global-dependencies-summary.json` when present
8. `dependencies-debug.jsonl` only for missing semantic data, parse warnings, or
   protocol debugging

If canonical `request.json` or `expected-response.json` is missing and only
`.partial` or `.truncated` variants exist, stop. The case was not published as
valid and must be re-recorded after fixing recorder limits, service readiness,
or recorder behavior.

## HTTP Boundary Files

`request.json` records the inbound HTTP gateway request:

- `timestamp`: capture time
- `client_addr`: original client socket address, when known
- `method`: HTTP method
- `uri`: path and query as received by the gateway
- `authority`: original authority/host, when known
- `matched_rule`: gateway rule name, when a rule matched
- `upstream`: upstream base URL used during recording
- `headers`: lowercase header map, values as arrays
- `body`: case body capture

Configured sensitive request-header values may be stored as
`traffic-e2e:enc:v1:aes-256-gcm:<nonce-base64>:<ciphertext-and-tag-base64>`.
The header name is authenticated and matching is case-insensitive. The
standard runner loads the project-managed key from
`.traffic-e2e/local/secrets/traffic-e2e-enc.sec`, authenticates and decrypts
these values into a private short-lived case view, and gives only that view to
the system HTTP driver. It never rewrites the published `request.json`.
Missing or wrong key material blocks replay startup. An explicit
`TRAFFIC_E2E_ENCRYPTION_KEY_B64` remains a compatibility override and must
equal the managed key. A legacy `<redacted>` request value is not recoverable
and must be re-recorded when the original value is required for behavior or
dependency association.

`expected-response.json` records the upstream response observed for that request:

- `timestamp`: capture time
- `matched_rule`: gateway rule name, when a rule matched
- `upstream`: upstream base URL used during recording
- `status`: HTTP status, or null when the upstream call failed
- `headers`: lowercase response header map, or null when unavailable
- `body`: case body capture, or null when unavailable
- `duration_ms`: observed upstream duration
- `error`: recorder/upstream error, or null

Use `method`, `uri`, headers, and body to drive the request. Use `status`, the
response body, and the engine's standard HTTP response headers for assertions.
The standard headers are `access-control-allow-credentials`,
`access-control-allow-headers`, `access-control-allow-methods`,
`access-control-allow-origin`, `access-control-expose-headers`,
`access-control-max-age`, `allow`, `cache-control`, `content-disposition`,
`content-type`, `location`, `vary`, `www-authenticate`, and `x-request-id`.
They are built-in response contract, not policy rules. `x-request-id` is
source-positive: source absence is ignored, source presence requires target
presence, source request echo must remain a target request echo, and generated
values compare by trimmed byte length. Older artifacts with no header snapshot
retain their existing status/body verdict because their header evidence is
unavailable; new HTTP Replay actual-response artifacts capture the standard
headers only and do not persist unselected sensitive headers such as
`set-cookie`. They additionally retain only the actual target request's
`x-request-id` under `request_headers` for echo evidence.

`expected-response.json` is assertion-only evidence. MUST NOT read its status,
headers, body, or derived values to produce the target's actual response,
configure product/replay behavior, seed database/HTTP/cache/queue dependency
results, decide whether a dependency is called, or manufacture a cache or side
effect. If the target cannot generate the result from request/session context,
source behavior, product config, time/generated values, and recorded
dependencies alone, keep the case non-passing and return the bounded engine
fact to the caller.
Use `blocked` only when the missing-external-evidence proof succeeds; otherwise
return `action_required`. A passing assertion after reverse-feeding expected
data is an invalid circular test.

For JSON response bodies, parse recorded and actual bodies and compare JSON
values structurally. Object member order is not meaningful. Field presence and
value kind are meaningful: a missing field, `null`, and `""` are three different
results. Arrays remain ordered unless the product contract or explicit
assertion config says otherwise.

An explicitly captured zero-length response body is valid even when the
response advertises a JSON content type. Its `original_len`, `stored_len`, and
`data` are all empty, and replay compares it as exact bytes. A non-empty
response advertised as JSON must still parse as valid JSON.

Use byte-level comparison only for zero-length bodies, non-JSON bodies, binary
payloads, or an explicit exact-bytes assertion mode.

## Body Capture

HTTP case body fields:

- `encoding`: `utf8` or `base64`
- `original_len`: byte length before truncation
- `stored_len`: byte length stored in the case file
- `truncated`: true when the body exceeded recorder limits
- `decoded`: true when gzip/deflate content was decoded before storage
- `content_encoding`: original `Content-Encoding`, when present
- `data`: UTF-8 text or base64 bytes depending on `encoding`
- `decode_error`: decode error text, or null

If `encoding` is `utf8`, use `data` directly. If `encoding` is `base64`, decode
`data` before sending the request or comparing exact bytes. Published HTTP
cases should not have truncated request or expected-response bodies. If they do,
treat the recording as invalid and report a recorder improvement instead of
weakening assertions.

For semantic dependency, summary, debug, and Global file formats, read
[dependency-case-format.md](dependency-case-format.md).
