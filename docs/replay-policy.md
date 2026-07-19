# Replay And Assertion Policy

Each target repository owns one source-controlled `.traffic-e2e/replay.yaml`.
Pass it explicitly to every recorded replay:

```bash
traffic-e2e replay --policy .traffic-e2e/replay.yaml /path/to/case-group
traffic-e2e diagnose replay-policy validate --policy .traffic-e2e/replay.yaml
```

This policy is independent of recorder `case_path_patterns`:

- `case_path_patterns` groups recorded inbound API paths.
- replay policy matches legitimate runtime-generated dependency fields.

## Required Contract

Every policy starts with:

```yaml
version: 1
expected_response: assertions_only
rules: []
```

Version two enables runner-owned response assertions:

```yaml
version: 2
expected_response: assertions_only
rules: []
response_rules:
  dynamic: {}
  unordered: {}
```

`expected-response.json` is an assertion oracle only. Target product code,
dependency mocks, E2E setup, and replay policy generation must not read its
status, headers, or body to create the actual response, dependency result,
branch decision, cache result, or side effect. The policy parser requires this
declaration; migration review must also verify the target harness obeys it.

Do not put recorded values, response bodies, secrets, absolute case paths, or
case-id exceptions in the policy. Use selectors and semantic validation only.

## Rule Scope

Dependency rules select one operation by protocol and a narrow dependency
identity. HTTP rules require a target host, dependency method and dependency
path. MySQL rules require a SQL pattern plus at least one target host, database,
or username. Reuse one unscoped rule for the same dependency operation instead
of copying it for every inbound API.

`case` is optional. Add it only when the same dependency operation has
different dynamic-field semantics in different request contexts and a narrower
dependency selector cannot distinguish them. Bindings remain isolated by
active case for both scoped and unscoped rules.

Case paths, when present, and HTTP dependency paths use segment-aware patterns:
`*` stays inside one segment and `**` crosses segments. SQL patterns are
normalized for whitespace, case, and backticks; `*` and `?` are wildcards.
Multiple rules may match one dependency only when they select disjoint dynamic
fields.

## Dynamic Fields

Version one supports scalar MySQL parameters and single-occurrence HTTP query
parameters:

- `bind`: capture the actual runtime value in the current case.
- `ref`: require the actual value to equal a value bound earlier in that case.
- `validate: uuid`, `uuid_v4`, or `non_empty`: validate shape without comparing
  the recorded literal.
- `time`: require a timestamp relative to `replay_now`, with an offset and
  tolerance.

Example:

```yaml
version: 1
expected_response: assertions_only
rules:
  - id: audit-insert
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "INSERT INTO request_log_* (uuid, request_time) VALUES (?, ?)"
      params:
        0:
          bind: audit_id
          validate: uuid_v4
        1:
          time:
            relative_to: replay_now
            tolerance: 2s
            format: "%Y-%m-%d %H:%M:%S"
            timezone: "+08:00"

  - id: audit-update
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "UPDATE request_log_* SET response_status=? WHERE uuid=?"
      params:
        1:
          ref: audit_id

  # Optional context-specific field composed with the unscoped update rule.
  - id: resource-token-audit-response
    case:
      method: GET
      path: /api/resource/token
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "UPDATE request_log_* SET response_status=? WHERE uuid=?"
      params:
        0:
          validate: non_empty
```

Durations accept integer `ms`, `s`, `m`, `h`, and `d` units. A time value may
be RFC 3339, Unix seconds, or use an explicit Chrono format and numeric
`+HH:MM`/`-HH:MM` timezone.

## Evidence And Failure

Replay reports include the canonical policy path, content fingerprint,
`assertions_only` declaration, rule applicability, match counts, field
operation counts, and unused applicable rules. An applicable rule with zero
matches is dirty evidence and fails `end`, `finalize --fail-on-dirty`, and
aggregate dirty checks. A rule is applicable only when a selected case-owned
recorded dependency exchange matches its stable dependency selectors and its
optional `case` selector. Selecting an inbound API alone and matching bootstrap
evidence do not make a dependency rule applicable.

A query field cannot be both policy-managed and passed through the global
`--http-ignore-query-param` option. Replay rejects that configuration at
startup.

Version two supports exact scalar JSON response locations whose runtime value
is intentionally non-deterministic:

```yaml
response_rules:
  dynamic:
    "GET /api/resource/token":
      - /content
```

The field must exist in both responses and keep the same scalar JSON kind.
Only literal equality is skipped; status, structure, other fields, and non-JSON
bodies stay exact. The comparator does not decide whether the value is a UUID,
random token, timestamp, or another generated value. Verify those semantics in
source review, unit tests, or real-traffic integration tests.

Use evidence-backed plan/apply after diagnosing the source and target:

```bash
traffic-e2e diagnose replay-policy response-rule plan \
  --policy .traffic-e2e/replay.yaml \
  --kind dynamic \
  --api 'GET /api/resource/token' \
  --json-pointer /content \
  --assertion-report .traffic-e2e/local/.../assertions.json \
  --aggregate-report .traffic-e2e/local/.../aggregate.json

traffic-e2e diagnose replay-policy response-rule apply \
  --policy .traffic-e2e/replay.yaml \
  --kind dynamic \
  --api 'GET /api/resource/token' \
  --json-pointer /content \
  --assertion-report .traffic-e2e/local/.../assertions.json \
  --aggregate-report .traffic-e2e/local/.../aggregate.json
```

Version two also supports arrays whose product contract does not assign meaning
to element order:

```yaml
response_rules:
  unordered:
    "GET /api/config/ansible_facts":
      - /general/sudo_users
```

Both selected values must be arrays. They are compared as multisets: length,
elements, and duplicate counts must match, while only their outer order is
ignored. Nested JSON values remain exact, as do every undeclared response
location. Dynamic and unordered rules cannot overlap the same JSON subtree.

An exact reorder-only mismatch produces an `unordered_candidates` diagnostic.
After source and target review proves the array is semantically unordered, use
the same evidence-backed workflow:

```bash
traffic-e2e diagnose replay-policy response-rule plan \
  --policy .traffic-e2e/replay.yaml \
  --kind unordered \
  --api 'GET /api/config/ansible_facts' \
  --json-pointer /general/sudo_users \
  --assertion-report .traffic-e2e/local/.../assertions.json \
  --aggregate-report .traffic-e2e/local/.../aggregate.json

traffic-e2e diagnose replay-policy response-rule apply \
  --policy .traffic-e2e/replay.yaml \
  --kind unordered \
  --api 'GET /api/config/ansible_facts' \
  --json-pointer /general/sudo_users \
  --assertion-report .traffic-e2e/local/.../assertions.json \
  --aggregate-report .traffic-e2e/local/.../aggregate.json
```

Planning accepts only the difference kind selected by `--kind`, runner-owned
assertions using the current policy fingerprint, exact focused-case coverage,
and complete, clean aggregate evidence. Apply is additive, sorted, atomic, and
rejects a policy changed after planning. Revalidate and rerun the entire
affected API group after every policy change.
