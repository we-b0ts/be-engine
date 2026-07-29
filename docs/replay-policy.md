# Dependency Replay And Response Verification Policy

Each target repository owns one source-controlled
`.traffic-e2e/verification.yaml`. Pass it explicitly to every recorded replay
and comparison verification:

```bash
traffic-e2e config replay init --target-root .
traffic-e2e replay --policy .traffic-e2e/verification.yaml /path/to/case-group
```

Initialization, evidence-driven application, and replay each validate the
policy.

This policy is independent of recorder `case_path_patterns`:

- `case_path_patterns` groups recorded inbound API paths.
- verification policy matches legitimate runtime-generated dependency fields
  and owns reviewed response-comparison rules.

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
comparison:
  source_match: before
rules: []
response_rules:
  dynamic: {}
  unordered: {}
  comparison:
    counter: {}
```

Standard replay loads only the root `dynamic` and `unordered` rules.
Comparison loads those replay rules plus the nested `comparison` rules.
Strategies across both sets must select disjoint JSON subtrees.

Top-level `comparison.source_match` controls which complete source observation
may serve as the comparison oracle. `before` is the default. Set
`before_or_after` only for runs that record `expected-response-after.json` for
every case. The candidate must match either complete source response under the
active response rules; fields from the two source observations are never
combined. Standard replay ignores this comparison-only setting.

`expected-response.json` is an assertion oracle only. Target product code,
dependency mocks, E2E setup, and verification policy generation must not read its
status, headers, or body to create the actual response, dependency result,
branch decision, cache result, or side effect. The policy parser requires this
declaration; migration review must also verify the target harness obeys it.

The same version 2 `response_rules` also apply to offline comparison recording
verification. `traffic-e2e compare <comparison-recording-run> --policy
<verification.yaml>` treats the baseline `expected-response.json` as the
oracle and the candidate `response.json` as actual output. When
`expected-response-after.json` exists, it also checks source-before against
source-after. With `source_match: before_or_after`, a complete candidate match
against source-after also passes and is recorded as `matched_source: after`.
When the candidate matches neither observation, a source change makes only
candidate differences at the same response location inconclusive; unrelated
candidate differences remain target differences. Replay dependency rules are
ignored during this file-only operation, and no interception or isolation is
enabled.

Do not put recorded values, response bodies, secrets, absolute case paths, or
case-id exceptions in the policy. Use selectors and semantic validation only.
In particular, ordinary mutable business data observed at different times is
not a dynamic-response exemption. Re-record it under comparable state. Add a
response rule only after source semantics prove current-time/random generation
or order-insensitive collection behavior.

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
      - pointer: /content
        mechanisms:
          - uuid
        source_evidence: src/token.rs:issue_token UUID generation
        source_example: <redacted source UUID>
        target_example: <redacted target UUID>
```

The field must exist in both responses and keep the same scalar JSON kind.
Only literal equality is skipped; status, structure, other fields, and non-JSON
bodies stay exact. Every dynamic field persists its declared mechanism,
single-line source citation, and distinct redacted source/target examples in
the policy. These audit fields do not make the comparator infer or validate the
generation mechanism; verify that semantic claim through source review, unit
tests, or real-traffic integration tests.

Never use a dynamic rule for a difference caused by process-local cache state
or implementation. Do not exempt an entire scalar when it contains stable
structure that the target omitted. Use evidence-backed apply only after source
review proves the declared nondeterministic mechanism and redacted
source/target examples demonstrate the same stable structure. Supported
mechanisms are `timestamp`, `duration`, `uuid`, `random`, `nonce`,
`random-salt`, and `dynamic-derived`; a derived digest or signature must also
declare its underlying dynamic input. It replans
against current evidence before writing; `plan` is optional diagnostics with
the same strategy and arguments. Multiple Pointers may be submitted together
only when the same citation, mechanism, and examples prove each selected
field; otherwise plan and apply them separately:

```bash
traffic-e2e config replay apply response-rule \
  --target-root . \
  --kind dynamic \
  --dynamic-mechanism uuid \
  --source-evidence 'src/token.rs:issue_token UUID generation' \
  --source-example '<redacted UUID from source>' \
  --target-example '<redacted UUID from target>' \
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
traffic-e2e config replay apply response-rule \
  --target-root . \
  --kind unordered \
  --api 'GET /api/config/ansible_facts' \
  --json-pointer /general/sudo_users \
  --assertion-report .traffic-e2e/local/.../assertions.json \
  --aggregate-report .traffic-e2e/local/.../aggregate.json
```

Both actions accept only the difference kind selected by `--kind`,
runner-owned assertions using the current policy fingerprint, exact
focused-case coverage, and complete, clean aggregate evidence. Apply is
additive, sorted, and atomic. Rerun the entire affected API group after every
policy change.

Comparison-only live counter semantics are nested separately:

```yaml
response_rules:
  comparison:
    counter:
      "GET /api/users/show":
        - pointer: /followers_count
          source_evidence: src/user.rs:load live follower count
          source_example: "100"
          target_example: "101"
```

Standard replay ignores this subtree. Do not infer counter behavior from the
field name. After source inspection proves a live count and a current
comparison report contains differing observations, use:

```bash
traffic-e2e config comparison plan response-rule \
  --target-root . \
  --kind counter \
  --source-evidence 'src/user.rs:load live follower count' \
  --source-example '100' \
  --target-example '101' \
  --api 'GET /api/users/show' \
  --json-pointer /followers_count \
  --comparison-report .traffic-e2e/artifacts/comparison-recordings/.../comparison-report.json
```

Review the plan, then repeat with `apply`. Number matches only number. String
matches only string, and empty strings match only empty strings. Presence and
all unsupported JSON kinds remain exact.
