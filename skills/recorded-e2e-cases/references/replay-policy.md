# Replay And Assertion Policy

Read this reference before creating, changing, or validating replay-time
response rules.

## Ownership

Maintain one source-controlled target `config/replay.yaml`. Every replay MUST
pass it explicitly with `--policy`; do not auto-discover it or duplicate rules
in shell, application config, target code, or migration state.

Use version one for legacy target-owned response assertions:

```yaml
version: 1
expected_response: assertions_only
rules: []
```

Use version two when the standard runner owns response assertions:

```yaml
version: 2
expected_response: assertions_only
rules: []
response_rules:
  dynamic: {}
  unordered: {}
```

Validate it with `traffic-replay-policy validate` before replay. Retain its
canonical path, fingerprint, applicable rules, usage, and unused applicable
rules from the final report.

## Assertion And Dependency Boundaries

`expected-response.json` is an assertion oracle only. Target product code, test
setup, dependency implementations, replay rules, branch or cache decisions,
side-effect generation, and runtime config MUST NOT read it to create actual
behavior.

`dependencies.jsonl` and bootstrap dependency files are recorder-owned replay
inputs. Target product code, E2E code, test support, commands, and application
config MUST NOT read, parse, copy, or derive dependency results from them. Do
not create recording-backed or fixture-backed target dependency implementations.

## Dependency Dynamic Rules

Add a rule only after source and dependency evidence proves that a field is
legitimately dynamic. Select the dependency identity or fingerprint and exact
field. Reuse one operation-level rule for the same dependency selector; do not
copy it for each inbound API. Use supported bind/ref relationships, shape
validation, or relative-time validation without copying recorded literals,
secrets, absolute case paths, or case ids into the policy.

The optional `case` selector is an exception for an evidenced ambiguity: use it
only when the same dependency operation has different dynamic-field semantics
in different request contexts and no narrower dependency selector can
distinguish them. Bindings remain isolated by active case even when the rule is
unscoped, so one bind/ref name can be reused safely across a collection.

An unscoped or scoped rule is applicable only when a selected case-owned
recorded dependency exchange matches its stable protocol and dependency
selectors, plus `case` when present. Selecting an inbound API alone does not
make a rule applicable, and bootstrap evidence does not make a case rule
applicable. Multiple rules may compose on one dependency exchange only when
they select disjoint fields; overlapping field selection is rejected.

```yaml
rules:
  - id: request-audit-insert
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "INSERT INTO request_log_* (*) VALUES (*)"
      params:
        0:
          bind: request_audit_id
          validate: uuid_v4
        11:
          time:
            relative_to: replay_now
            tolerance: 10s

  - id: request-audit-update
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "UPDATE request_log_* SET * WHERE uuid=?"
      params:
        0:
          bind: request_audit_elapsed
        3:
          ref: request_audit_id

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
      sql: "UPDATE request_log_* SET * WHERE uuid=?"
      params:
        1:
          validate: non_empty
```

Version one supports only its recorder-declared scalar fields. It does not
support background allowlists, case-id exceptions, dependency payload fixtures,
response ignores, or arbitrary JSON-body transformations. A case requiring an
unsupported rule remains incomplete; do not compensate in target code or the
test harness.

## Dynamic Response Fields

Version two makes the runner, rather than the target facade, compare expected
and actual responses. The target facade reads `request.json`, sends the genuine
request, and writes the runner-named version-one actual-response artifact. It
MUST NOT read `expected-response.json`.

`response_rules.dynamic` selects an exact scalar JSON value by canonical API
group and JSON Pointer:

```yaml
response_rules:
  dynamic:
    "GET /api/resource/token":
      - /content
```

The selected field must exist in expected and actual JSON, and both values must
have the same scalar JSON kind. Only literal equality is skipped. Status, body
structure, undeclared fields, missing fields, nulls, arrays, and non-JSON bodies
remain exact. The rule does not validate UUID shape, randomness, timestamps, or
other generation semantics; cover those through source review, unit tests, or
real-traffic integration tests.

On an exact scalar mismatch the assertion report may expose the pointer as a
diagnostic candidate. That mechanical candidate is not authorization to weaken
the assertion. Inspect source and target behavior first. If the difference is
intentional and dependency evidence is complete and clean, plan and apply it:

```bash
traffic-replay-policy response-rule plan \
  --policy config/replay.yaml \
  --kind dynamic \
  --api 'GET /api/resource/token' \
  --json-pointer /content \
  --assertion-report .migration/local/.../assertions.json \
  --aggregate-report .migration/local/.../aggregate.json

traffic-replay-policy response-rule apply \
  --policy config/replay.yaml \
  --kind dynamic \
  --api 'GET /api/resource/token' \
  --json-pointer /content \
  --assertion-report .migration/local/.../assertions.json \
  --aggregate-report .migration/local/.../aggregate.json
```

## Unordered Response Arrays

`response_rules.unordered` selects an exact JSON array by canonical API group
and JSON Pointer:

```yaml
response_rules:
  unordered:
    "GET /api/config/ansible_facts":
      - /general/sudo_users
```

The selected field must exist in both responses and both values must be arrays.
Comparison preserves length, exact JSON elements, and duplicate counts while
ignoring only the outer array order. Other response locations remain exact.
Dynamic and unordered rules cannot overlap the same JSON subtree.

An exact reorder-only mismatch may expose an `unordered_candidates` diagnostic.
It does not prove that order is irrelevant. Inspect source behavior, target
behavior, and consumers before planning:

```bash
traffic-replay-policy response-rule plan \
  --policy config/replay.yaml \
  --kind unordered \
  --api 'GET /api/config/ansible_facts' \
  --json-pointer /general/sudo_users \
  --assertion-report .migration/local/.../assertions.json \
  --aggregate-report .migration/local/.../aggregate.json

traffic-replay-policy response-rule apply \
  --policy config/replay.yaml \
  --kind unordered \
  --api 'GET /api/config/ansible_facts' \
  --json-pointer /general/sudo_users \
  --assertion-report .migration/local/.../assertions.json \
  --aggregate-report .migration/local/.../aggregate.json
```

Planning requires runner-owned structural assertion evidence using the current
policy fingerprint and complete, clean aggregate evidence. It accepts only the
difference kind selected by `--kind` and rejects status, shape, type, non-JSON,
content, or undeclared field differences. Apply is additive, sorted, atomic,
and rejects a policy changed after planning.

After every policy change, revalidate and rerun the entire affected API group.
Earlier replay and aggregate artifacts are stale. Completion requires zero
unused applicable rules and a direct audit proving the expected response and
dependency recordings did not flow into actual behavior.
