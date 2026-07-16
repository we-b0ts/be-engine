# Replay And Assertion Policy

Read this reference before creating, changing, or validating replay-time dynamic
value rules.

## Ownership

Maintain one source-controlled target `config/replay.yaml`. Every replay MUST
pass it explicitly with `--policy`; do not auto-discover it or duplicate rules
in shell, application config, target code, or migration state.

Initialize version one with:

```yaml
version: 1
expected_response: assertions_only
rules: []
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

## Dynamic Rules

Add a rule only after source and dependency evidence proves that a field is
legitimately dynamic. Select the outer API, dependency identity or fingerprint,
and exact field. Use supported bind/ref relationships, shape validation, or
relative-time validation without copying recorded literals, secrets, absolute
case paths, or case ids into the policy.

Version one supports only its recorder-declared scalar fields. It does not
support background allowlists, case-id exceptions, dependency payload fixtures,
response ignores, or arbitrary JSON-body transformations. A case requiring an
unsupported rule remains incomplete; do not compensate in target code or the
test harness.

Never add a response ignore automatically. When replay proves a response field
unstable, report the exact field and wait for explicit user authorization for
any assertion change.

After every policy change, revalidate and rerun the entire affected API group.
Earlier replay and aggregate artifacts are stale. Completion requires zero
unused applicable rules and a direct audit proving the expected response and
dependency recordings did not flow into actual behavior.
