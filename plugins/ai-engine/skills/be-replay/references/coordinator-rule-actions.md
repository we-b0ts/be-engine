# Coordinator Rule Actions

Use the `traffic-policy/v3` file named by `project.policy`, normally
`.traffic-e2e/policy.yaml`, for time, ID, and token rules. When preparing a
rule change, require Source code proof, exact selectors, and the smallest
supported declaration. See
[rule diagnosis](api-implementer-rule-diagnosis.md).

1. Give the assigned implementer the failed sequence and available evidence
   references. Ask the implementer to establish the value relationship and
   deliver the supported policy edit with the Source proof and checks.
2. Review the returned diff and evidence, then register the delivery with a
   `fixes` report. Ask the implementer to resolve any remaining diagnosis.
3. Follow the delegated integration task to publish and report the validated
   candidate. Use `status` to verify it on the same sealed recording.

See [shared rule evidence](rule-policy.md) and [Session regression](session-regression.md).
