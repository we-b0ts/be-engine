# Coordinator Rule Actions

Use the `traffic-policy/v3` file named by `project.policy`, normally
`.traffic-e2e/policy.yaml`, for time, ID, and token rules. When preparing a
rule change, require Source code proof, exact selectors, and the smallest
supported declaration. See
[rule diagnosis](api-implementer-rule-diagnosis.md).

1. Follow the evidence queries from `run` or `status`. Review the Source
   sequence, any related Source events, and the authenticated Target
   observation when available.
2. Ask the assigned implementer to confirm the value relationship and edit the
   policy when supported. Review the diff against the observed value location.
3. Register the policy commit with a `fixes` report and register the integrated
   candidate after validation. Follow
   `status` to verify the candidate on the same sealed recording.

See [shared rule evidence](rule-policy.md) and [Session regression](session-regression.md).
