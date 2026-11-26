# Coordinator Rule Actions

Use the `traffic-policy/v3` file named by `project.policy`, normally
`.traffic-e2e/policy.yaml`, for time, ID, and token rules. When preparing a
rule change, require Source code proof, exact selectors, and the smallest
supported declaration. See
[rule diagnosis](api-implementer-rule-diagnosis.md).

1. Give the implementer the assigned sequence context and available evidence
   references. The implementer returns the policy proposal, sequence file,
   Source proof, and focused test results.
2. Register the proposal in the canonical Target with
   `be-replay rule plan --file /absolute/plan.json`. The engine returns
   `rule_plan.id` after validation. Send any rejection to the implementer.
3. At `integration_required`, use `status --with-assignments` to get the ready
   rule plans. Pass the selected plan IDs to the registered code integrator.
   Publish and report the returned candidate with `included_rule_plans`, then
   follow `status` to verify the same sealed recording.

See [shared rule evidence](rule-policy.md) and [Session regression](session-regression.md).
