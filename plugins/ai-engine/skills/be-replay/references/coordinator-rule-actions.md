# Coordinator Rule Actions

Use the `traffic-policy/v3` file named by `project.policy`, normally
`.traffic-e2e/policy.yaml`, for time, ID, and token rules. Require Source code
proof, exact selectors, and the smallest supported declaration. See
[rule diagnosis](api-implementer-rule-diagnosis.md).

1. Follow the evidence queries from `run` or `status`. Review the Source
   sequence, any related Source events, and the authenticated Target
   observation when available.
2. Submit the finding to `plan` as `kind: rule` with its repository-relative
   policy path. Have the assigned owner edit the policy, and review the exact
   diff against the observed value carrier.
3. Integrate the candidate and rerun `be-replay run` on the same sealed
   recording. Verify the full timeline from launch through shutdown.

See [shared rule evidence](rule-policy.md) and [Session regression](session-regression.md).
