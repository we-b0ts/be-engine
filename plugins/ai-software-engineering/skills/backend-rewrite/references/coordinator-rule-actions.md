# Coordinator Rule Actions

Use the `traffic-policy/v3` file named by `project.policy`, normally
`.traffic-e2e/policy.yaml`, for time, ID and token rules. Require Source code
proof, exact selectors and the smallest supported declaration. See
[rule diagnosis](api-implementer-rule-diagnosis.md).

## Source Event Session

1. Follow the evidence commands from `session run`. Use the failed sequence,
   any related Source sequences and the retained Target observation to review
   the worker's proof.
2. Submit the finding to `session plan` with `kind: rule` and the affected
   repository-relative policy path. The command groups findings and returns
   assignment decisions. Have the assigned owner edit the policy and review
   the candidate diff against the observed carrier.
3. Rerun `backend-rewrite session run` on the integrated candidate. Confirm
   that the complete recording verifies from launch through shutdown.

Keep the original Source recording for a value-only change. See
[session regression](session-regression.md) and the [shared rule evidence contract](rule-policy.md).

## Unified Rule Transaction In The Case Workflow

When the engine returns an active Case issue and its policy planner, use the
current detail evidence ID to plan an admitted time, ID or token rule:

```text
backend-rewrite rule plan --file rule.yaml --evidence <current-evidence-id>
backend-rewrite rule apply --plan <returned-plan-id>
```

Review the immutable Source scope, independent Target evidence, strict remainder,
residual failures and fresh Replay obligation. Use exact selectors from the
Source proof and follow any evidence pagination or policy freshness action.
For format additions or intentional replacements, follow the
[shared rule evidence contract](rule-policy.md#case-workflow-evidence).

If Apply returns `traffic_e2e_report.status: wait_required`, retain the reviewed
plan and follow the returned status command. After the active Replay finishes,
use the returned `plan_apply_required` command. After an interrupted or stale
apply, follow `rule recover` and its policy checks. Continue with the engine's
next verification action.
