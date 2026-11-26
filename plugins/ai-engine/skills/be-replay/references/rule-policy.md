# Rule Evidence Contract

The policy at `project.policy` uses `traffic-policy/v3`. Rule work covers time,
IDs, and token values. When implementing a rule, establish Source generation
or validation, the exact value location, and the required relationship. Preserve
other fields, physical resource identity, and the finite sequence of exchanges. See
[rule diagnosis](api-implementer-rule-diagnosis.md).

The implementer uses the assigned sequences and [evidence queries](session-regression.md#diagnose-the-first-failure)
to read the Source event, dependency admission, and authenticated Target
observation when available. Trace the assigned event's dynamic value to its
Source generator or validator.

The implementer confirms the exact selector and supported value relationship,
then delivers an additive policy proposal, a sequence file, and focused test
results. The engine validates the proposal with `be-replay rule plan`. The
integrator uses `be-replay rule apply` for the selected plans, and the
coordinator verifies the candidate with a complete `run` of the same sealed
recording. [Plan format](api-implementer-rule-diagnosis.md#submit-a-rule-plan) · [Coordinator rule actions](coordinator-rule-actions.md)
