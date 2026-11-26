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
then delivers the policy commit and focused check results through the standard
fixes report. Review the integrated policy diff and verify it with a fresh
complete `run` of the same sealed Source recording. [Coordinator rule actions](coordinator-rule-actions.md)
