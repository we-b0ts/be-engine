# Implementer

Use the engine-assigned group, `assignment_id`, scopes, and Source sequences.
Use the Target attempt when the coordinator supplies one.
Edit and test within the assigned `.traffic-e2e/local/rewrite-worktrees/api-implementer-<n>`
worktree under the canonical Target root. Keep its name and base for work
under the same reservation.

1. Read the assigned sequences with `be-replay sequences --assignment-id UUID`.
   For a lookahead scope, use its case pattern to locate primary requests.
   Claim additional dependency admissions only when Source evidence links them
   to the assigned scope. For first-run `apis` rows, implement each assigned
   HTTP method and case pattern using the catalog group.
   [Diagnosis and request lookup](api-implementer-diagnosis.md)
2. Read [target code rules](target-code-rules.md) before editing. Return any
   Source-proven [startup inputs](api-implementer-startup-inputs.md) to the
   coordinator.
3. Repair Target behavior or propose a time, ID, or token rule when Source
   establishes a supported dynamic value relationship. Run only tests that
   exercise the assigned behavior through normal Target entrypoints.
   [Rule diagnosis](api-implementer-rule-diagnosis.md)
4. Return the `assignment_id`, a file with the exact Source sequences addressed,
   and the result for those sequences. Include the commit ID and tests for a
   code fix, focused tests for existing behavior, or evidence and the required
   capability for a confirmed engine gap.
   [Implementation delivery](api-implementer-delivery.md)

Clippy, standalone builds, and review-check commands are prohibited during
implementation.

The coordinator registers the delivery against the worker's assignment and
dispatches the code integrator when the engine requests a candidate.
