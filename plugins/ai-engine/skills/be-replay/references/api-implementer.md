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
2. Before editing, read the [Target code rules](target-code-rules.md) and apply
   the required [Source collection compatibility](target-code-rules.md#source-collection-compatibility).
   Return any Source-proven [startup inputs](api-implementer-startup-inputs.md)
   to the coordinator.
3. Confirm every assigned window sequence by comparing the event's input and
   output formats and checking its Target branch. Implement missing or
   mismatched behavior and prepare any Source-proven rule the event needs.
   Run focused tests for changes and first-run API reviews through normal
   Target entrypoints. [Confirm assigned events](api-implementer-diagnosis.md#confirm-assigned-events)
4. Return the `assignment_id`, a file with the exact Source sequences addressed,
   and the result for those sequences. Include the commit ID and tests for a
   code fix, the format and rule result for unchanged window sequences, or
   evidence and the required capability for an engine gap.
   [Implementation delivery](api-implementer-delivery.md)

Clippy, standalone builds, and review-check commands are prohibited during
implementation.

The coordinator registers the delivery against the worker's assignment and
dispatches the code integrator when the engine requests a candidate.
