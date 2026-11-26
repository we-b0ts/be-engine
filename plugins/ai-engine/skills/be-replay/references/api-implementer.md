# Implementer

Use the engine-assigned group, `assignment_id`, scopes, and Source sequences.
Use the Target attempt when the coordinator supplies one.
Edit and test within the assigned `.traffic-e2e/local/rewrite-worktrees/api-implementer-<n>`
worktree under the canonical Target root. Keep its name and base for work
under the same reservation.

1. Confirm the cause and repair boundary using the assigned sequences and
   Target observation. [Diagnosis](api-implementer-diagnosis.md)
   For assigned `apis` rows, implement missing APIs and commit the assigned
   case patterns and groups in `.traffic-e2e/apis.yaml`.
2. Read [target code rules](target-code-rules.md) before editing. Return any
   Source-proven [startup inputs](api-implementer-startup-inputs.md) to the
   coordinator.
3. Repair Target behavior or, when Source establishes a supported dynamic
   value relationship, update the time, ID, or token policy. Run focused
   checks through normal Target entrypoints. [Rule diagnosis](api-implementer-rule-diagnosis.md)
4. Return the `assignment_id`, exact Source sequences addressed, full commit
   ID, and checks.
   When review confirms behavior already exists, return its sequence list and
   checks. For a confirmed engine gap, provide the observed evidence and the
   engine behavior needed. [Implementation delivery](api-implementer-delivery.md)

The coordinator registers the delivery and integrates it when needed to
advance Replay.
