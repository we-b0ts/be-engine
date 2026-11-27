# API Implementer Delivery

Commit the Target code repair in the assigned worktree. Run the
assignment-specific tests against the delivered version. For a rule change,
return the [rule proposal](api-implementer-rule-diagnosis.md#submit-a-rule-plan).

Return the assigned `group`, `assignment_id`, full commit ID, exact
`sequences_file` covered by the change, and focused test results in `checks`.
A short verification conclusion is sufficient for a fix.
Write the Source sequence numbers one per line or comma-separated. Use an
absolute path or a path relative to the receipt JSON.
Use the ID from the full handoff for the original recording. Pass along any
required startup inputs so the coordinator can apply them before Replay.

For assigned window sequences that need no change, return `kind: confirmed`
with the group, assignment ID, sequence file, `format: matches`, and
`rule: not_needed` or `rule: covered`. Group confirmations by the same rule
result. A first-run API that is already implemented uses a `kind: review`
receipt with route and handler tests. [Confirmation format](session-regression.md#confirm-window-sequences)

Send an evidence-backed `kind: claim` receipt for unassigned dependencies
before submitting a result that covers them. The claim establishes ownership.
Deliver a confirmation, tested fix, or rule plan in the same assignment.
[Claim format](session-regression.md#claim-window-dependencies)

For a confirmed engine gap, return the group, assignment ID, Source
sequence file, observed result, and the engine capability needed. Cite the
specific event, Target observation, or implementation behavior that establishes
the gap. The coordinator registers the escalation, routes it to the engine
owner, and retries after repair. [Engine gap report](session-regression.md#plan-implement-and-verify)
