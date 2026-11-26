# API Implementer Delivery

Commit the Target or policy repair in the assigned worktree. Verify the diff
against the supplied base and the focused checks against the delivered version.

Return the assigned `group`, `assignment_id`, full commit ID, exact
`sequences` covered by the change, and focused checks. Use the ID from the
full handoff for the original recording. For assigned lookahead events that
require no change, return the group, assignment ID, sequences, and checks
as a review. Pass along any required startup inputs so the coordinator can
apply them before Replay.

For a confirmed engine gap, return the group, assignment ID, Source
sequences, observed result, and the engine capability needed. Cite the
specific event, Target observation, or implementation behavior that establishes
the gap. The coordinator registers the escalation, routes it to the engine
owner, and retries after repair. [Engine gap report](session-regression.md#plan-implement-and-verify)
