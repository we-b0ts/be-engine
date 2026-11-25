# API Implementer Delivery

Commit the Target or policy repair in the assigned worktree. Verify the diff
against the supplied base and the focused checks against the delivered version.

Return the full commit ID and focused check results for the assigned
`root_cause` and originating attempt. Pass along any required startup inputs
so the coordinator can apply them before Replay.

For a confirmed engine gap, return the finding group, originating attempt ID,
Source sequence, observed result, and the engine capability needed. Cite the
specific event, Target observation, or implementation behavior that establishes
the gap. The coordinator registers the escalation, routes it to the engine
owner, and retries after repair. [Engine gap report](session-regression.md#plan-implement-and-verify)
