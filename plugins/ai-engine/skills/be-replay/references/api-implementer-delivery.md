# API Implementer Delivery

Commit the reviewed finding's changes in the assigned worktree. Verify the
diff against the supplied base and the focused checks against the version
being delivered.

Return the following to the coordinator:

- Finding identity, recording ID, and Source sequences.
- Source files or symbols that establish the behavior and the Target paths
  changed to implement it.
- Full commit ID, assigned worktree, and the commands and results for focused
  checks.
- Any unresolved evidence or supported startup inputs the coordinator needs
  before Replay.

For an input-only finding, return the evidence and required input. The
coordinator publishes any code changes and runs full verification.
