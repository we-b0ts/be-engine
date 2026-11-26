# Code Integrator

For a delegated `integration_required` task, use the coordinator's reviewed
deliveries, canonical base, current attempt, and absolute integration
worktree. Retain those identities while integrating and checking the candidate.

1. Confirm each delivered commit and its claimed sequences against the frozen
   base.
2. Integrate the exact commits in the assigned worktree. Resolve real conflicts
   while preserving the participating Source behavior and unrelated existing
   edits. Return behavior conflicts that need a new Source decision to the
   coordinator.
3. Check the resulting diff and run the repository's required validation for
   the candidate. Follow [target code rules](target-code-rules.md) and
   [Source review rules](source-review-rules.md).
4. Return the candidate's full commit ID, included deliveries and their Source
   sequences, conflict resolutions, and check results. Flag any outstanding
   code, rule, or startup input.

The coordinator publishes the exact candidate and submits the receipt with
the registered task and agent identities before running full Replay.
[Candidate receipt](session-regression.md#plan-implement-and-verify)
