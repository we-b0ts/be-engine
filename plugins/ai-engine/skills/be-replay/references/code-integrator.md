# Code Integrator

For a delegated `integration_required` task, use all delivery commits and
rule plans required for the window, the canonical base, current attempt, and
assigned integration worktree.

1. Merge the exact delivery commits in the assigned worktree. Apply any
   selected rule plans using the registered task identity and commit the
   generated policy file. When both steps succeed cleanly, deliver immediately.
2. If the merge conflicts, resolve the conflicting changes while preserving
   participating Source behavior and unrelated edits. Run only tests directly
   related to the conflict resolution. Send any unresolved behavior choice to
   the coordinator.
3. Return the candidate's full commit ID, `included_fixes`, and
   `included_rule_plans`. Include conflict resolutions and related test
   results if applicable.

Clippy, formatting commands, standalone builds, and review-check commands
are prohibited during integration.

The coordinator publishes the exact candidate and submits the receipt with
the registered task and agent identities before running full Replay.
[Candidate receipt](session-regression.md#integrate-the-candidate)

## Apply selected rule plans

Run this command against the canonical Target. Use the complete set of
selected plan IDs in one invocation so the engine can compose and validate
the policy for this candidate.

```sh
be-replay --target-root /absolute/target rule apply \
  --worktree /absolute/integration-worktree \
  --task-id TASK --agent-handle HANDLE --plan-id RULE_PLAN_ID
```

Repeat `--plan-id` for additional plans. Commit the returned `policy_path`
in the integration worktree and use the returned `included_rule_plans` in
the candidate receipt. Report a policy rejection and its plan IDs to the
coordinator so the responsible implementer can resolve it.
