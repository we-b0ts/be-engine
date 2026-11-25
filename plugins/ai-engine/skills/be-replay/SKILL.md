---
name: be-replay
description: "Orchestrate, verify, and deliver backend rewrites from Source behavior and recorded traffic. Use for cross-language ports, API migrations, and compatibility replacements. Coordinate read-only analysis, implementation, integration, and Replay of sealed Source sessions."
---

# Backend Replay

Use `be-replay` to verify a rewrite against a sealed Source recording. The
Target is the service being rewritten. The deployment caller owns
`traffic-e2e record` and hands over the sealed recording under
`.traffic-e2e/local/artifacts/recordings/<run-id>/`.

The coordinator runs `be-replay run` against the selected recording.
Replay drives the complete Source session by event sequence from launch through
shutdown and reports the first failure. Use `status` to inspect an attempt,
then use the returned `events`, `dependency`, and `target` queries as needed.
`plan` groups reviewed findings for implementation. A fresh passing `run`
verifies the integrated candidate. See [Source Session regression](references/session-regression.md).

## Roles

Keep the role, worktree, and evidence scope supplied by the coordinator. Read
your role's entrypoint and the specialty references it routes to.

| Role | Owns | Reference |
| --- | --- | --- |
| Coordinator | Runs Replay, routes failures, manages assignments, publishes integrated changes, and verifies the result | [Coordinator](references/coordinator.md) |
| Issue Analyst | Investigates the reported sequence and traces the cause through Source code and observed Target behavior, read-only | [Issue Analyst](references/issue-analyst.md) |
| Implementer | Repairs a reviewed finding in the assigned worktree and returns the tested commit | [Implementer](references/api-implementer.md) |
| Code integrator | Combines reviewed commits and returns the exact candidate | [Code integrator](references/code-integrator.md) |

For an explicit request to initialize a Target, use [project initialization](references/project-init.md).
For missing evidence or recapture, use [recording handoff](references/coordinator-recording.md).

## Evidence and verification

- Inspect the exact recording and attempt using the public engine queries.
  Preserve recordings, private evidence, and engine-generated `progress.yaml`.
- Use normal product code, configuration, and real dependencies for Target
  behavior. Keep recording values, expected responses, and Replay state out of
  product code.
- Tie comparisons for time, IDs, and tokens to the actual Source contract and
  authenticated observations. See [rule evidence](references/rule-policy.md).
- The coordinator tracks active work using the agent runtime and integrates
  exact commits before verification. The engine determines the Replay result.
