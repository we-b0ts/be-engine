---
name: be-replay
description: "Orchestrate, verify, and deliver backend rewrites from Source behavior and recorded traffic. Use for cross-language ports, API migrations, and compatibility replacements. Coordinate read-only analysis, implementation, integration, and Replay of sealed Source sessions."
---

# Backend Replay

Use `be-replay` to verify a rewrite against a sealed Source recording. The
Target is the service being rewritten. The deployment caller owns
`traffic-e2e record` and hands over the sealed recording under
`.traffic-e2e/local/artifacts/recordings/<run-id>/`.

The coordinator starts with `be-replay status`. On the configured pull-request
base, obtain the caller's approval before starting a round with
`run --user-confirm --recording-run-id ID`. On a named work branch, use
`switch-recording-id ID` to change the active recording, or
`run --recording-run-id ID` to select and immediately replay it. Replay
verifies the complete Source timeline and reports the first failure. `plan`
records reviewed findings and `report` registers fixes, engine gaps, and the
integrated candidate. Follow `status` through implementation, integration and
Replay of the published candidate. Use `action.kind` to decide which role or
workflow command is needed and `failure` to scope evidence queries.
See [Source Session regression](references/session-regression.md).

## Roles

Keep the role, worktree, and evidence scope supplied by the coordinator. Read
your role's entrypoint and the specialty references it routes to.

| Role | Owns | Reference |
| --- | --- | --- |
| Coordinator | Runs Replay, routes failures, manages assignments, publishes integrated changes, and verifies the result | [Coordinator](references/coordinator.md) |
| Issue Analyst | Groups related symptoms by likely cause and identifies their Source sequences, read-only | [Issue Analyst](references/issue-analyst.md) |
| Implementer | Diagnoses the assigned finding and returns a tested repair or a demonstrated engine gap | [Implementer](references/api-implementer.md) |
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
