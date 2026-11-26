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
`switch-recording-id ID` to change the active recording. Follow
`api_grouping_required` to group uncatalogued API paths. Submit the plan and
commit the catalog written by the engine. Follow `dispatch_required` to
launch the assigned groups in parallel and register their runtime handles.
At `worker_status_required`, query the agent runtime and submit its status.
Follow `advance_required` to start Replay while those groups work.

Replay verifies the complete Source timeline and reports the first failure.
The engine assigns API work in a rolling 60-second Source window.
For `ownership_required`, have the Issue Analyst identify the owner of the
failed sequence and submit it with `plan`. Use the worker names and worktrees
in the engine's assignments. Include the engine's `assignment_id` when
registering worker deliveries. Register the integrated candidate against the
current attempt. Use `action.kind` to identify the next step,
`action.query` for supporting details, `action.command` for the next
`be-replay` invocation when present, and `failure` to scope evidence queries.
See [Source Session regression](references/session-regression.md).

## Roles

Keep the role, worktree, and evidence scope supplied by the coordinator. Read
your role's entrypoint and the specialty references it routes to.

| Role | Owns | Reference |
| --- | --- | --- |
| Coordinator | Runs Replay, routes failures, manages assignments, publishes integrated changes, and verifies the result | [Coordinator](references/coordinator.md) |
| Issue Analyst | Finds case patterns and groups for uncatalogued APIs and identifies the first failed event's owner when asked, read-only | [Issue Analyst](references/issue-analyst.md) |
| Implementer | Diagnoses the assigned group's events and delivers exact sequences with a tested repair, review, or demonstrated engine gap | [Implementer](references/api-implementer.md) |
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
