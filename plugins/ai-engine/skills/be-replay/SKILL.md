---
name: be-replay
description: "Coordinate and verify backend rewrites against sealed Source traffic. Use for cross-language ports, API migrations, and compatibility replacements that need managed Replay and delegated analysis, implementation, and integration."
---

# Backend Replay

Use `be-replay` to verify a Target against a sealed Source recording.
The recording owner supplies the sealed directory under
`.traffic-e2e/local/artifacts/recordings/<run-id>/`. [Recording handoff](references/coordinator-recording.md)

## Start or resume as coordinator

For an explicit Target initialization, use [Project initialization](references/project-init.md).
When coordinating a managed round, read the coordinator entrypoint and start with
`be-replay status` in the canonical Target. Follow `action.kind`. At
`dispatch_task`, launch the named role through the agent runtime. Ask the
agent to load this skill for its assigned role. Register the handle returned
by the runtime. At `await_delivery`, monitor the agent and submit its returned
artifact. Use engine-provided assignments to launch implementers and use the
engine's verdict to verify the result.
[Coordinator](references/coordinator.md)

## Work in your assigned role

If you were dispatched to a role, use its name to read only your assigned
guide. You can read this entrypoint directly when the runtime has no skill
invocation tool.

| Role | Owns | Reference |
| --- | --- | --- |
| `issue-analyst` | Read-only API grouping or ownership of the failed sequence | [Issue Analyst](references/issue-analyst.md) |
| `api-implementer` | Diagnosis and tested repairs, reviews, or engine gaps for assigned sequences | [Implementer](references/api-implementer.md) |
| `code-integrator` | Integration and validation of accepted fixes in the integration worktree | [Code integrator](references/code-integrator.md) |

Use the exact recording, attempt, revision, and worktree supplied with the
assignment. Preserve sealed recordings, private evidence, and
engine-generated `progress.yaml`. [Source Session commands and receipt formats](references/session-regression.md)
