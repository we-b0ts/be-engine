---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend rewrites from source behavior and recorded traffic. Use for cross-language ports, API migrations, and compatibility replacements; coordinate dedicated API implementers and a code integrator through the backend-rewrite state machine."
---

# Backend Rewrite

Use `backend-rewrite` as the authority for workflow state, legal actions,
verification, and completion. The task runtime owns real agent handles, events,
queuing, and concurrency. The target is the service being rewritten.

## Select Your Role

Role comes from the assignment and persists through missing inputs, failures,
resumed turns, and completed handoffs. Read only your role's entrypoint and the
references it requests.

| Assignment | Responsibility | Entrypoint |
| --- | --- | --- |
| Main/root workflow task: `coordinator` | Dispatch, reconcile results, execute engine transitions, invoke acceptance, deliver | [coordinator.md](references/coordinator.md) |
| `api-implementer` | Diagnose and implement the assigned API; return evidence and checked code | [api-implementer.md](references/api-implementer.md) |
| `code-integrator` | Prepare the assigned integration or inspect assigned source findings; return a version-bound result | [code-integrator.md](references/code-integrator.md) |

A legacy implementation-worker assignment with API scope uses the
`api-implementer` entrypoint. Existing `work_scope.kind=process_output`
assignments retain [worker-diagnosis.md](references/worker-diagnosis.md).

For an explicit request to initialize an uninitialized target, read
[project-init.md](references/project-init.md). Ordinary rewrite sessions never
rerun initialization.

## Shared Constraints

- Keep the assigned role, scope, canonical root, and worktree. Return a specific
  missing input or interface gap instead of inventing identity or authority.
- Execute returned commands in their bound `cwd` with their original argv.
  Apply only extensions documented by your role's protocol. Supply required
  environment variables without printing their values.
- Use public engine interfaces. Never mutate runtime state files or infer the
  current operation from artifact recency. Read-only runtime inspection is for
  diagnosing a specific interface gap, not reconstructing the state machine.
- Recordings and `.traffic-e2e/local/artifacts/` are immutable evidence. Preserve
  engine-generated `progress.yaml`. Do not synthesize evidence, rewrite source
  behavior to manufacture a pass, or replace engine aggregation with scripts.
- Target behavior must use normal product code and configuration, never recorded
  results, expected responses, Replay sessions, reports, or private engine state.
- Only the coordinator executes workflow mutations and formal acceptance.
  Worker-local reports and integrator results do not mark a work item complete.
- Coordinators must actually invoke the task runtime's agent-list/status tool
  for a fresh pass over all outstanding worker assignments before waiting and
  after each bounded wait. In Claude Code, invoke the built-in `ListAgents`
  (`/list-agents`) when available. Historical reports and absent stop events do
  not satisfy this requirement. Follow the
  [runtime query protocol](references/coordinator-worker-protocol.md#mandatory-runtime-queries).
