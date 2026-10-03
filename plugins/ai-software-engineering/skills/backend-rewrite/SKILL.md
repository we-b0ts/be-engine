---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend rewrites from source behavior and recorded traffic. Use for cross-language ports, API migrations, and compatibility replacements; coordinate dedicated API implementers and a code integrator through the backend-rewrite state machine."
---

# Backend Rewrite

Use `backend-rewrite` as the authority for workflow state, legal actions,
verification, and completion. The target is the service being rewritten.

## Actor Model

The workflow has one engine and four agent roles. The task runtime is execution
infrastructure for agent handles, events, queuing, and concurrency; it is not a
fifth agent role and is never workflow authority.

| Actor | Identity | Owns | Must not do |
| --- | --- | --- | --- |
| Rewrite engine | `backend-rewrite` and `traffic-e2e` | Workflow state, legal action selection, evidence identity, traffic serialization, verification, and terminal eligibility | Invent task-runtime state or perform source diagnosis |
| Rewrite coordinator | Main/root `coordinator` task | Execute engine actions, dispatch and reconcile agents, apply coordinator-owned inputs, publish reviewed integration candidates, invoke acceptance, and deliver | Diagnose business source, edit target code, or mark work complete from an agent report |
| API implementer | `api-implementer` assignment | Diagnose and implement exactly one API work item, run its local review, and return a version-bound handoff | Mutate workflow state, publish to the canonical target, or accept its own work |
| Code integrator | `code-integrator` assignment | Prepare one retained integration/review candidate, resolve assigned conflicts, run candidate review, and return a version-bound result | Act as an API implementer, mutate engine state, or report implementation-worker activity |
| API expert | Engine-requested `api-expert` assignment | Investigate one reserved API read-only and return evidence-backed findings for its existing API implementer | Edit code, own the API, mutate workflow state, or satisfy implementation/acceptance gates |

The normal ownership flow is:

```text
rewrite engine -> coordinator -> API implementer -> coordinator -> code integrator -> coordinator -> rewrite engine
                       \-> API expert -> coordinator -> existing API implementer
```

The coordinator remains the only bridge between agent results and engine
mutations. An API expert advises the existing API implementer through the
coordinator; it never creates another implementation owner.

`route_analysis` is a read-only API-implementer task mode, not another role. Existing
`work_scope.kind=process_output` assignments are a legacy worker specialization,
not another core role. External system owners may repair infrastructure, but
they are outside this agent-role model.

## Select Your Agent Role

Role comes from the assignment and persists through missing inputs, failures,
resumed turns, and completed handoffs. Read only your role's entrypoint and the
references it requests.

| Assignment | Responsibility | Entrypoint |
| --- | --- | --- |
| Main/root workflow task: `coordinator` | Dispatch, reconcile results, execute engine transitions, invoke acceptance, deliver | [coordinator.md](references/coordinator.md) |
| API implementer: `api-implementer` | Diagnose and implement the assigned API; return evidence and checked code | [api-implementer.md](references/api-implementer.md) |
| Code integrator: `code-integrator` | Prepare the assigned integration or inspect assigned source findings; return a version-bound result | [code-integrator.md](references/code-integrator.md) |
| Engine-requested API expert: `api-expert` | Investigate the assigned API read-only; return findings and evidence to the coordinator | [api-expert.md](references/api-expert.md) |

A legacy implementation-worker assignment with API scope uses the
`api-implementer` entrypoint. Existing `work_scope.kind=process_output`
assignments use [api-implementer-diagnosis.md](references/api-implementer-diagnosis.md)
and its routed [process-output diagnosis](references/api-implementer-process-output.md).

For an explicit request to initialize an uninitialized target, read
[project-init.md](references/project-init.md). Ordinary rewrite sessions never
rerun initialization.

## Document Routing

Role entrypoints remain separate because they define different authorities.
Do not merge coordinator, API-implementer, code-integrator, or API-expert
instructions into one operating guide.

| Role | Always read | Read only when routed by the entrypoint or current action |
| --- | --- | --- |
| Rewrite coordinator | [coordinator.md](references/coordinator.md) | `coordinator-*.md` matching the current action |
| API implementer | [api-implementer.md](references/api-implementer.md) | `api-implementer-*.md`, [target-code-rules.md](references/target-code-rules.md), and shared review rules as directed |
| Code integrator | [code-integrator.md](references/code-integrator.md) | [target-code-rules.md](references/target-code-rules.md), [source-review-rules.md](references/source-review-rules.md), and `code-integrator-*.md` as directed |
| API expert | [api-expert.md](references/api-expert.md) | Relevant read-only diagnostic methods in [api-implementer-diagnosis.md](references/api-implementer-diagnosis.md) and its routed specialty documents as directed; never code-repair or delivery instructions |

Neutral shared contracts such as target-code and source-review rules keep
capability-based names because more than one role consumes them. Task-mode
documents use their owning role as a prefix, for example
`api-implementer-route-analysis.md`. Coordinator action documents use the
`coordinator-` prefix. These naming rules are documentation routing, not new
engine roles or action kinds.

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
  [runtime query protocol](references/coordinator-agent-protocol.md#mandatory-runtime-queries).
- Coordinators must not invoke `sleep` or wrap or loop engine commands. Execute
  engine commands directly, one at a time, and process each complete response
  before the next command. Follow the
  [coordinator execution rules](references/coordinator.md#execution-rules).
