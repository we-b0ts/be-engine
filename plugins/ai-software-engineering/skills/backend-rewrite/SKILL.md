---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend rewrites from source behavior and recorded traffic. Use for cross-language ports, API migrations, and compatibility replacements; coordinate dedicated API implementers and a code integrator through the backend-rewrite state machine."
---

# Backend Rewrite

Use `backend-rewrite` as the authority for workflow state, legal actions,
verification, and completion. The target is the service being rewritten.

The deployment caller owns `traffic-e2e record` and its containers. Backend
rewrite consumes completed immutable batches under the target's
`.traffic-e2e/local/artifacts/recordings/<run-id>/`; it does not start capture or
import batches. For missing evidence or capture refreshes, read
[external recording evidence](references/coordinator-recording.md).

## Actor Model

The workflow has one engine and four agent roles. The task runtime is execution
infrastructure for agent handles, events, queuing, and concurrency; it is not a
fifth agent role and is never workflow authority.

| Actor | Identity | Owns | Must not do |
| --- | --- | --- | --- |
| Rewrite engine | `backend-rewrite` and `traffic-e2e` | Workflow state, legal action selection, evidence identity, traffic serialization, verification, and terminal eligibility | Invent task-runtime state or perform source diagnosis |
| Rewrite coordinator | Main/root `coordinator` task | Execute engine actions, dispatch and reconcile agents, apply coordinator-owned inputs, publish reviewed integration candidates, invoke acceptance, and deliver | Diagnose business source, edit target code, or mark work complete from an agent report |
| API implementer | `api-implementer` assignment | Diagnose and implement exactly one API route work item (all included recorded methods), run its local review, and return a version-bound handoff | Mutate workflow state, publish to the canonical target, or accept its own work |
| Code integrator | `code-integrator` assignment | Prepare one retained integration/review candidate, resolve assigned conflicts and routine quality issues, run candidate review, and return a version-bound result | Act as an API implementer, mutate engine state, or report implementation-worker activity |
| API expert | Engine-requested `api-expert` assignment | Investigate one reserved API read-only and return evidence-backed findings for its existing API implementer | Edit code, own the API, mutate workflow state, or satisfy implementation/acceptance gates |

API implementers build/debug and run tests relevant to their changes as needed;
they do not need to run Clippy. Worker and ordinary integration review check
Source rules, Replay isolation and exact delivery identity without executing
repository quality commands. Daily integration uses focused builds/tests as
needed. After implementation and ordinary delivery drain, the engine requires
`pre_revalidation_review_required`: the retained integrator executes the returned
`review check --pre-revalidation --worktree ...` command. That single engine
entrypoint runs the full quality suite, including Clippy, and source/isolation
checks, producing a final-stage receipt. Do not manually run the same full suite
before this command. The integrator fixes routine formatting/lint issues; API
behavior decisions return to the responsible implementer. Only the coordinator
publishes and admits the exact checked candidate. The state machine requires a
current final-stage receipt before full revalidation and final delivery.

The normal ownership flow is:

```text
rewrite engine -> coordinator -> API implementer -> coordinator -> code integrator -> coordinator -> rewrite engine
                       \-> API expert -> coordinator -> existing API implementer
```

The coordinator remains the only bridge between agent results and engine
mutations. An API expert advises the existing API implementer through the
coordinator; it never creates another implementation owner.

`route_analysis` is a read-only API-implementer task mode, not another role. External system owners may repair infrastructure, but
they are outside this agent-role model.

## HTTP Route Work Scope

Use the engine's exact canonical path/pattern, for example
`/api/subscriptions/*`, for dispatch, evidence, review, and acceptance. One route
owns one worker, worktree, and delivery covering every included recorded method.
Do not split methods into workers or use `METHOD API` or combined selectors.

Inventory counts routes; method-specific evidence and progress retain `METHOD
API` identities. Acceptance replays a route's included methods in one session.
The route is complete only when all included methods are complete and skipped
only when all methods are skipped; a passing method does not complete a failing
sibling. Local `.traffic-e2e/regression.yaml` `only` and `skip` use the same routes;
`skip` takes precedence. Preserve the user's scope and execute returned commands
unchanged; the engine selects the next route and any wait or non-Replay action.

## Role And Document Routing

Role comes from the assignment and persists through missing inputs, failures,
resumed turns, and completed handoffs. Read only your role's entrypoint and the
references it requests.

Role entrypoints remain separate because they define different authorities.
Do not merge coordinator, API-implementer, code-integrator, or API-expert
instructions into one operating guide.

| Role | Always read | Read only when routed by the entrypoint or current action |
| --- | --- | --- |
| Rewrite coordinator | [coordinator.md](references/coordinator.md) | `coordinator-*.md` matching the current action |
| API implementer | [api-implementer.md](references/api-implementer.md) | `api-implementer-*.md`, [target-code-rules.md](references/target-code-rules.md), and shared review rules as directed |
| Code integrator | [code-integrator.md](references/code-integrator.md) | [target-code-rules.md](references/target-code-rules.md), [source-review-rules.md](references/source-review-rules.md), and `code-integrator-*.md` as directed |
| API expert | [api-expert.md](references/api-expert.md) | Relevant read-only diagnostic methods in [api-implementer-diagnosis.md](references/api-implementer-diagnosis.md) and its routed specialty documents as directed; never code-repair or delivery instructions |

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
- Rule diagnosis and source proof belong to the API implementer; planning,
  application, and fresh verification follow the coordinator's rule protocol.
  Use current evidence and follow required policy-refresh actions.
- Target behavior must use normal product code and configuration, never recorded
  results, expected responses, Replay sessions, reports, or private engine state.
- Only the coordinator executes workflow mutations and formal acceptance.
  Worker-local reports and integrator results do not mark a work item complete.
- Coordinators must actually query runtime status for all outstanding worker
  assignments before waiting and after each bounded wait. Follow the
  [runtime query protocol](references/coordinator-agent-protocol.md#mandatory-runtime-queries).
- Coordinators execute engine commands directly, one at a time, without sleep,
  wrappers, or loops, and process each complete response. Follow the
  [coordinator execution rules](references/coordinator.md#execution-rules).
