---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend rewrites from source behavior and recorded traffic. Use for cross-language ports, API migrations, and compatibility replacements; coordinate read-only repository analysis, API implementation, and code integration through the backend-rewrite state machine."
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

The workflow has one engine and five agent roles. The task runtime is execution
infrastructure for agent handles, events, queuing, and concurrency; it is not a
workflow agent role and is never workflow authority.

| Actor | Identity | Owns | Must not do |
| --- | --- | --- | --- |
| Rewrite engine | `backend-rewrite` and `traffic-e2e` | Workflow state, legal action selection, evidence identity, traffic serialization, verification, and terminal eligibility | Invent task-runtime state or perform source diagnosis |
| Rewrite coordinator | Main/root `coordinator` task | Execute engine actions, dispatch and reconcile agents, apply coordinator-owned inputs, publish reviewed integration candidates, invoke acceptance, and deliver | Diagnose business source, edit target code, or mark work complete from an agent report |
| Repository analyst | `repository-analyst` assignment | Analyze source routes and module relationships read-only, distinguish static/dynamic routes, and incrementally assign new APIs to persistent groups | Edit code or configuration, bind an implementer, run Replay, or mutate workflow state |
| API implementer | Fixed `api-implementer-N` slot | Process assigned same-group API batches one API at a time, run per-API local review, and return reviewed subsets that may span assigned groups | Mutate workflow state, publish to the canonical target, or accept its own work |
| Code integrator | `code-integrator` assignment | Prepare one retained integration/review candidate, resolve assigned conflicts and routine quality issues, run candidate review, and return a version-bound result | Act as an API implementer, mutate engine state, or report implementation-worker activity |
| API expert | Engine-requested `api-expert` assignment | Investigate one reserved API read-only and return evidence-backed findings for its existing API implementer | Edit code, own the API, mutate workflow state, or satisfy implementation/acceptance gates |

API implementers build/debug and run tests relevant to their changes as needed;
they do not need to run Clippy. Worker and ordinary integration review check
Source rules, Replay isolation and exact delivery identity without executing
repository quality commands. Daily integration uses focused builds/tests as
needed. After implementation and ordinary delivery drain, the engine requires
`pre_revalidation_review_required`: the retained integrator executes the tool
named in `details.quality_check` across `details.quality_paths` on the final
committed candidate. For `cargo-clippy`, run `cargo clippy --workspace
--all-targets -- -D warnings` in each applicable Rust project; other tools follow
the project's language and configuration. After success, execute the returned
`review check --pre-revalidation --quality-check TOOL --worktree ...` command.
This records the agent's successful check and runs Source/isolation checks; the
engine never executes repository quality commands. Report the tool only after
it passed on that candidate. Reuse a current passing result for the same code
and inputs; do not repeat it for each API in the final sweep. The integrator fixes routine formatting/lint issues; API
behavior decisions return to the responsible implementer. Only the coordinator
publishes and admits the exact checked candidate. The state machine requires a
current final-stage receipt before full revalidation and final delivery.

The normal ownership flow is:

```text
rewrite engine -> coordinator -> API implementer -> coordinator -> code integrator -> coordinator -> rewrite engine
                       \-> repository analyst -> coordinator -> rewrite engine
                       \-> API expert -> coordinator -> existing API implementer
```

The coordinator remains the only bridge between agent results and engine
mutations. An API expert advises the existing API implementer through the
coordinator; it never creates another implementation owner.

`route_analysis` belongs to the repository analyst and has no implementation-worker
binding. The coordinator applies its result through the existing engine action.
External system owners may repair infrastructure, but they are outside this
agent-role model.

## HTTP Route Work Scope

Use the engine's exact canonical path/pattern, for example
`/api/subscriptions/*`, for dispatch, evidence, review, and acceptance. Each API
retains one current implementation assignment and covers every included recorded
method. Several APIs and groups share a fixed implementer/worktree. Do not split
methods into implementers or use `METHOD API` or combined selectors.

Inventory counts routes; method-specific evidence and progress retain `METHOD
API` identities. Acceptance replays a route's included methods in one session.
The route is complete only when all included methods are complete and skipped
only when all methods are skipped; a passing method does not complete a failing
sibling. Local `.traffic-e2e/regression.yaml` `only` and `skip` use the same routes;
`skip` takes precedence. Complete incremental repository analysis before starting
Replay. The engine finishes each group's Replay round before dispatching its
failure batch; per-API results remain independent. After dispatch, prioritize
never-attempted APIs at group boundaries before ordinary integration or acceptance.
Preserve the user's scope and execute returned commands unchanged.

New workflows use `max_implementers: 16` from local `regression.yaml`, fixed for
that workflow. Slot names and paths are `api-implementer-0` through the configured
limit under `.traffic-e2e/local/rewrite-worktrees/`. New groups are mapped to slots
round-robin; the coordinator can explicitly adjust future group assignments.
Use the [fixed implementer protocol](references/coordinator-implementers.md)
for batch identities, worktree reuse, runtime reports and partial handoffs.

## Role And Document Routing

Role comes from the assignment and persists through missing inputs, failures,
resumed turns, and completed handoffs. Read only your role's entrypoint and the
references it requests.

Role entrypoints remain separate because they define different authorities.
Do not merge coordinator, repository-analyst, API-implementer, code-integrator,
or API-expert instructions into one operating guide.

| Role | Always read | Read only when routed by the entrypoint or current action |
| --- | --- | --- |
| Rewrite coordinator | [coordinator.md](references/coordinator.md) | `coordinator-*.md` matching the current action, including [analysis](references/coordinator-repository-analysis.md) and [fixed implementers](references/coordinator-implementers.md) |
| Repository analyst | [repository-analyst.md](references/repository-analyst.md) | Assigned source route declarations, mount registrations and module relationships |
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
