---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend service rewrites from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns coordinator sequencing, one persistent dedicated implementation subagent and worktree per API, repair routing, completion state, and delivery."
---

# Backend Rewrite

Use the `backend-rewrite` binary as the authoritative workflow coordinator.
Treat recorded artifacts as read-only diagnostic evidence and coordinator
actions as the only authority for workflow state, legal transitions, and gate
results.

## Select The Current Role

Choose one role before taking action:

- **Main orchestrator:** use this role unless a parent explicitly assigned one
  API, issue/action, and worker worktree. Own coordinator commands, worktrees,
  dedicated API-subagent bindings, integration, serialized Replay/comparison,
  repository checks, and final delivery. Do not diagnose or implement an API
  before dispatch.
- **Assigned API worker:** use this role only when the handoff names one exact
  API, complete `implementation_required` action, and absolute worktree. Own
  that API's evidence, source/target diagnosis, implementation, and local tests.
  Never advance coordinator state, execute acceptance, or operate another API.

The main orchestrator reads
[workflow.md](references/workflow.md) before advancing the workflow and reads
[implementation-worker-coordination.md](references/implementation-worker-coordination.md)
before its first implementation dispatch. An assigned worker reads
[problem-diagnosis.md](references/problem-diagnosis.md) and loads
[`backend-engineering`](../backend-engineering/SKILL.md) before changing target
code. Do not load worker engineering guidance in the main orchestrator merely
to prepare a handoff.

## Coordinator Contract

Start or resume an initialized, all-configured-API workflow from the canonical
target repository:

```bash
backend-rewrite next
```

Before the first standard recording, add `--api '<METHOD path-or-pattern>'`
only when the caller explicitly requests a single-API recording. After the
coordinator publishes its stable inventory, select work with the exact
inventory method/pattern.

Response schema v8 contains an `action` object with exactly `kind`, `summary`,
`details`, and `commands`. This action schema version is independent of target
repository configuration versions. Read facts only from `action.details` and
execute only command roles actually present under `action.commands`; never
guess legacy fields or missing transitions.

Every returned command has a canonical `cwd` and argv whose absolute
`--target-root` is already bound. Execute it opaquely without reconstructing,
combining, shell-evaluating, or changing arguments. Supply named required
environment variables without printing their values. Compact JSON is the
default; use global `--pretty` only for interactive human inspection.

Use `backend-rewrite status [--api '<METHOD pattern>']` when an action response
was lost or a session resumes. Never infer state from artifact recency. Never
read, search, list, or summarize `.traffic-e2e/local/ai-forbidden/**`; report an
insufficient public action/status/evidence surface as a coordinator API gap.

## Main Orchestrator Loop

1. Execute `backend-rewrite next`, a returned opaque command, or scoped
   read-only `status` as required by the current action.
2. Read the complete action and `api_inventory`. Keep `workflow.scope` separate
   from the currently selected API.
3. Follow [workflow.md](references/workflow.md) for action-specific execution,
   waiting, recovery, fresh recording, rule, and repair semantics.
4. On every `implementation_required`, stop before evidence or code analysis.
   Create and bind the API worktree and dedicated subagent on its first issue;
   reactivate that same binding on every later issue.
5. After dispatch, if inventory still has a `status=pending` item and no
   `wait_required`, run read-only `backend-rewrite inventory`, select its exact
   method/pattern, and execute `backend-rewrite next --api '<exact API>'`.
6. When a worker returns a tested handoff, integrate it into the canonical
   worktree, freeze the target revision, and execute that API's unchanged
   coordinator-issued acceptance.
7. Repeat until the coordinator permits terminal completion or a proven blocker
   prevents further progress.

Recording, focused Replay, and comparison share one serialized traffic lane.
Serialize each live operation, not the complete lifecycle of one API. Expensive
worker diagnosis, coding, and tests may run concurrently while the main
orchestrator advances other pending APIs. Do not wait for one worker while
another pending API can advance.

Keep the standard cases immutable through ordinary repair attempts. A failed
focused attempt changes the target and reuses those cases; it does not itself
authorize fresh traffic. Later integrated edits may invalidate an API's target
fingerprint and requeue its prior evidence.

## Mandatory Dedicated API Implementation Workers

Each exact inventory API has one dedicated subagent handle and one worktree
from its first `implementation_required` until coordinator `complete`. The API
method/pattern is the binding identity. A new issue ID, attempt, workflow
revision, action kind, or comparison failure updates the assignment but never
creates another subagent for that API.

The first `implementation_required`, including in a single-API workflow, is a
hard dispatch barrier. Before the main orchestrator executes evidence, opens a
case, reads source or target implementation code, or forms an API hypothesis,
it must:

1. preserve the exact API, workflow/issue identity, complete action, canonical
   `cwd`, and all opaque command specs;
2. create the isolated worktree from the current integrated target revision;
3. invoke the runtime's real subagent mechanism with that handoff;
4. capture the returned subagent handle; and
5. retain the `API -> subagent handle -> worktree` binding.

On every later `implementation_required`, update the bound worktree from the
integrated revision and resume or reactivate the stored handle with the new
complete action and raw acceptance result. A new subagent invocation without
that handle is replacement, not resume, even if its prompt says "resuming".
Never replace the dedicated subagent silently. If the stored handle cannot be
resumed, preserve its worktree and report a capability blocker; transfer
requires explicit caller approval.

`TaskCreate`, TODO state, narration, or delayed intent is not dispatch. If a
real subagent is unavailable, report that capability blocker instead of
implementing in the main orchestrator.

The worker executes only its assigned evidence, case-dependency, and returned
read-only help commands, proves one cause, implements one compatible repair,
runs focused local tests, and returns its handoff. It returns source proof and
proposed inputs when a rule, route, or other coordinator mutation is needed;
only the orchestrator executes that mutation. Follow
[implementation-worker-coordination.md](references/implementation-worker-coordination.md)
for exact worktree placement, scheduling, integration, reactivation, and
cleanup.

## Completion Contract

Keep these states distinct:

- **Worker handoff ready:** the worker returned API and issue identity, proven
  cause/evidence, changed files and shared-module impact, patch or commit,
  tests, required coordinator inputs, and unresolved risks. Its current turn
  may become idle, but its API binding and worktree remain.
- **API complete:** the orchestrator integrated the handoff and the
  coordinator-issued acceptance returned that API as `complete` for the current
  target revision. If acceptance returns `implementation_required`, update the
  same worker from the integrated revision and reactivate its stored handle
  with the new action/result; do not create a replacement worker.
- **Workflow complete:** `terminal_allowed=true` proves every API has current
  focused E2E and comparison evidence for the same target revision. Then run
  the caller-required repository checks and finish delivery.

Thus worker handoff ready is not API completion, and API completion is not
workflow completion. Remove an API worktree and release its binding only after
that API is complete and the worktree is no longer needed.

An evidence-proven unavailable external response-driving value may stop work as
blocked under [problem-diagnosis.md](references/problem-diagnosis.md). A blocker
is not successful completion and must never be reported as
`terminal_allowed=true`.

## Evidence And Repository Contract

`.traffic-e2e/local/artifacts/` is readable, read-only evidence. Preserve
coordinator-generated `replay-progress.yaml` and `comparison-progress.yaml` and
commit their verified changes with the target change. Do not hand-edit them,
replace coordinator aggregation with bulk scripts, make target code consume
recorded results, or modify source business behavior to manufacture evidence.

The initialized target repository provides ordinary product implementation,
source-compatible configuration, and the generic lifecycle boundary:

```text
scripts/<project>-cli start --e2e \
  --boot-dir .traffic-e2e/local/boot --port <port>
scripts/<project>-cli stop
```

Compile once per E2E start and launch release output when the normal compile
supports it. Keep `stop` idempotent. The target CLI must not read cases, Replay
sessions, expected responses, or reports.

Read [configuration-compatibility.md](references/configuration-compatibility.md)
before implementing target configuration loading or accepting
configuration-dependent startup. Read
[platform-breeze-runtime.md](references/platform-breeze-runtime.md) only for a
Platform Java/Tomcat source whose dependency clients are Breeze-owned; that
reference adds the Breeze-specific startup contract.
