---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend service rewrites from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns coordinator sequencing, one persistent dedicated implementation subagent and worktree per API or process-output item, repair routing, completion state, and delivery."
---

# Backend Rewrite

Use the `backend-rewrite` binary as the authoritative workflow coordinator.
Treat recorded artifacts as read-only diagnostic evidence and coordinator
actions as the only authority for workflow state, legal transitions, and gate
results.

## Select The Current Role

Choose exactly one role before taking action:

- **Main orchestrator:** use this role unless a parent explicitly assigned one
  complete implementation work scope, action, and absolute worker worktree.
  Own coordinator commands and state mutations, worker/worktree bindings,
  integration, serialized traffic, repository gates, and final delivery. Stop
  at every `implementation_required` action and dispatch its dedicated worker
  before diagnosis.
- **Assigned API worker:** use this role only when the handoff contains
  `action.details.work_scope.kind=api`, its exact API, the complete action, and
  an absolute worker worktree. Own that API's returned evidence, source/target
  diagnosis, implementation, and local tests. Never advance coordinator state,
  execute acceptance, or operate another work item.
- **Assigned process-output worker:** use this role only when the handoff
  contains `action.details.work_scope.kind=process_output`, its ID, the complete
  action, and an absolute worker worktree. Own diagnosis of the returned
  `comparison_observation`, target startup/output implementation, and local
  tests. Do not expect API evidence commands, invent traffic operations,
  advance coordinator state, execute acceptance, or operate another work item.

If the handoff omits an exact work scope, complete action, or absolute
worktree, remain the main orchestrator rather than inferring a worker role.

## Reference Routing

The main orchestrator reads [workflow.md](references/workflow.md) before
advancing the workflow. Load these conditional references directly from this
file only when their trigger occurs:

- Read [recording-lifecycle.md](references/recording-lifecycle.md) for a
  `recording_required`, `recording_in_progress`, or
  `comparison_recording_required` action, before requesting fresh standard
  traffic, or when applied capture rules require a consolidated recording
  refresh.
- Read
  [coordinator-evidence-actions.md](references/coordinator-evidence-actions.md)
  only after worker confirmation and only when that worker returns inputs for
  response-rule, recorder-capture, or dependency-rule planning, or confirmed
  evidence exposes one of those coordinator-owned planners.
- Read
  [recovery-and-system-repair.md](references/recovery-and-system-repair.md) only
  for `recovery_required`, `system_repair_required`, or a coordinator-issued
  repair verification action.
- Read
  [implementation-worker-coordination.md](references/implementation-worker-coordination.md)
  before the first implementation dispatch and whenever dispatch, resume,
  transfer, integration, or worker cleanup is required.
- Read
  [target-implementation-requirements.md](references/target-implementation-requirements.md)
  before integrating a worker change, resolving an integration conflict that
  changes target code, or making a shared target refactor. Ordinary coordinator
  transitions do not load target implementation requirements.

Both assigned worker roles read
[problem-diagnosis.md](references/problem-diagnosis.md) and
[target-implementation-requirements.md](references/target-implementation-requirements.md)
before changing target product code, startup, or configuration. Follow the
diagnosis branch selected by `work_scope.kind`. Do not preload conditional
coordinator references or target implementation requirements merely to
anticipate a later action.

When an assigned API worker exposes a Motan service through `brz-motan`, read
[motan-exporter.md](references/motan-exporter.md) before defining DTOs, service
adapters, or export endpoints. When target code calls a Motan dependency, read
[motan-referer.md](references/motan-referer.md) before defining its dependency
contract, client, authentication, or lifecycle. Read both only when the same
work scope owns both directions.

When an assigned API worker uses memcache `CacheService`, read
[memcache.md](references/memcache.md) before constructing the cache or calling
`get`/`set`.

When an assigned API worker uses `brz-redis`, read
[redis.md](references/redis.md) before choosing a `RedisService` topology or
calling its typed Redis contract.

Read [project-init.md](references/project-init.md) only when the caller
explicitly asks to initialize an uninitialized target repository. Project
initialization is manual and one-time; normal rewrite and resumed sessions
assume it is complete and never rerun it.

## Shared Coordinator Contract

A fresh standard recording requires explicit user authorization.

Response schema v20 contains an `action` object with exactly `kind`, `summary`,
`details`, and `commands`. This action schema version is independent of target
repository configuration versions. Read kind-specific facts only from
`action.details`. An API worker uses only the issue-scoped evidence commands
returned under `action.commands.evidence`; a process-output worker normally
receives none. Execute only command roles actually present under
`action.commands`; never guess legacy fields or missing transitions.

Every returned command has a canonical `cwd` and argv whose absolute
`--target-root` is already bound. Execute it opaquely without reconstructing,
combining, shell-evaluating, or changing arguments. Supply named required
environment variables without printing their values. Compact JSON is the
default; use global `--pretty` only for interactive human inspection. The sole
documented argv extension is the target-quality exception in
[workflow.md](references/workflow.md).

Use `backend-rewrite status [--api '<METHOD pattern>' | --process-output <id>]`
when an action response was lost or a session resumes. Never infer state from
artifact recency. Never
mutate coordinator runtime files. Use action, status, and evidence APIs as the
primary interface; report an insufficient API surface as a coordinator gap.
Read-only runtime inspection is allowed when needed to diagnose such a gap,
but its layout is not a stable workflow contract.

## Completion Contract

Keep these states distinct:

- **Worker handoff ready:** the assigned worker returned its work-scope and
  issue identity, proven cause, changed files/shared impact, patch or commit,
  local tests, coordinator inputs, unchanged acceptance, and unresolved risks.
  Its binding and worktree remain active.
- **Work item complete:** the orchestrator integrated the handoff and the
  coordinator-issued acceptance returned the API or process output as complete
  for the current target content fingerprint. A later integration may make it
  stale and require revalidation through the same binding.
- **Workflow complete:** `terminal_allowed=true` proves every API and process
  output is current for one target content fingerprint. Only then run the
  caller-required repository checks and finish delivery.

An evidence-proven unavailable external response-driving value may stop work as
blocked under [problem-diagnosis.md](references/problem-diagnosis.md). A blocker
is not successful completion and must never be reported as
`terminal_allowed=true`.

## Target And Repository Contract

`.traffic-e2e/local/artifacts/` is readable, read-only evidence. Preserve
coordinator-generated `progress.yaml`; do not hand-edit it, replace coordinator
aggregation with bulk scripts, make target code consume recorded results, or
modify source behavior to manufacture evidence. The coordinator, not a worker,
owns every state-changing transition and final progress publication.

The target implements ordinary product behavior and source-compatible
configuration. It must not read cases, Replay sessions, expected responses, or
reports. The coordinator owns the isolated target runtime, build caching,
traffic dependencies, readiness, signals, and cleanup. See
[project-init.md](references/project-init.md) only for the one-time target
contract and initialization procedure. Target-code changes and integration use
[target-implementation-requirements.md](references/target-implementation-requirements.md).
