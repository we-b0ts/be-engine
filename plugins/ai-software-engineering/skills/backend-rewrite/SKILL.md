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

- **State-machine coordinator (main/root agent):** use this role unless a parent explicitly assigned one
  complete implementation work scope, action, and absolute worker worktree.
  Own coordinator commands and state mutations, worker/worktree bindings,
  integration, serialized traffic, repository gates, and final delivery. Stop
  at every `implementation_required` action and dispatch its dedicated worker
  before work-item diagnosis; continue other executable items after dispatch.
- **Assigned API worker:** use this role only when the handoff contains
  `action.details.work_scope.kind=api`, its exact API, the complete action, and
  an absolute worker worktree. Own that API's returned evidence, source/target
  diagnosis, implementation, and local tests. Never advance coordinator state,
  execute acceptance, or operate another work item.
- **Assigned process-output worker:** use this role only when the handoff
  contains `action.details.work_scope.kind=process_output`, its ID, the complete
  action, and an absolute worker worktree. Own diagnosis of the returned
  `comparison_observation`, source-path analysis required by a returned profile
  rule candidate, target startup/output implementation, and local tests. Do not
  expect API evidence commands, invent traffic operations, advance coordinator
  state, execute acceptance, or operate another work item.

If the handoff omits an exact work scope, complete action, or absolute
worktree, remain the state-machine coordinator rather than inferring a worker role.

## Reference Routing

The state-machine coordinator reads [workflow.md](references/workflow.md) before
advancing the workflow. Load these conditional references directly from this
file only when their trigger occurs:

- Read [recording-lifecycle.md](references/recording-lifecycle.md) for a
  `recording_required`, `recording_in_progress`, or
  `comparison_recording_required` action, before requesting fresh standard
  traffic, or when applied capture rules require a consolidated recording
  refresh.
- Read
  [case-pattern-identification.md](references/case-pattern-identification.md)
  only for `case_pattern_identification_required`.
- Read
  [coordinator-evidence-actions.md](references/coordinator-evidence-actions.md)
  only after worker confirmation and only when that worker returns inputs for
  response-rule, recorder-capture, dependency-rule, or process-output-rule
  planning, or confirmed evidence exposes one of those coordinator-owned
  planners. This includes rejection-count hints and `unrecorded-ip` preflight;
  inspect supported recorder rules before submitting an IP capture defect.
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

When an assigned API worker calls an outbound HTTP dependency through
`brz-http`, read [http.md](references/http.md) before constructing the client,
defining endpoints, or implementing request and response handling.

When an assigned API worker exposes an inbound HTTP API or starts an
`http-server` listener, read [http-server.md](references/http-server.md) before
defining routes, authentication, request binding, or server lifecycle.

When an assigned API worker uses memcache `CacheService`, read
[memcache.md](references/memcache.md) before constructing the cache or calling
`get`/`set`.

When an assigned API worker uses `brz-redis`, read
[redis.md](references/redis.md) before choosing a `RedisService` topology or
calling its typed Redis contract.

When an assigned API worker uses `brz-mysql`, read
[mysql.md](references/mysql.md) before constructing `MysqlService`, defining
row mappings, issuing queries, or adding transaction and table-selection code.

When target startup installs process logging through `brz-logs`, or a worker
changes application log routing, buffering, flushing, or shutdown, read
[logs.md](references/logs.md) before changing the subscriber or emitting
product logs.

When source analysis, target implementation, or startup diagnosis identifies a
required environment variable, dotenv import, configuration mount, or
image-local writable directory, read [startup.md](references/startup.md)
before changing startup inputs or either Dockerfile. A required environment
variable is actionable as soon as source behavior proves the target logic needs
it; do not wait for a target failure. Source application environment captured
during initialization is already injected into every target start. Workers
return a startup input only for an override or addition, and the state-machine
coordinator applies it through the documented startup API, using
`--from-source` when appropriate. Do not load this reference during one-time
initialization merely to search for possible inputs.

Read [project-init.md](references/project-init.md) only when the caller
explicitly asks to initialize an uninitialized target repository. Project
initialization is manual and one-time; normal rewrite and resumed sessions
assume it is complete and never rerun it.

## Shared Coordinator Contract

A fresh standard recording requires explicit user authorization.

Response schema v25 contains an `action` object with exactly `kind`, `summary`,
`details`, and `commands`. This action schema version is independent of target
repository configuration versions. `status` (including scoped status) and
`next` return scheduling state, a short issue summary, and legal commands;
they do not embed issue diagnostics. Read scheduling facts from
`action.details`. For either worker role, after dispatch confirmation execute
the single `action.commands.evidence` command to fetch the issue overview.
Read diagnostic facts from `facts.issue`; API workers then use the exact
commands under the overview's `queries`. Process-output workers read
`facts.issue.comparison_observation` and receive no API queries. The state-machine
coordinator forwards the compact action and evidence entrypoint to its worker
without fetching diagnostics for scheduling. Execute only command roles
actually present under `action.commands`; never guess legacy fields or missing
transitions.

Every returned command has a canonical `cwd` and argv whose absolute
`--target-root` is already bound. Execute it opaquely without reconstructing,
combining, shell-evaluating, or changing arguments. Supply named required
environment variables without printing their values. Compact JSON is the
default; use global `--pretty` only for interactive human inspection. The sole
documented argv extension is the target-quality exception in
[workflow.md](references/workflow.md).

Start and resume in the initialized canonical target repository with unscoped
`backend-rewrite status`. An initialized project without a workflow returns the
command that starts it. Default `workflow` contains only `id` and `revision`;
`inventory` retains phase, recording, comparison, and selected-scope metadata.
Choose the next operation from `pending`, `action`, and `terminal_allowed`.
Do not infer scheduling from `workflow.phase`.

The state-machine coordinator consumes one executable-work loop. Top-level
`pending` counts only actions it can perform now; running or resource-waiting
work is excluded. While `pending > 0`, execute the returned action and report
its result. When it reaches zero, wait for a runtime completion event or the
returned polling delay (normally 30 seconds), then query status again. End only
when `terminal_allowed` permits delivery. `inventory` expands English ready and
waiting counts; API `unverified` counts are not a dispatch queue. Scoped status
retains this same global `pending` count while showing the selected item's action;
use unscoped status for the coordinator loop.

The engine owns selection across all APIs and process-output items, including
parked implementation issues. The coordinator imposes no worker concurrency
limit; the runtime owns its concurrency and queuing. `next` and target-quality
execution are detached so the coordinator can continue dispatch and feedback
while verification runs. Follow the
[coordination loop and event protocol](references/implementation-worker-coordination.md)
for actual dispatch/resume, `worker_status_required`, `integration_required`,
worker completion callbacks, and recovery. A received and integrated handoff
schedules only its owning API's acceptance. Defer cross-API impact to final
unified verification. Preserve evidence confirmation and final coverage gates.

Use `backend-rewrite status [--api '<METHOD pattern>' | --process-output <id>]`
when an action response was lost or a session resumes. Coordinator scheduling uses the
canonical coordinator's unscoped status; assigned workers use their scoped
status. Never infer state from artifact recency. Never
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
  output satisfies this recording batch's validation requirements for one target
  content fingerprint. `workflow.require_comparison=false` permits API completion
  after Replay; skipped Comparison remains `comparison_current=false`. The first
  completed batch enables Comparison for future recordings without changing the
  current batch. Follow a final `advance_required` to persist that transition;
  never override the batch requirement or infer it from historical pass counts.
  Only then run the
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
