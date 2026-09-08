---
name: backend-rewrite
description: "Orchestrate, verify, and deliver backend service rewrites from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns coordinator sequencing, one persistent dedicated implementation subagent and worktree per API or process-output item, repair routing, completion state, and delivery."
---

# Backend Rewrite

Use the `backend-rewrite` binary as the authoritative **rewrite engine**. It
maintains workflow state, selects legal actions, and evaluates verification and
completion gates. Recorded artifacts are read-only diagnostic evidence.

The **workflow coordinator** and **implementation workers** are AI roles. The
**task runtime** creates and resumes worker tasks, supplies their handles and
events, and controls concurrency and queuing. In this skill, `coordinator` means
the workflow coordinator, `worker` means an implementation worker, and `target`
means the target service or repository. Engine-owned traffic execution is
separate from the task runtime.

## Select The Current Role

Role follows the task assignment, not the completeness of its attached data:

- **Workflow coordinator:** the main/root session that owns the rewrite workflow.
  Execute engine-issued actions, maintain worker/worktree bindings, receive and
  integrate handoffs, invoke verification, and deliver the completed workflow.
  Dispatch every returned implementation action through the task runtime and
  continue other executable work. Implementation diagnosis and code repairs
  belong to workers.
- **Implementation worker:** a task dispatched to implement one work item.
  Its role remains worker through missing inputs, interruptions, resumed turns,
  failed acceptance, and completion. It never becomes a workflow coordinator.
  Fetch current issue and dispatch identity through `evidence --api` or
  `evidence --process-output` using the assignment's canonical root and exact
  scope. Follow [worker-diagnosis.md](references/worker-diagnosis.md). Never advance engine state, execute acceptance, or take another item.

Worker scope determines the diagnosis path, not a different authority level:

- `work_scope.kind=api`: diagnose and implement the exact API using its returned
  evidence, source/target code, and local tests.
- `work_scope.kind=process_output`: diagnose the returned
  `comparison_observation`, inspect source paths required by a profile rule
  candidate, and implement normal startup/output behavior. Do not request API
  evidence queries or invent traffic operations.

The engine supplies current work-item facts through its APIs; a prose handoff
is not their authoritative store. Task identity and the assigned absolute
worktree come from the task runtime and retained assignment. If the known
identity cannot resolve the required information, report the specific missing
input or engine API gap to the coordinator and retain the worker role. Do not
guess a scope, initialize another workflow, or edit before the assigned worktree
is established. A missing input never grants coordinator permissions.

## Reference Routing

The workflow coordinator reads [workflow.md](references/workflow.md) at every
session start or resume, including sessions that only monitor existing workers.
It is the single main-loop and action-handling guide. Load conditional
references directly from this file only when their trigger occurs:

- Read [recording-lifecycle.md](references/recording-lifecycle.md) for a
  `recording_required`, `recording_in_progress`, or
  `comparison_recording_required` action, before requesting fresh standard
  traffic, or when applied capture rules require a consolidated recording
  refresh.
- Read
  [case-pattern-identification.md](references/case-pattern-identification.md)
  only for `case_pattern_identification_required`.
- Read
  [coordinator-rule-actions.md](references/coordinator-rule-actions.md)
  only after worker confirmation and only when that worker returns inputs for
  response-rule, recorder-capture, dependency-rule, or process-output-rule
  planning, or confirmed evidence exposes one of those coordinator-owned
  planners. This includes rejection-count hints and `unrecorded-ip` preflight;
  inspect supported recorder rules before submitting an IP capture defect.
- Read
  [recovery-and-system-repair.md](references/recovery-and-system-repair.md) only
  for `recovery_required`, `system_repair_required`, or an engine-issued
  repair verification action.
- Read
  [coordinator-worker-protocol.md](references/coordinator-worker-protocol.md)
  before the first implementation dispatch and for worker status checks,
  completion events, resume, transfer, integration, or worker cleanup.
- Read
  [target-implementation-requirements.md](references/target-implementation-requirements.md)
  before integrating a worker change, resolving an integration conflict that
  changes target code, or making a shared target refactor. Ordinary coordinator
  transitions do not load target implementation requirements.

Implementation workers read
[worker-diagnosis.md](references/worker-diagnosis.md) and
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
`brz-http`, read [http-client.md](references/http-client.md) before constructing the client,
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
image-local writable directory, read [target-startup-inputs.md](references/target-startup-inputs.md)
before changing startup inputs or either Dockerfile. A required environment
variable is actionable as soon as source behavior proves the target logic needs
it; do not wait for a target failure. Source application environment captured
during initialization is already injected into every target start. Workers
return a startup input only for an override or addition, and the workflow
coordinator applies it through the documented startup API, using
`--from-source` when appropriate. Do not load this reference during one-time
initialization merely to search for possible inputs.

Read [project-init.md](references/project-init.md) only when the caller
explicitly asks to initialize an uninitialized target repository. Project
initialization is manual and one-time; normal rewrite and resumed sessions
assume it is complete and never rerun it.

## Shared Engine Contract

A fresh standard recording requires explicit user authorization.

Response schema v26 contains an `action` object with exactly `kind`, `summary`,
`details`, and `commands`. This action schema version is independent of target
repository configuration versions. `status` (including scoped status) and
`next` return scheduling state, a short issue summary, and coordinator commands.
They do not embed issue diagnostics or an evidence command. Read scheduling
facts from `action.details` and execute only command roles actually present;
never guess legacy fields or missing transitions.

The coordinator dispatches the worker role, exact work scope, canonical target
root, and absolute assigned worktree. It does not forward action JSON, evidence
IDs, commands, or diagnostic payloads. Workers start or resume with the stable
read-only entrypoint for their assignment:

```text
backend-rewrite --target-root <canonical-root> evidence --api '<METHOD pattern>'
backend-rewrite --target-root <canonical-root> evidence --process-output <id>
```

Use exactly one selector. After dispatch confirmation, the overview supplies
current workflow/recording and binding/dispatch identity in `context`, the full
issue in `facts.issue`, and API detail commands in `queries`. Process-output
workers read `facts.issue.comparison_observation` and receive no API queries.
Workers retain this identity for their return handoff; further opaque
`evidence <query-id>` commands remain bound to the evidence they describe.
See [worker-diagnosis.md](references/worker-diagnosis.md) for confirmation
waiting and stale-context handling.

Every returned command has a canonical `cwd` and argv whose absolute
`--target-root` is already bound. Execute it opaquely without reconstructing,
combining, shell-evaluating, or changing arguments. Supply named required
environment variables without printing their values. Compact JSON is the
default; use global `--pretty` only for interactive human inspection. The scoped
evidence commands above are worker entrypoints; returned query and action argv
remain opaque. The sole documented argv extension is the target-quality
exception in [workflow.md](references/workflow.md).

The workflow coordinator starts and resumes with unscoped
`backend-rewrite status` and follows [workflow.md](references/workflow.md#coordinator-loop) for
its executable-work loop, event handling, and periodic polling. `pending` counts
ready coordinator operations; `terminal_allowed` governs completion. The engine
selects work; the task runtime limits worker concurrency. Scoped status serves
assigned work-item inspection and does not replace the global coordinator loop.
Default `workflow` contains only `id` and `revision`; `inventory` expands its
metadata and ready/waiting counts. Do not infer scheduling from `workflow.phase`.

Use `backend-rewrite status [--api '<METHOD pattern>' | --process-output <id>]`
when an action response was lost or a session resumes. Coordinator scheduling uses the
canonical target's unscoped status; assigned workers restore diagnostics through
their scoped evidence entrypoint. Never infer state from artifact recency. Never
mutate engine runtime files. Use action, status, and evidence APIs as the
primary interface; report an insufficient API surface as an engine API gap.
Read-only runtime inspection is allowed when needed to diagnose such a gap,
but its layout is not a stable workflow contract.

## Completion Contract

Keep these states distinct:

- **Worker handoff ready:** the assigned worker returned the initial overview's
  work-scope, issue and dispatch identity, proven cause and supporting evidence,
  changed files/shared impact, patch or commit, local tests, coordinator inputs,
  and unresolved risks. Its binding and worktree remain active.
- **Work item complete:** the workflow coordinator integrated the handoff and the
  engine-issued acceptance returned the API or process output as complete
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
blocked under [worker-diagnosis.md](references/worker-diagnosis.md). A blocker
is not successful completion and must never be reported as
`terminal_allowed=true`.

## Target And Repository Contract

`.traffic-e2e/local/artifacts/` is readable, read-only evidence. Preserve
engine-generated `progress.yaml`; do not hand-edit it, replace engine
aggregation with bulk scripts, make target code consume recorded results, or
modify source behavior to manufacture evidence. The coordinator, not a worker,
executes engine-issued transitions and requests final progress publication.

The target implements ordinary product behavior and source-compatible
configuration. It must not read cases, Replay sessions, expected responses, or
reports. The engine owns the isolated target runtime, build caching,
traffic dependencies, readiness, signals, and cleanup. See
[project-init.md](references/project-init.md) only for the one-time target
contract and initialization procedure. Target-code changes and integration use
[target-implementation-requirements.md](references/target-implementation-requirements.md).
