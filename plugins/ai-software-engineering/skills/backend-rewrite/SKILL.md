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

Read [project-init.md](references/project-init.md) only when the caller
explicitly asks to initialize an uninitialized target repository. Project
initialization is manual and one-time; normal rewrite and resumed sessions
assume it is complete and never rerun it.

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

Response schema v13 contains an `action` object with exactly `kind`, `summary`,
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

At the start of a main-orchestrator session, read
`.traffic-e2e/local/block.md` when it exists. When you determine that progress
is blocked and are about to stop, create or update that file with the context
you consider useful for resuming. Remove it when the blocker is resolved. Treat
it as AI-owned handoff context, never as coordinator state;
`backend-rewrite status` remains authoritative.

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
5. After confirmation, execute a returned `advance_required` action immediately;
   it proves the current worker is confirmed and supplies the exact next pending
   API command. If an older or lost response does not expose that action, use
   read-only `status`, then `inventory` only as needed to recover it.
6. When workers return tested handoffs, batch compatible integrations into the
   canonical worktree, freeze its content fingerprint, and execute each API's
   unchanged coordinator-issued acceptance. When it returns
   `target_quality_required`, execute its exact command in the bound canonical
   worktree, then execute the returned `advance_required`; workers never
   execute this repository gate.
7. If a handoff identifies a high-impact shared or global change, the main
   orchestrator may explicitly schedule selected stale APIs with `verification
   request`; this is extra early validation and never replaces final coverage.
8. Repeat until the coordinator permits terminal completion or a proven blocker
   prevents further progress.

Recording, focused Replay, and comparison share one serialized traffic lane.
Serialize each live operation, not the complete lifecycle of one API. Expensive
worker diagnosis, coding, and tests may run concurrently while the main
orchestrator advances other pending APIs. Do not wait for one worker while
another pending API can advance.

Keep the standard cases immutable through ordinary repair attempts. A failed
focused attempt changes the target and reuses those cases; it does not itself
authorize fresh traffic. Later integrated edits may invalidate an API's
verified content fingerprint. The coordinator exposes it as
`revalidation_pending`, defers it while normal pending or implementation work
remains, and drains every stale API against one final fingerprint before
terminal completion. A commit that only packages the same effective worktree
content does not change this fingerprint.

When a worker proves that source code consumes an exact response-driving
endpoint absent from recorded dependencies, it returns the endpoint and one
source file/symbol proof; it never guesses a Breeze resource or descriptor.
The orchestrator uses `recorder-capture plan` to resolve configured Breeze
capture, then applies the exact returned command immediately. That API waits
while other runnable work continues; after it drains, the coordinator combines
all applied capture rules into one fresh full-scope standard recording.

## Mandatory Dedicated API Implementation Workers

Each exact inventory API has one dedicated subagent handle and one worktree
from its first `implementation_required` until workflow
`terminal_allowed=true`. The API method/pattern is the binding identity. A new
issue ID, attempt, workflow revision, action kind, or comparison failure updates
the assignment but never creates another subagent for that API.

Every `implementation_required`, including a single-API workflow, is a hard
dispatch barrier. Before evidence, artifacts, code, or an API hypothesis, the
orchestrator creates the first worktree and real subagent or reactivates that
API's existing binding, hands off the complete action and canonical commands,
and executes the exact `confirm_worker` command with the returned handle.
Require either `action.details.worker.state=confirmed` when no API can advance,
or the post-confirmation `advance_required` action before any later `next`.

`resume_required` means the same handle and worktree, updated from the
integrated revision; a newly created subagent is replacement, not resume. Never
replace it silently. If it cannot be resumed, preserve the worktree and report
a capability blocker; ownership transfer requires explicit caller approval.

Before waiting for a bound worker, and once after a main-session restart or
user interruption, send one continue/reactivate message with the current
action to its stored handle. If the worker is active, let it continue; if it is
idle, this message resumes the same worker. Then wait only for the runtime's
worker-completion notification. Never infer worker activity from output-file
timestamps, process lists, worktree changes, or shell sleeps.

`TaskCreate`, TODO state, or narration is not dispatch. A real worker executes
only its assigned read-only evidence, proves and repairs one cause, runs local
tests, and returns source proof or proposed inputs for any coordinator-owned
mutation. Follow
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
  target content fingerprint. If acceptance returns `implementation_required`,
  update the same worker from the integrated revision and reactivate its stored
  handle with the new action/result; do not create a replacement worker.
- **Workflow complete:** `terminal_allowed=true` proves every API has current
  focused E2E and comparison evidence for the same target content fingerprint.
  Then run the caller-required repository checks and finish delivery.

Thus worker handoff ready is not API completion, and API completion is not
workflow completion. A later integrated change may move an API that was
already complete to deferred `revalidation_pending`, so retain every API
binding and worktree through per-API completion. Release them only after
`terminal_allowed=true` and they are no longer needed for delivery.

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
source-compatible configuration, and `.traffic-e2e/Dockerfile.e2e`. That
BuildKit multi-stage contract compiles the normal release target, copies it
into the pinned traffic-e2e Rust runtime, and exposes the target binary as its
foreground OCI entrypoint.

The coordinator owns build caching, the immutable image ID used across Replay
and Comparison, the run-owned network namespace, the read-only
`.traffic-e2e/local/boot` mount at `/traffic-e2e/config`, UID/GID `998:998`,
readiness, signals, and container cleanup. For Breeze-dependent targets, the
coordinator also owns the shared Breeze lifecycle and required Breeze mounts.
The target image must not read cases, Replay sessions, expected responses, or
reports. See [project-init.md](references/project-init.md) for the exact build,
runtime, TLS trust, logging, and isolation contract.

The existing coordinator-owned `backend-rewrite init preflight` must prove both
target `docker build`/one disposable `docker run` and the recording environment,
then return one authoritative structured result. Do not create a second
target-validation command or accept target-AI self-validation. An explicit
mock entrypoint is allowed before product startup exists, but it must honor the
final environment, mounts, UID, port/readiness, foreground lifetime, logging,
and `SIGTERM` contract. Treat its result only as container integration evidence,
never as migrated business behavior.

## Mandatory Breeze SDK Packages

Implement every used Breeze or platform SDK capability—including Memcache,
Redis, MySQL, Vintage, Motan, Auth, MCQ, Kafka, and equivalents—as its own
workspace package at `crates/breeze/<capability>` and expose it through the
corresponding `brz-<capability>` library. Use the canonical capability names
`memcache`, `redis`, `mysql`, `vintage`, `motan`, `auth`, `mcq`, and `kafka`.
`brz-auth` owns all authentication SDK implementations, including TAuth and
TAuth2. MCQ is the internal Memcache-backed queue and belongs in `brz-mcq`.
Product code MUST use the `brz-*` library; it MUST NOT depend directly on the
raw SDK or driver, place the implementation in an application or domain crate,
or combine multiple capabilities into one package. Create only packages the
product uses.

Read [configuration-compatibility.md](references/configuration-compatibility.md)
before implementing target configuration loading or accepting
configuration-dependent startup.
