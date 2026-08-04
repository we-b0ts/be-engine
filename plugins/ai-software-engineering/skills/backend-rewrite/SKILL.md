---
name: backend-rewrite
description: "Plan, implement, verify, and deliver backend service rewrites and migrations from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns migration sequencing, repair routing, completion state, and pull-request delivery."
---

# Backend Rewrite

Use the `backend-rewrite` binary for migration sequence and bounded
traffic evidence. The target AI owns source-code attribution and target-code
implementation; it does not operate the traffic engine. Recorded artifacts are
readable diagnostic evidence, while coordinator actions remain authoritative
for workflow state and gate results.

This skill is self-contained for ordinary rewrites. Do not load the
`traffic-e2e` skill. `backend-rewrite` uses the `traffic_e2e` crate and is the
complete executable coordinator interface; the target AI must not reconstruct
its operations from lower-level `traffic-e2e` commands. Load
`backend-engineering` only when an action requires target-code implementation
or review.

## Control Protocol

From the initialized target repository, start or continue the default
all-configured-traffic workflow:

```bash
backend-rewrite next
```

Before the first standard recording, use `--api '<METHOD path-or-pattern>'`
only when the caller explicitly narrows the recording to one API. After the
recording installs its API inventory, `next --api '<METHOD pattern>'` selects
that exact inventory item for one AI worker. When a selected dynamic pattern
needs its source registration route, the coordinator returns `input_required`;
continue with the requested `--source-route` for that API. Do not invent routes
for other inventory items.

The coordinator shares one immutable standard recording across the discovered
API inventory. It may retain multiple API-scoped `implementation_required`
work items so different AI workers can diagnose and edit code concurrently.
Each worker must keep using its exact `--api`; an acceptance command returned
for one API never authorizes advancing another. Recording, focused Replay, and
comparison share one serialized `traffic_runtime` lease. The same standard
baseline remains available to every inventory item.

Coordinator action schema v8 always has exactly four fields:
`kind`, `summary`, `details`, and `commands`. Read variant-specific facts only
from `action.details`; read executable commands only from
`action.commands.<role>`. Command roles are explicit (`execute`, `status`,
`advance`, `recover`, `evidence`, `apply`, or `acceptance`), and absent roles are
not legal transitions. Concurrent issues remain API-scoped and are never
published as parallel top-level `active_issue` or `next` fields. There are no
legacy action-level `command`, `issue`, `evidence_commands`, or `acceptance`
aliases. Never guess an old field path or rerun `next` merely because a command
role is absent.

Every command contains a canonical `cwd` and an argv array. Change to that exact
directory, then execute the argv without reconstructing, combining,
shell-evaluating, or changing its arguments. Supply named required environment
variables without printing their values.

`backend-rewrite status [--api '<METHOD pattern>']` is a read-only recovery
snapshot. With `--api`, it reconstructs that API's action even when another API
is selected. Use it when an earlier action response was lost or when resuming
an interrupted AI session.
`plan_apply_required` recovers the exact pending
`action.commands.apply` command with its `apply <plan-id>` argv.
The stored plan is an evidence-validated snapshot: the workflow revision
created by planning does not make its apply stale. If the plan report proves
that the selector is incomplete, rerun the same planner with the same evidence
ID and corrected selector inputs before apply; this replaces only the pending
preview and does not mutate recorder configuration.
`advance_required` means the prerequisite named in `action.summary` is already
available and the coordinator is ready for its next state transition. Execute
the exact `action.commands.advance` argv once; do not repeat the prior
recording, Replay, comparison, or implementation action. If
`action.kind=wait_required`, read the blocking API and live operation from
`action.details`, wait at least `retry_after_seconds`, and execute only
`action.commands.status`. Never use `recover` for a live owner and never launch
another recording, Replay, or comparison concurrently. If a previously
launched action is still known to be running, continue waiting rather than
launching its reconstructed command concurrently.

Read the bounded `api_inventory` summary from every initialized `next` or
`status` result. It includes `total`, `completed`, `pending`,
`implementation_required`, `current_index`, and `current_api`. When the main
orchestrator first observes `api_inventory.total > 1` in the current task, it
must read [parallel-api-coordination.md](references/parallel-api-coordination.md)
once before assigning subagents. Use the stable `total` as the trigger; do not
retrigger on the changing unfinished count. Subagents do not read that guide
merely because their API-scoped status includes the same inventory. An
individual worker may act only on its assigned API and must not stop when that
API alone completes. `terminal_allowed=true` means every inventory item has
current focused E2E and comparison evidence for the same target revision.
`workflow.scope` describes the standard-recording selector
(`all_configured_apis` when it was omitted); it is not the active action target.

`backend-rewrite` emits one compact JSON object per command by default so the
result can be captured atomically without `head`/`tail`. Use global `--pretty`
only for interactive human inspection.

Keep the standard case source stable during implementation. A nonpassing
focused E2E attempt reuses the same immutable cases after the target changes;
it does not trigger another recording. A passing focused E2E attempt advances
to a fresh comparison recording automatically.

For a multi-API workflow, the orchestrator owns worktree allocation,
state-mutating coordinator commands, integration, and serialized verification;
workers own API-level diagnosis, implementation, and focused tests in assigned
worktrees. Follow
[parallel-api-coordination.md](references/parallel-api-coordination.md) instead
of allowing workers to create worktrees or run private coordinators. Completed
API evidence is requeued when later integrated edits change the target
fingerprint.

After any focused attempt, read `latest_focused_e2e` from the `backend-rewrite next`
or `backend-rewrite status` result. Its `execution_mode` explicitly distinguishes
`fresh_standard_cases` from `reused_standard_cases`; use its recording run,
exact case source, case inventory, previous/current attempt numbers, and pass
status instead of inferring reuse from internal paths. This field describes the
latest completed focused attempt and does not imply that every `next` call ran
another attempt.

When the caller explicitly requests new traffic, the Recorder contract has
changed, or the source baseline has changed, request a fresh standard recording
through the coordinator:

```bash
backend-rewrite recording request \
  --kind standard \
  --reason <user-requested|recorder-contract-changed|source-baseline-changed> \
  --duration-seconds <positive-seconds> \
  --per-api-case-limit <positive-limit>
```

Omit `--api` to record every API admitted by recorder configuration, including
when replacing a previously narrowed workflow. Supply `--api '<METHOD path>'`
only when the caller explicitly requests a single-API fresh recording. The
defaults are 60 seconds and 100 cases per configured API pattern; the limit is
not a recording-wide total. Caller-supplied
positive values may replace them. A request identical to the current pending request returns the
same action and run; a matching completed manifest returns an advance action. A different
pending request is rejected unless the caller explicitly supplies
`--replace-pending`. The command invalidates evidence for every API derived
from the shared prior standard recording, preserves old artifacts, allocates a
new run ID, and returns one `recording_required` action. Read the allocated run
from `action.details.run_id` and execute the opaque `action.commands.execute`
argv exactly. It starts a detached coordinator-owned worker and returns
immediately; do not background it, pipe it through `head`/`tail`, or wait on a
shell task. Poll the exact status command returned by execution. While running,
owner status may return `recording_in_progress` with
`action.commands.status`; after finalization it returns `advance_required` with
`action.commands.advance`. `recovery_required` means the owner exited and its
exact `action.commands.recover` must run before retrying.
`action.details.input_mode=reused_atomic_recording` means
the coordinator found one finalized historical recording whose API selector
exactly equals the requested selector. An omitted selector matches only an
omitted historical selector; a single API matches only that exact single API.
Never split, merge, or narrow a recording because boot and case evidence are
one lifecycle. `action.details.input_mode=external_live_traffic` means no exact
atomic input was reusable and the action opens a fresh recording window; its
bounded `action.details.recording_input_diagnosis` contains recent candidate
scopes and rejection reasons. Never add `nohup`, curl loops, a replayer, or
driver parameters. Do not inspect internal state, search the traffic-e2e
implementation, or synthesize requests. A failed E2E attempt alone never
authorizes this transition.

For a recording bound to one or more explicit API selectors, the worker may
finalize as soon as every selected API reaches its per-API case limit; the
configured duration is an upper bound. An all-configured recording with no API
selector always observes the complete duration so low-frequency APIs still
have an opportunity to appear. This early completion is coordinator-owned and
does not change the status/advance polling protocol.

The public coordinator surface is the `backend-rewrite` binary with `next`,
`status`, `inventory`, `case`, `evidence`, `rule`, `dependency-rule`, `route`,
`repair`, `recording`, and `recover` subcommands. `repair verify` and `recording execute` are ID-bound action
commands returned by the coordinator, not commands whose arguments the AI
invents. The target AI may choose and compose these bounded transitions according to their documented
preconditions. Reading traffic artifacts may support diagnosis, but never
replaces a coordinator transition or authorizes editing generated evidence.

Read [workflow.md](references/workflow.md) for action semantics, phase order,
and recovery behavior.

## Problem Diagnosis And Repair

Problem diagnosis is mandatory for every `implementation_required` action. It
selects the one evidence-backed repair attempted before the next replay; it is
not an optional fallback after speculative implementation.

When the action is `implementation_required`:

1. Read the issue ID, kind, owner, representative, and hypotheses from
   `action.details`. Run only the
   `action.commands.evidence[*].command` argv for traffic facts.
2. For `representatives`, inspect the returned immutable `case_dir` and its
   request, expected response, candidate response when present, dependencies,
   and other persisted case evidence. When the result contains a
   `dependencies_command`, execute its exact argv for a compact target summary;
   select only the relevant target and execute its returned `detail_command`
   for bounded representative exchanges that keep keys, arguments, and
   responses associated. Do not write an
   ad hoc parser for `dependencies.jsonl` while this query answers the question.
   Inspect additional cases under
   `.traffic-e2e/local/artifacts/` when they can distinguish the active hypotheses.
3. Read [problem-diagnosis.md](references/problem-diagnosis.md) and follow its
   issue-specific evidence and source-proof route.
4. Inspect the matching immutable source code and target implementation and
   prove one cause.
5. Use [`backend-engineering`](../backend-engineering/SKILL.md) for the target
   repair and repository checks.
6. In a single-agent workflow, execute `action.commands.acceptance`; for target
   implementation this is the coordinator-issued `backend-rewrite next` that
   detects the repository change and reruns the same immutable cases. In the
   parallel workflow, the worker returns its tested change and the unchanged
   acceptance command to the orchestrator, which integrates the change and
   executes acceptance from the coordinator worktree.

Treat coordinator `possible_causes` as hypotheses, never conclusions. Preserve
source cache keys, expiry, bounds, eviction, negative caching, warmup,
concurrent load, refresh, and fallback semantics when they affect behavior.

Dependency cleanliness is case-scoped. Diagnose only the case clusters returned
by `dirty_clusters`; they group unmatched, unsupported, unsafe, and unused-case
events by protocol and endpoint. Each cluster has a stable `cluster_id` and only
the correlated pre-readiness interaction count; query `pre_readiness_traffic`
for the complete startup summary. `unused_global` and target activity outside
an active case do not fail the case gate. Treat pre-readiness traffic as
reference context for startup jobs, warmup, and local-cache hypotheses, never
as a gate or as proof of ownership. The dirty-cluster result includes a
`representative_dependencies_command` for its selected case when available;
execute it before expanding raw dependency artifacts.

`backend-rewrite case dependencies <case-dir>` is read-only and returns a
bounded target summary. It deliberately omits keys and response bodies; every
target carries an opaque `target_id` and an exact `detail_command`. The detail
query expands only that target and caps representative values. Redis detail
labels keys only for command shapes the coordinator understands. Memcached
detail returns representative keys and response outcome summaries but never
interprets or exposes flags, whose meaning is application-specific. Dependency
response previews are capped at 256 bytes and retain encoding, original length,
and truncation metadata. Complete small Redis scalar frames also expose a
`response_value`, so the AI does not need to parse RESP framing; inspect the
read-only artifact only when the preview is insufficient. Use raw
read-only case artifacts only when the selected detail remains insufficient.

For a dependency issue, the `dirty_clusters` evidence report's
`applicable_rule_planners` lists only the background-rule protocol planners
supported by the current clusters. Run
the returned protocol-specific help argv, then use
`backend-rewrite dependency-rule plan <protocol>` with the current evidence ID and only
the source-proven selector inputs shown there. The coordinator resolves the
current replay evidence, immutable case source, and source revision; none are
rule selector inputs. HTTP and Memcached expose different inputs, and
irrelevant protocol flags are intentionally unavailable; Redis exposes
command-specific `zcount`, `get`, `scard`, and `hgetall` selector inputs.
`get`, `scard`, and `hgetall` require exact keys; do not infer prefixes or
wildcards from recorded examples. When the plan reports
`reused_existing=true`, the protocol selector is already covered: execute the
returned apply-by-plan-ID action to confirm that reuse and refresh the current
derived evidence; it makes no duplicate config change. Inspect the bounded
plan coverage before apply. When it exposes an
incomplete selector, rerun the planner with the same evidence ID and complete
source-proven inputs; the new preview replaces the pending one without a
special replacement flag. Otherwise execute the plan report's exact apply argv
by plan ID.
After apply, inspect `evidence_reclassification` and execute its exact `next`.
The coordinator preserves immutable request, response, and dependency capture
files, reapplies the current background rules to the latest focused replay
report, rebuilds bounded dependency evidence, and revises that same attempt.
If responses already pass and the effective dependency view becomes clean, it
advances directly to comparison recording. Residual dirty evidence remains an
`implementation_required` action. A background rule is not a Recorder capture
contract change, so this path must not request fresh standard traffic or return
`recorder-contract-changed`. Do not use the lower-level
`config recorder plan|apply background-dependencies` interface during a rewrite.
If a session was interrupted after apply, discard cached actions and execute
the current `backend-rewrite next`. The coordinator repairs an obsolete
dependency-finalize failure against the current clean derived view and resumes
the same attempt; do not retry E2E, inspect internal state, or request new
traffic to recover it.

A background rule changes case ownership only: it proves that matching
asynchronous traffic is process-scoped and case-independent. It carries no
`independent` or `runtime_state` classification and never replaces destination
behavior. The target AI must determine from source and response evidence
whether those dependencies drive process state. If they do, implement the
source-compatible load, refresh, cache, fallback, and readiness behavior in
destination code, then verify the affected cases. `initial_load_timeout_ms`
only bounds source recording observation; it does not classify behavior.

When source code proves a supported response rule, use only the coordinator's
`backend-rewrite rule plan|apply` interface with a current `evidence_id`. When source
and bounded evidence prove a Recorder/Replay gap, external-data blocker, or
source change, use `backend-rewrite route`; it records the source reference and required
change and returns a coordinator-issued `repair verify <repair-id>` acceptance.
The AI cannot supply an acceptance command, and neither `next` nor
`recording request` can bypass the pending repair. A failed route leaves the
active target repair in place.

## Evidence And Internal State

`.traffic-e2e/local/artifacts/` is readable diagnostic evidence, not a forbidden
directory. Start with the exact `case_dir` returned by `representatives`, then
inspect other standard or comparison cases when useful. Keep every artifact
read-only and let coordinator output determine the active run, issue, gates,
and legal transition; never select workflow state by recency.

Never read, search, list, summarize, or otherwise inspect
`.traffic-e2e/local/ai-forbidden/**`. It is coordinator-owned internal state and is
not a diagnostic surface for a target rewrite. If a public action, status, or
evidence result is insufficient, report that coordinator API gap to the caller;
do not compensate by inspecting the internal directory or the traffic-e2e
implementation. This prohibition does not apply to maintainers working inside
the traffic-e2e engine repository under its own `AGENTS.md`.

`replay-progress.yaml` and `comparison-progress.yaml` are coordinator-generated,
versioned migration evidence. They retain durable values such as consecutive
success counts. Never hand-edit, reset, restore, or check out their changes to
clean the worktree. When the coordinator changes either file, include that
generated change in the same delivery commit as the verified target change.
This exception does not apply to ignored runtime state under
`local/ai-forbidden/` or to recordings and other generated artifacts.

Do not use bulk `jq`, Python, or ad-hoc shell processing as a substitute for
coordinator gate and aggregate results. Focused inspection of case files is
allowed. Do not make target code, configuration, tests, or fixtures consume
recorded responses or dependency outputs. Never modify source business
behavior to manufacture evidence.

## Repository Contract

Initialize once with:

```bash
traffic-e2e config init --source-container <container> [--breeze]
```

The target provides only its ordinary implementation, source-compatible
configuration, and:

```text
scripts/<project>-cli start --e2e --start-breeze off \
  --boot-dir .traffic-e2e/local/boot --port <port>
scripts/<project>-cli stop
```

Every E2E start compiles once; use the compile command's `--release` mode when
available and launch that artifact. `stop` is idempotent. The target CLI must
not read traffic cases, Replay sessions, expected responses, or reports.

Read [configuration-compatibility.md](references/configuration-compatibility.md)
for target configuration work. For Platform+Breeze recording lifecycle, read
[platform-breeze-runtime.md](references/platform-breeze-runtime.md). The
traffic engine owns source/Breeze/Recorder/Replay containers and capture-only
source adaptation; the target repository owns none of that control flow.

## Completion

Continue while `terminal_allowed` is false. `implementation_required` and
`system_repair_required` are working states, not final answers. Retries,
diminishing returns, code changes, or a draft PR never authorize stopping.

`action.kind=complete` with `terminal_allowed=false` means only the assigned
API is complete and other workers or inventory items remain. Only
`terminal_allowed=true` completes the whole rewrite. Delivery still requires
the user-requested repository checks and delivery outcome.
