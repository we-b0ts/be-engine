---
name: backend-rewrite
description: "Plan, implement, verify, and deliver backend service rewrites and migrations from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns migration sequencing, repair routing, completion state, and pull-request delivery."
---

# Backend Rewrite

Use the traffic-e2e rewrite coordinator for migration sequence and bounded
traffic evidence. The target AI owns source-code attribution and target-code
implementation; it does not operate the traffic engine. Recorded artifacts are
readable diagnostic evidence, while coordinator actions remain authoritative
for workflow state and gate results.

This skill is self-contained for ordinary rewrites. Do not load the
`traffic-e2e` skill. `traffic-e2e rewrite ...` is an executable coordinator
interface, not a Skill dependency. Load `backend-engineering` only when an
action requires target-code implementation or review.

## Control Protocol

From the initialized target repository, begin and resume with the default
all-configured-traffic workflow:

```bash
traffic-e2e rewrite next
```

Use `--api '<METHOD path-or-pattern>'` only when the caller explicitly narrows
the rewrite to one API. When an active dynamic pattern needs its source
registration route, the coordinator returns `input_required`; resume with the
requested `--source-route` for that active API. Do not invent routes for the
other inventory items.

The coordinator shares one immutable standard recording across the discovered
API inventory, keeps one active API and one active issue, and executes every
deterministic Prepare/E2E/Compare step. After one API's comparison passes,
`next` advances to the next pending inventory item without recording the
standard baseline again. It returns exactly one action. Execute only that
action, then call `rewrite next` again.

Action commands contain a canonical `cwd` and an argv array. Change to that
exact directory, then execute the argv without reconstructing, combining,
shell-evaluating, or changing its arguments. Supply named required environment
variables without printing their values.

`rewrite status` is a read-only recovery snapshot and includes the current
`action`, reconstructed from the persisted workflow revision. Use it when an
earlier action response was lost or when resuming an interrupted AI session.
`plan_apply_required` recovers the exact pending `apply <plan-id>` command.
`resume_required` means the coordinator detected a completed recording result
or a target change; execute its exact `rewrite next` argv instead of repeating
the prior recording or implementation action. If a previously launched action
is still known to be running, continue waiting rather than launching its
reconstructed command concurrently.

Read `api_inventory` from every initialized `next` or `status` result. It is
the authoritative stable list and includes total/completed counts, the current
index and API, and per-API `pending`, `active`, or `complete` status. Do not
enumerate APIs from directories, choose a different pending item, or stop when
only the active API completes. `terminal_allowed=true` means every inventory
item has current focused E2E and comparison evidence.

Keep the standard case source stable during implementation. A nonpassing
focused E2E attempt reuses the same immutable cases after the target changes;
it does not trigger another recording. A passing focused E2E attempt advances
to a fresh comparison recording automatically.

After any focused attempt, read `latest_focused_e2e` from the `rewrite next`
or `rewrite status` result. Its `execution_mode` explicitly distinguishes
`fresh_standard_cases` from `reused_standard_cases`; use its recording run,
exact case source, case inventory, previous/current attempt numbers, and pass
status instead of inferring reuse from local paths. This field describes the
latest completed focused attempt and does not imply that every `next` call ran
another attempt.

When the caller explicitly requests new traffic, the Recorder contract has
changed, or the source baseline has changed, request a fresh standard recording
through the coordinator:

```bash
traffic-e2e rewrite recording request \
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
same action and run; a matching completed manifest returns a resume action. A different
pending request is rejected unless the caller explicitly supplies
`--replace-pending`. The command invalidates evidence for every API derived
from the shared prior standard recording, preserves old artifacts, allocates a
new run ID, and returns one `recording_required` action. Execute that opaque
`rewrite recording execute <action-id>` argv exactly. It starts a detached
coordinator-owned worker and returns immediately; do not background it, pipe it
through `head`/`tail`, or wait on a shell task. Poll the exact `rewrite status`
command from the result. `recording_in_progress` means the one worker still
owns the run, `resume_required` means finalization completed, and
`recovery_required` means the owner exited and its exact recovery command must
run before retrying. The coordinator chooses and drives the finalized
real-traffic request corpus; never add `nohup`, curl loops, a replayer, or
driver parameters. If it returns `input_required` because
no finalized real-traffic corpus exists, report that missing external input and
do not synthesize requests. A failed E2E attempt alone never authorizes this
transition.

`rewrite next`, `evidence`, `rule`, `dependency-rule`, `route`,
`repair verify`, and `recording request|execute` are the public coordinator
control surface. `repair verify` and `recording execute` are ID-bound action
commands returned by the coordinator, not commands whose arguments the AI
invents. The target AI
may choose and compose these bounded transitions according to their documented
preconditions. Reading traffic artifacts may support diagnosis, but never
replaces a coordinator transition or authorizes editing generated evidence.

Read [workflow.md](references/workflow.md) for action semantics, phase order,
and recovery behavior.

## Problem Diagnosis And Repair

Problem diagnosis is mandatory for every `implementation_required` action. It
selects the one evidence-backed repair attempted before the next replay; it is
not an optional fallback after speculative implementation.

When the action is `implementation_required`:

1. Run only the returned `rewrite evidence <query-id>` commands for traffic
   facts.
2. For `representatives`, inspect the returned immutable `case_dir` and its
   request, expected response, candidate response when present, dependencies,
   and other persisted case evidence. Inspect additional cases under
   `.traffic-e2e/artifacts/` when they can distinguish the active hypotheses.
3. Read [problem-diagnosis.md](references/problem-diagnosis.md) and follow its
   issue-specific evidence and source-proof route.
4. Inspect the matching immutable source code and target implementation and
   prove one cause.
5. Use [`backend-engineering`](../backend-engineering/SKILL.md) for the target
   repair and repository checks.
6. Call `traffic-e2e rewrite next`; it detects the repository change and
   reruns the same immutable cases.

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
as a gate or as proof of ownership.

For a dependency issue, the `dirty_clusters` evidence report's
`applicable_rule_planners` lists only the background-rule protocol planners
supported by the current clusters. Run
the returned protocol-specific help argv, then use
`rewrite dependency-rule plan <protocol>` with the current evidence ID and only
the source-proven selector inputs shown there. The coordinator resolves the
current replay evidence, immutable case source, and source revision; none are
rule selector inputs. HTTP and Memcached expose different inputs, and
irrelevant protocol flags are intentionally unavailable; Redis exposes
command-specific `zcount` and `get` selector inputs. When the plan reports
`reused_existing=true`, the protocol selector is already covered: do not apply
a duplicate rule; execute the returned fresh-recording request. If an apply is
nevertheless resumed by plan ID, it is an idempotent reuse and makes no config
change. Otherwise execute the plan report's exact apply argv by plan ID.
After apply, execute its exact fresh-recording request because the Recorder
contract changed. Do not use the lower-level
`config recorder plan|apply background-dependencies` interface during a rewrite.

A background rule changes case ownership only: it proves that matching
asynchronous traffic is process-scoped and case-independent. It carries no
`independent` or `runtime_state` classification and never replaces destination
behavior. The target AI must determine from source and response evidence
whether those dependencies drive process state. If they do, implement the
source-compatible load, refresh, cache, fallback, and readiness behavior in
destination code, then verify the affected cases. `initial_load_timeout_ms`
only bounds source recording observation; it does not classify behavior.

When source code proves a supported response rule, use only the coordinator's
`rewrite rule plan|apply` interface with a current `evidence_id`. When source
and bounded evidence prove a Recorder/Replay gap, external-data blocker, or
source change, use `rewrite route`; it records the source reference and required
change and returns a coordinator-issued `repair verify <repair-id>` acceptance.
The AI cannot supply an acceptance command, and neither `next` nor
`recording request` can bypass the pending repair. A failed route leaves the
active target repair in place.

## Evidence And Internal State

`.traffic-e2e/artifacts/` is readable diagnostic evidence, not a forbidden
directory. Start with the exact `case_dir` returned by `representatives`, then
inspect other standard or comparison cases when useful. Keep every artifact
read-only and let coordinator output determine the active run, issue, gates,
and legal transition; never select workflow state by recency.

Prefer coordinator queries and status over scanning `.traffic-e2e/local/**`,
`.active`, `latest`, generated state, or large reports. Those paths are noisy,
unstable implementation details, so this is an efficiency rule rather than an
access prohibition. Narrow inspection is allowed when the public result is
insufficient to understand a system problem, but never edit internal state or
treat its schema as a target contract.

`replay-progress.yaml` and `comparison-progress.yaml` are coordinator-generated,
versioned migration evidence. They retain durable values such as consecutive
success counts. Never hand-edit, reset, restore, or check out their changes to
clean the worktree. When the coordinator changes either file, include that
generated change in the same delivery commit as the verified target change.
This exception does not apply to ignored runtime state under `local/` or to
recordings and other generated artifacts.

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
  --boot-dir .traffic-e2e/boot --port <port>
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

Only `action.kind=complete` with `terminal_allowed=true` completes the active
API slice. Whole-rewrite delivery still requires the user-requested repository
checks and delivery outcome.
