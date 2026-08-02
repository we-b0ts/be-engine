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

From the initialized target repository, begin and resume with:

```bash
traffic-e2e rewrite next
```

For a new workflow, select one canonical API:

```bash
traffic-e2e rewrite next --api '<METHOD path-or-pattern>'
```

Add `--source-route '<source-registration-route>'` when the selector is
dynamic. The coordinator keeps one API and one active issue, executes every
deterministic Prepare/E2E/Compare step, invalidates stale evidence, and returns
exactly one action. Execute only that action, then call `rewrite next` again.

Action commands are argv arrays. Do not reconstruct, combine, shell-evaluate,
or change their arguments. Supply named required environment variables without
printing their values.

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
  --case-limit <positive-limit>
```

The defaults are 60 seconds and 100 cases. Caller-supplied positive values may
replace them. This command invalidates evidence derived from the prior standard
recording, preserves old artifacts, allocates a new run ID, and returns one
`recording_required` action. Execute that returned argv exactly. A failed E2E
attempt alone never authorizes this transition.

`rewrite next`, `evidence`, `rule`, `route`, and `recording request` are the
public coordinator control surface. The target AI may choose and compose these
bounded transitions according to their documented preconditions. Reading
traffic artifacts may support diagnosis, but never replaces a coordinator
transition or authorizes editing generated evidence.

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
events by protocol and endpoint. `unused_global` and target activity outside an
active case do not fail the case gate. Treat `source_pre_readiness` as reference
context for startup jobs, warmup, and local-cache hypotheses, never as a gate or
as proof of ownership.

When source code proves a supported response rule, use only the coordinator's
`rewrite rule plan|apply` interface with a current `evidence_id`. When source
and bounded evidence prove a Recorder/Replay gap, external-data blocker, or
source change, use `rewrite route`; a failed route leaves the active target
repair in place.

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
