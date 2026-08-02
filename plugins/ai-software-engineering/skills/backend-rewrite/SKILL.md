---
name: backend-rewrite
description: "Plan, implement, verify, and deliver backend service rewrites and migrations from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns migration sequencing, repair routing, completion state, and pull-request delivery."
---

# Backend Rewrite

Use the traffic-e2e rewrite coordinator for migration sequence and bounded
traffic evidence. The target AI owns source-code attribution and target-code
implementation; it does not operate the traffic engine or parse its files.

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

Read [workflow.md](references/workflow.md) for action semantics, phase order,
and recovery behavior.

## Problem Diagnosis And Repair

Problem diagnosis is mandatory for every `implementation_required` action. It
selects the one evidence-backed repair attempted before the next replay; it is
not an optional fallback after speculative implementation.

When the action is `implementation_required`:

1. Run only the returned `rewrite evidence <query-id>` commands for traffic
   facts.
2. Read [problem-diagnosis.md](references/problem-diagnosis.md) and follow its
   issue-specific evidence and source-proof route.
3. Inspect the matching immutable source code and target implementation and
   prove one cause.
4. Use [`backend-engineering`](../backend-engineering/SKILL.md) for the target
   repair and repository checks.
5. Call `traffic-e2e rewrite next`; it detects the repository change and
   reruns the same immutable cases.

Treat coordinator `possible_causes` as hypotheses, never conclusions. Preserve
source cache keys, expiry, bounds, eviction, negative caching, warmup,
concurrent load, refresh, and fallback semantics when they affect behavior.

When source code proves a supported response rule, use only the coordinator's
`rewrite rule plan|apply` interface with a current `evidence_id`. When source
and bounded evidence prove a Recorder/Replay gap, external-data blocker, or
source change, use `rewrite route`; a failed route leaves the active target
repair in place.

## Forbidden Inputs

During an ordinary rewrite, never open or parse:

- `.traffic-e2e/local/**`, `.active`, `latest`, or generated state;
- assertion, aggregate, Replay, or comparison reports;
- expected, actual, or dependency case artifacts;
- recording manifests except through coordinator actions.

Do not use `jq`, Python, or ad-hoc shell to derive traffic facts. Do not make
target code, configuration, tests, or fixtures consume recorded responses or
dependency outputs. Never modify source business behavior to manufacture
evidence.

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
