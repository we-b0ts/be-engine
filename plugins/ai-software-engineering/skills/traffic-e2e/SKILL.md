---
name: traffic-e2e
description: "Operate traffic-e2e for managed recording, published case inspection and grouping, genuine dependency replay, response verification, comparison verification, failure diagnosis, and evidence-driven policy. Use when recording application traffic, replaying cases, verifying behavior against recorded or live comparison evidence, diagnosing traffic-e2e failures, or maintaining recorder and replay policy. This skill owns traffic operations and evidence gates, not migration sequencing, target-code implementation, whole-migration completion, or pull-request delivery."
---

# Traffic E2E

Operate recording, replay, comparison, and diagnosis while preserving one
observable contract: the inbound request and expected response, every
case-owned dependency call, and every required side effect.

## Core Contract

- Treat published recordings as immutable sensitive evidence. Never edit,
  trim, synthesize, or expose them to make replay pass.
- Use `expected-response.json` only as an assertion oracle. Only
  recorder-owned replay may consume `dependencies.jsonl` or bootstrap
  dependencies.
- Target code, configuration, tests, and support must use genuine runtime
  clients and must never turn recorded outputs into fixtures or behavior.
- One passing response cannot compensate for invalid artifacts, incomplete
  coverage, dirty dependencies, missing side effects, or a stale evidence
  gate.

## Ownership And Outcome

This skill owns the mechanics and evidence gates of each traffic operation. It
does not choose migration order, implement target behavior, declare a whole
migration complete, modify the traffic-e2e product from an operation task, or
deliver a PR.

Return a concise handoff after each operation:

```text
status: passed | action_required | incomplete | blocked
stage, scope, exact evidence
```

For non-passing results, add every evidenced category, capability owner,
concrete next TODO, acceptance check, and resume stage. Use capability owners
such as `target-code`, `target-runtime`, `traffic-e2e-config`,
`traffic-e2e-system`, or `runtime-owner`; the caller maps them to an agent or
team. `passed` advances only the current operation.

Use stable evidence categories:

```text
target_behavior, target_environment, background_dependency,
recording_configuration, recording_no_traffic, recorder_capability_gap,
replay_capability_gap, intentional_nondeterminism, source_drift, unresolved
```

## Mandatory Sequence

1. Resolve an exact immutable case source and canonical scope.
2. Run the applicable recording, preparation, replay, or comparison operation
   through repository entrypoints and runner-owned state.
3. After the first failure, diagnose all applicable gates. Report structured
   response differences and causal dependency evidence before remaining
   dependency coverage.
4. Return target behavior or runtime defects to the caller. Rerun the same
   cases after repair until response assertions pass.
5. Only after response assertions pass, classify unused dependencies. Apply a
   background rule only when source evidence proves process ownership and
   response independence; then create a new standard recording.
6. Start comparison only after current runner-generated evidence proves the
   affected replay E2E scope passes. Any behavior or policy change makes prior
   comparison evidence stale.

An unrelated unused dependency must not preempt response diagnosis. Preserve
all independent findings when one gate is blocked.

## Reference Routing

- Managed recording or recording failure:
  [recording.md](references/recording.md)
- Artifact validity: [case-format.md](references/case-format.md)
- Canonical groups: [case-grouping.md](references/case-grouping.md), plus
  [route-pattern-feedback.md](references/route-pattern-feedback.md) for a
  confirmed dynamic source route
- Startup, identity, configuration, and genuine clients:
  [target-integration.md](references/target-integration.md)
- Dependency behavior: [dependency-replay.md](references/dependency-replay.md)
- Assertion and replay policy: [replay-policy.md](references/replay-policy.md)
- Standard project runner: [e2e-run.md](references/e2e-run.md)
- First failed attempt: [failure-diagnosis.md](references/failure-diagnosis.md)
- Comparison after current E2E passes:
  [comparison-verification.md](references/comparison-verification.md)
- Direct low-level replay lifecycle:
  [replay-lifecycle.md](references/replay-lifecycle.md)
- Low-level multi-case/session aggregation:
  [aggregate-report.md](references/aggregate-report.md)

Read every reference selected by the operation before acting.

## Operation Invariants

- Use source-controlled `scripts/start-recording` and
  `scripts/start-recording-comparison` when present; do not reconstruct their
  lifecycle.
- Pass an explicit positive duration and a unique UTC run ID for every new
  recording unless the caller supplied one. Retain the exact finalized path;
  never choose a run merely because it is newest.
- Pass the known scope through repeatable `--api` selectors, not recorder
  configuration edits.
- When request-header encryption is configured, require the named key
  environment and keep its value out of commands, logs, reports, cases, policy,
  and target configuration.
- Make recorder or replay policy changes only through the supported
  evidence-validating `config ... plan|apply` interface.
- Never hand-edit generated state or parse partial output to manufacture
  completion.

## Evidence And Stop Rules

The selected reference defines the full gate. In all phases, evidence must be
finalized, complete, canonical, current for the latest behavior and policy, and
free of invalidating capture, replay, assertion, or aggregation failures.

Return a Recorder or Replay capability blocker after one bounded reproduction
proves that the genuine contract cannot be captured or replayed and ordinary
configuration, runtime wiring, or re-recording cannot resolve it. Include the
exact evidence, required system change, owner, affected gate, and verification
command; do not create a target workaround.

For other causes, use `blocked` after the same root cause repeats for three
cycles without new evidence or progress. Use `incomplete` when a required
observation or input is missing but work can resume. Never invent requests,
responses, dependency values, side effects, routes, or completion artifacts.
