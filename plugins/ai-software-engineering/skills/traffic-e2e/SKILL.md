---
name: traffic-e2e
description: "Operate traffic-e2e for managed recording, published case inspection and grouping, genuine dependency replay, response verification, comparison recording verification, failure diagnosis, and recorder feedback. Use when recording application traffic, replaying cases, verifying software behavior against recorded contracts or live comparison evidence, diagnosing failures, or maintaining evidence-driven traffic-e2e policy. Do not invoke for repository initialization, ordinary project initialization, merely developing or reviewing the traffic-e2e implementation, or general backend coding."
---

# Traffic E2E

Preserve one observable contract: the inbound request and expected response,
every case-owned dependency call, and every required side effect.

## Core Contract

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Completion
requires every applicable gate; one matching response cannot compensate for
invalid artifacts, dirty dependencies, missing side effects, or incomplete case
coverage.

- Treat published recordings as immutable evidence. Never edit, move, trim, or
  synthesize them to make replay pass.
- Use `expected-response.json` only as an assertion oracle.
- Let recorder-owned replay alone consume `dependencies.jsonl` and bootstrap
  dependencies. Target product code, config, tests, and support MUST NOT turn
  them into fixtures or behavior.
- Exercise the target's genuine runtime dependency clients through
  recorder-owned listeners.
- Protect recording directories as sensitive data. Keep them out of Git, logs,
  and unapproved copies.

## Reference Routing

- Read [recording.md](references/recording.md) before managed recording or
  recording-failure diagnosis.
- Read [case-format.md](references/case-format.md) when resolving artifacts or
  deciding whether a case is valid replay evidence.
- Read [case-grouping.md](references/case-grouping.md) for collections or runs
  containing multiple canonical inputs.
- Read [route-pattern-feedback.md](references/route-pattern-feedback.md) with
  case grouping when a confirmed source route is dynamic.
- Read [target-integration.md](references/target-integration.md) before wiring
  startup, configuration, identity, genuine dependencies, or the project
  facade.
- Read [dependency-replay.md](references/dependency-replay.md) when wiring or
  diagnosing dependency behavior.
- Read [replay-policy.md](references/replay-policy.md) before creating,
  changing, or validating response or dependency replay policy.
- Read [e2e-run.md](references/e2e-run.md) for the standard `config project
  init`, `prepare`, `run-api`, `run`, `status`, `recover`, and `abort`
  workflow.
- Read [replay-lifecycle.md](references/replay-lifecycle.md) only for direct
  replay execution or low-level lifecycle diagnosis.
- Read [aggregate-report.md](references/aggregate-report.md) for low-level
  collection, multi-case, or multi-session aggregation.
- Read [failure-diagnosis.md](references/failure-diagnosis.md) after the first
  failed attempt. This is REQUIRED before changing target behavior, replay
  policy, or recorder attribution for an unused case dependency.
- Read
  [comparison-verification.md](references/comparison-verification.md) before
  recording or evaluating baseline/candidate comparison traffic. This phase
  starts only after the affected replay E2E scope passes.

## Configuration Interfaces

Make evidence-driven managed changes only through
`traffic-e2e config recorder <plan|apply> <strategy>` or `traffic-e2e config
replay <plan|apply> <strategy>`. Use `apply` for normal automation; it performs
the same current-state planning and evidence validation before its atomic
write. Use `plan` only when diagnostic output is useful.

## Runtime Evidence

When artifacts and repository configuration do not explain a recording,
replay, or comparison result, inspect an available authorized source or target
runtime read-only. Inspect only what is necessary, such as effective
configuration, environment variable names and provenance, startup arguments,
mounts, container or deployment metadata, network wiring, and dependency
endpoints. Never dump secret values or copy them into logs, cases, policy,
commits, or reports.

Runtime evidence may establish configuration provenance or a wiring defect. It
must not turn a value loaded by a genuine runtime dependency into a target
environment variable. Follow [target-integration.md](references/target-integration.md)
for materialization and precedence rules.

## Repository Entrypoints

This skill owns the mechanics and evidence gates of recording, replay, and
comparison. A rewrite orchestration skill decides when to enter and repeat
those phases.

When source-controlled `scripts/start-recording` or
`scripts/start-recording-comparison` exists, use it as the normal operation
boundary. Do not reconstruct its container, service startup, signal,
finalization, or cleanup lifecycle. Generated scripts may default to 60
seconds, but AI and automated invocations must pass
`--duration-seconds 60` or another positive integer explicitly.

Generate a unique UTC `--run-id YYYYMMDDHHMMSS` for every new recording
operation unless the caller supplied one, retain the exact finalized artifact
path, and never select a run merely because it is newest. When the intended
scope is known, pass repeatable `--api 'METHOD /path-or-pattern'`; the selector
is run-local and must not become a recorder configuration edit.

## Operation Outcome

Return a concise control handoff to the calling orchestrator after each
recording, preparation, E2E, comparison, or diagnosis operation. This is not a
mandatory user-facing report template. Always include:

```text
status: passed | action_required | incomplete | blocked
stage, api, exact evidence
```

For a non-passing outcome, also include the evidence-backed category, owner,
next TODO, and resume stage. Include `case_source`, `requires_rerecord`,
`requires_e2e_rerun`, and `requires_new_comparison` only when they affect the
next transition. Omit inapplicable fields; do not invent values or emit an
empty schema.

Use these categories:

```text
target_behavior, target_environment, background_dependency,
recording_configuration, recording_no_traffic,
recorder_capability_gap, replay_capability_gap,
intentional_nondeterminism, source_drift, unresolved
```

Set `owner` to the component or team that can perform `next_todo`; do not assign
a traffic-e2e system defect to the rewrite target. Use `rewrite-agent` for
target runtime, recording configuration, background attribution, policy, and
new observations; `backend-engineering` for target behavior;
`traffic-e2e-system` for Recorder or Replay capability gaps; and
`runtime-owner` for missing runtime access or qualifying traffic. `passed`
advances only the current stage. It is not whole-migration completion.

## Managed Recording

1. Inspect the target's authoritative recorder config, startup, readiness,
   upstreams, access policy, redaction, limits, enabled protocols, dependency
   timing, and background rules. Do not guess from examples. When
   `scripts/start-recording` exists, invoke it instead of bypassing its
   repository-specific orchestration.
2. For container recording, create a network-namespace anchor that uses host
   networking by default. Run Recorder, source, and dependency-producing
   sidecars with `--network container:<anchor>` so they share that one
   namespace. Use another verified Docker network only when explicitly
   required. Run only the genuine source application process as the fixed
   `trp-record` identity; always preserve supporting-container users. Let
   managed `traffic-e2e record` own DNS, fake-IP
   interception, recovery, and shutdown inside that boundary.
3. Wait for configured readiness. Send only controlled trigger requests and
   avoid overlapping active cases.
4. Allow post-response dependency admission and bounded drain to finish, then
   stop cleanly and inspect run diagnostics, failed cases, canonical files, and
   summaries.
5. Fix target-owned or recording-configuration defects and create a new run.
   For a confirmed Recorder capability gap, stop with a system-owned blocker
   instead of modifying the tool from a rewrite task. Never repair or promote a
   failed or published recording in place.

## Replay And Verification

1. Resolve the exact published case source and IDs. Group one confirmed source
   API at a time; never infer API identity from directory names.
2. Inspect normal target startup, config, dependency wiring, and source
   behavior. Require genuine clients and the ordinary runtime path.
3. Use a source-controlled assertion-only replay policy and audit target code
   for forbidden expected-response, dependency-recording, or fixture data
   flows.
4. Use the standard runner for normal work: initialize generated config,
   prepare the canonical group, and run focused `run-api` attempts only until
   that complete group passes.
5. Diagnose failures from canonical evidence. Classify every unused case
   dependency from source as case-owned, source-proven background, or
   unresolved before changing recorder config. After applying a proven
   background rule, make a new standard recording for the same API, prepare
   that new immutable source, and rerun E2E. A background rule changes
   capture-time attribution; it never cleans or reinterprets an old recording.
6. After all selected groups pass, run the required full round when a later
   behavior-affecting change can invalidate earlier evidence.
7. Use runner-owned reports, aggregation, E2E pass progress, comparison
   reports, and policy feedback. Never hand-edit generated state or parse
   partial output to manufacture completion.

## Comparison Verification

1. Start comparison only after runner-generated evidence proves genuine
   dependency replay E2E passed for the exact affected API and case source
   after the latest target, policy, attribution, or case-source change.
2. When `scripts/start-recording-comparison` exists, invoke it instead of
   reproducing its source and candidate lifecycle. Run both services normally
   without fixed-user or network isolation. Configure only explicit read-only
   methods. Use repeatable `--api` arguments for the affected scope instead of
   rewriting recorder TOML. For Platform repositories, require source and
   candidate containers to reuse one Breeze instance; let the wrapper consume
   `--brz-no-fallback <true|false>` rather than forwarding it to traffic-e2e.
3. Use the optional baseline recheck when source-time drift evidence is needed;
   do not treat it as automatic authorization to ignore a difference.
4. Classify non-passing evidence as candidate implementation difference,
   source data drift, or source-proven intentional non-determinism.
5. Fix code for genuine candidate defects. Re-record inconclusive mutable-data
   cases. Apply only narrow, evidence-backed dynamic or unordered response
   rules for proven non-determinism.
6. After any behavior or policy change, pass the affected replay E2E scope
   again and generate a new comparison report.

## Evidence Gates

A recording is usable only when managed shutdown finalized cleanly, the genuine
ready target handled the intended trigger, every selected case is canonically
published with complete bodies and explicit semantic dependency evidence, no
selected case exists only under failed/partial/truncated state, and no policy,
protocol, capture, drain, or interception failure invalidates the contract.

A replay scope passes only when:

- every selected case belongs to exactly one canonical group;
- the final policy is validated, assertion-only, fingerprinted, and has zero
  unused applicable rules;
- direct audit proves target behavior did not consume expected responses or
  recorded dependency outputs;
- genuine target clients emitted dependency traffic through the supported
  isolation or explicit routing boundary;
- every selected case ended and the final report is finalized with the exact
  case and session IDs;
- aggregate evidence is complete and clean;
- response assertions pass after the last behavior-affecting change; and
- applicable runner progress and pattern feedback reached their canonical
  E2E-pass states.

A comparison scope passes only when its run finalized cleanly, every published
case was evaluated, no source-drift or unevaluable case remains, all candidate
responses and every affected API pass the reviewed shared verification policy,
and the affected candidate behavior still passes replay E2E. This report is
current evidence, not a permanent API-verified terminal state.

## Stop And Report

Report `blocked` immediately when one bounded reproduction confirms a Recorder
or Replay capability gap: the genuine contract cannot be captured or replayed,
and target configuration, runtime wiring, or an ordinary re-recording cannot
resolve it. Do not modify the traffic-e2e implementation or create a
recording-backed target workaround during a rewrite. Emit a blocker packet
with the capability, exact evidence, required system change, owner, resume
stage, and verification command.

For other categories, stop as `blocked` when the same root cause repeats for
three consecutive cycles without new evidence or meaningful progress. Use
`incomplete` when a required observation or input is missing but work can
resume. Never invent requests, responses, dependency values, side effects,
source routes, or completion artifacts.

For execution work, report `complete`, `incomplete`, or `blocked` with the exact
case source and IDs, final session/report, aggregate, policy, assertion,
pattern, comparison API counts, verification command, and remaining blockers.
Also include the active API, stage, failure category, owner, next TODO, and
resume stage. Never use success wording while an applicable gate is missing.
