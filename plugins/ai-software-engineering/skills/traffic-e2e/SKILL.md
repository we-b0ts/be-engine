---
name: traffic-e2e
description: "Operate traffic-e2e for managed traffic recording, published case inspection and grouping, genuine dependency replay, response verification, failure diagnosis, and recorder feedback. Use when recording application traffic, replaying cases, verifying software behavior against recorded contracts, diagnosing recording or replay failures, or maintaining traffic-e2e policy and evidence. Do not invoke merely to develop or review the traffic-e2e tool implementation or as a general backend coding guide."
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
- Read [e2e-run.md](references/e2e-run.md) for the standard `init`, `prepare`,
  `run-api`, `run`, `status`, `recover`, and `abort` workflow.
- Read [replay-lifecycle.md](references/replay-lifecycle.md) only for direct
  replay execution or low-level lifecycle diagnosis.
- Read [aggregate-report.md](references/aggregate-report.md) for low-level
  collection, multi-case, or multi-session aggregation.
- Read [verified-excludes.md](references/verified-excludes.md) only after final
  aggregate and response assertion evidence exists.
- Read [failure-diagnosis.md](references/failure-diagnosis.md) after the first
  failed attempt. This is REQUIRED before changing target behavior, replay
  policy, or recorder attribution for an unused case dependency.

## Managed Recording

1. Inspect the target's authoritative recorder config, startup, readiness,
   upstreams, access policy, redaction, limits, enabled protocols, dependency
   timing, and background rules. Do not guess from examples.
2. Confirm the fixed interception identity and run managed
   `traffic-e2e record`. Let it own DNS, fake-IP interception, recovery, and
   shutdown.
3. Wait for configured readiness. Send only controlled trigger requests and
   avoid overlapping active cases.
4. Allow post-response dependency admission and bounded drain to finish, then
   stop cleanly and inspect run diagnostics, failed cases, canonical files, and
   summaries.
5. Fix recorder, target, or config defects and create a new run. Never repair
   or promote a failed or published recording in place.

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
   unresolved before changing recorder config.
6. After all selected groups pass, run the required full round when a later
   behavior-affecting change can invalidate earlier evidence.
7. Use runner-owned reports, aggregation, progress, policy feedback, and
   verified excludes. Never hand-edit generated state or parse partial output
   to manufacture completion.

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
- applicable runner progress, pattern feedback, and verified-exclude outcomes
  reached their canonical terminal states.

## Stop And Report

If the same root cause repeats for three consecutive cycles without new
evidence or meaningful progress, stop as `blocked` or `incomplete`. Never invent
requests, responses, dependency values, side effects, source routes, or
completion artifacts.

For execution work, report `complete`, `incomplete`, or `blocked` with the exact
case source and IDs, final session/report, aggregate, policy, assertion,
pattern, verified-exclude status, verification command, and remaining blockers.
Never use success wording while an applicable gate is missing.
