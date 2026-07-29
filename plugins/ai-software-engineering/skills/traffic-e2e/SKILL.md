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
- Treat the source repository and source application behavior as immutable
  evidence. Never edit source code, replace source classes through an adapter,
  patch source artifacts, disable caches, or change business switches to
  manufacture dependency traffic or make verification pass. This skill
  authorizes no source patch; never invent or extend one.
- Use `expected-response.json` only as an assertion oracle. Only
  recorder-owned replay may consume case or Global dependency files.
- Target code, configuration, tests, and support must use genuine runtime
  clients and must never turn recorded outputs into fixtures or behavior.
- A response difference caused by a missing, cold, stale, partially loaded, or
  behaviorally different process-local cache is target behavior. Never exempt
  it with a dynamic response rule.
- One passing response cannot compensate for invalid artifacts, incomplete
  coverage, dirty dependencies, missing side effects, or a stale evidence
  gate.

## Ownership And Outcome

This skill owns the mechanics and evidence gates of each traffic operation. It
does not choose migration order, implement target behavior, declare a whole
migration complete, modify the traffic-e2e product from an operation task, or
deliver a PR.

Return a concise handoff after each operation. When any selected response
assertion is non-passing, begin the handoff with this model and fill every
applicable key; do not replace it with prose:

```text
status: passed | action_required | incomplete | inconclusive | blocked
stage: <current stage>
scope: <canonical API or capability>

counts:
  apis:
    selected: <integer>
    evaluated: <integer>
    passed: <integer>
    nonpassing: <integer>
  cases:
    selected: <integer>
    executed: <integer>
    response_passed: <integer>
    response_nonpassing: <integer>

representative_case:
  api: <METHOD path>
  case_id: <case id>
  pointer: <exactly one JSON Pointer>
  difference_kind: <kind>
  source_before: <JSON value>
  candidate: <JSON value>
  source_after: <JSON value | not_recorded>
  cause: <concrete cause or unresolved>
  cause_status: proven | unresolved
  evidence: <source/runtime/artifact evidence>
  missing_evidence: <required only when unresolved>
```

Choose one real failed case and exactly one representative Pointer on one
causal path. Read `source_before`, `candidate`, and `source_after` at that
Pointer from `expected-response.json`, `response.json`, and
`expected-response-after.json`. Render concrete bounded JSON values, with
strings quoted. Use `<missing>` only when the Pointer is absent, and
`not_recorded` only when the complete source-after artifact is absent. Preserve
`null` and `""` distinctly. Redact sensitive content while retaining length or
a stable digest that proves the values differ. When `cause_status` is `proven`,
omit `missing_evidence`; when it is `unresolved`, name the exact evidence still
needed. Do not substitute aggregate mismatch counts, a field list, dependency
cleanliness, or a generic blocker for this evidence. When every selected
response passes, omit `representative_case`.

Use `action_required` while response or other repairable behavior remains.
Use `incomplete` only when all selected response assertions pass but dirty
dependency evidence remains and no source-proven rule can be safely applied.
Use `inconclusive` only when the first valid comparison after an evidenced
target repair does not observe the repaired case, while that same immutable
case has current passing E2E evidence. End the current operation without
automatically recording again and use the comparison reference's handoff.
Use `blocked` only when response-driving external-system information was not
recorded or provided and the missing information prevents target behavior from
being implemented.

Artifact terms such as an incomplete case, session, report, or rule describe
evidence validity, not the handoff status. Map them to `action_required` while
response repair or an in-scope system/configuration repair remains; never infer
`blocked` or `incomplete` from an artifact label or retry count.

For non-passing results, add every evidenced category, capability owner,
concrete next TODO, acceptance check, and resume stage. Use capability owners
such as `target-code`, `target-runtime`, `traffic-e2e-config`,
`traffic-e2e-system`, or `runtime-owner`; the caller maps them to an agent or
team. `passed` advances only the current operation.

Use stable evidence categories:

```text
target_behavior, target_environment, background_dependency,
recording_configuration, recording_no_traffic, recorder_capability_gap,
replay_capability_gap, verification_policy, intentional_nondeterminism,
source_change, repaired_case_not_observed, unresolved
```

## Mandatory Sequence

1. Resolve an exact immutable case source and canonical scope.
2. Run the applicable recording, preparation, replay, or comparison operation
   through repository entrypoints and runner-owned state.
3. After the first failure, diagnose all applicable gates. Report structured
   response differences and causal dependency evidence before remaining
   dependency coverage.
4. When response-driving dependency evidence appears absent, run the
   missing-evidence checkpoint, including Breeze snapshot/resource-capture
   diagnosis when applicable, before classifying a recording-data blocker.
5. Return target behavior or runtime defects to the caller. When source
   evidence proves process-owned dependency traffic builds response-driving
   local state, apply a narrow `runtime_state` background rule as part of that
   repair. Rerun the same cases after repair until response assertions pass.
6. Only after response assertions pass, classify remaining unused dependencies.
   Apply an `independent` background rule only when source evidence proves
   process ownership and response independence; then create a new recording.
7. Start comparison only after current runner-generated evidence proves the
   affected replay E2E scope passes. Any behavior or policy change makes prior
   comparison evidence stale.

An unrelated unused dependency must not preempt response diagnosis. Preserve
all independent findings when one gate is blocked. Dirty dependency evidence is
not a stop signal while any response assertion still fails.

## Reference Routing

Read the smallest phase bundle before acting, then add only references selected
by evidence from that phase:

- **Record:** read [recording.md](references/recording.md). Add
  [background-dependencies.md](references/background-dependencies.md) only for
  source-proven process-owned traffic.
- **Inspect or prepare cases:** read
  [case-grouping.md](references/case-grouping.md). Add
  [case-format.md](references/case-format.md) for HTTP artifact validity,
  [dependency-case-format.md](references/dependency-case-format.md) for
  semantic dependency artifacts, [mysql-case-format.md](references/mysql-case-format.md)
  for MySQL, and [route-pattern-feedback.md](references/route-pattern-feedback.md)
  only for a confirmed dynamic source route.
- **Run standard E2E:** read [e2e-run.md](references/e2e-run.md). Add
  [target-integration.md](references/target-integration.md) when initializing
  or repairing target startup/configuration,
  [dependency-replay.md](references/dependency-replay.md) when dependency
  matching or genuine-client behavior is in question, and
  [replay-policy.md](references/replay-policy.md) only when inspecting or
  changing assertion policy.
- **Diagnose a non-passing attempt:** read
  [failure-diagnosis.md](references/failure-diagnosis.md), then load only the
  operation reference it selects: recording/resource capture, background
  classification, dependency replay or format, target integration, or replay
  policy.
- **Compare after current E2E passes:** read
  [comparison-verification.md](references/comparison-verification.md), adding
  replay policy only for source-proven policy feedback.

Read [replay-lifecycle.md](references/replay-lifecycle.md) or
[aggregate-report.md](references/aggregate-report.md) only when directly using
their low-level diagnostic commands. Normal `prepare`, `run-api`, and `run`
operations do not require either reference.

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
- Make recorder-rule and response-rule changes only through the supported
  evidence-validating `config ... plan|apply` interface. The typed
  `response_rules.comparison.source_match` behavior may be reviewed and changed
  directly in the source-controlled verification config when its reference
  defines that operation.
- Never hand-edit generated state or parse partial output to manufacture
  completion.

## Evidence And Stop Rules

The selected reference defines the full gate. In all phases, evidence must be
finalized, complete, canonical, current for the latest behavior and policy, and
free of invalidating capture, replay, assertion, or aggregation failures.
During dynamic response-rule repair, the replay-policy reference may admit
complete dependency-dirty evidence; the dirty dependency remains a separate
failing gate and never becomes passing evidence.

Return a Recorder or Replay capability gap as `action_required` while an
in-scope system repair can recover the evidence or replay behavior. Use
`blocked` only when one bounded reproduction proves that response-driving
external information was not captured or provided and its absence prevents
target implementation. Include the exact evidence, required system change or
external input, owner, affected gate, and verification command; do not create a
target workaround or alter the source to manufacture the missing evidence.

Repeated failures without capability proof remain `action_required`, not
`blocked`. Use `incomplete` only for response-passing dirty evidence without a
safe source-proven rule. A valid comparison that does not observe a repaired
case follows the comparison reference and terminates as `inconclusive`; it is
not a retry signal. Never invent requests, responses, dependency values, side
effects, routes, or completion artifacts.
