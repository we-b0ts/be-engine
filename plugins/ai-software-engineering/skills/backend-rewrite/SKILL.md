---
name: backend-rewrite
description: "Plan, implement, verify, and deliver backend service rewrites and migrations from observable behavior and traffic evidence. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements; this skill owns migration sequencing, repair routing, completion state, and pull-request delivery."
---

# Backend Rewrite And Migration

Own the migration from contract discovery through delivery. Select one
independently verifiable slice, coordinate target implementation and traffic
evidence, and advance only on current proof.

## Core Contract

- Rewrite observable behavior and operational contracts, not source syntax.
  Preserve responses, dependency roles, side effects, ordering, error
  semantics, metrics, configuration provenance, and lifecycle behavior unless
  the user approves a contract change.
- Treat the source configuration interface as an operational compatibility
  contract. Make target startup consume the same authoritative configuration
  and preserve its externally supplied formats, keys, parsing semantics,
  defaults, precedence, validation, and behavior-relevant reload behavior.
  Whenever source startup uses configuration files or directories, trace the
  loader from the source runtime and implement compatible target
  initialization and loading before accepting target startup.
- Treat the source repository and source application implementation as
  immutable evidence. Never edit source code, replace source classes through a
  recording adapter, patch source artifacts, or change source business
  behavior to manufacture traffic or make verification pass. This skill
  authorizes no source patch; never invent or extend one.
- Treat source structure as evidence, not as target architecture. Use the
  smallest independently triggerable and verifiable slice; for HTTP traffic,
  default to one canonical API group.
- Preserve genuine dependency paths. Only a value proven to come directly from
  process environment, startup arguments, or machine-local configuration may
  move to an equivalent target input.
- Treat source-process local caches as target behavior. Reproduce the source
  cache semantics that affect responses or runtime behavior.
- Keep recordings immutable and assertion-only. Target code, configuration,
  tests, and fixtures must never consume expected responses or recorded
  dependency outputs.
- Verify existing target behavior before changing it. Preserve passing behavior
  and make only evidence-backed compatibility changes.

## Ownership

This skill alone owns migration scope, sequence, active-slice state, repair
priority, completion, branch/PR delivery, and the final decision.

Before traffic work, read and use the
[`traffic-e2e` skill](../traffic-e2e/SKILL.md); it owns recording, replay,
comparison, diagnosis, and their evidence gates. Before target-code work, read
and use the [`backend-engineering` skill](../backend-engineering/SKILL.md); it
owns production code quality and local verification. Companion results inform
this workflow but cannot advance, terminate, or declare the migration
complete.

When target-code work designs, implements, integrates, migrates, or reviews
business-independent remote-resource access managed through Breeze, read the
[`breeze-sdk` skill](../breeze-sdk/SKILL.md) completely before that work and
use it for that work. This explicitly includes Memcached, Redis, MySQL, Kafka,
queues such as MCQ or QueueService, Motan, and other Breeze-managed remote
resources. Breeze owns reusable resource identity, discovery, runtime
lifecycle, and client construction; business contracts and behavior remain in
the target capability, while rewrite retains slice sequencing, evidence gates,
completion, and delivery. Require target resource packages to use the shared
Breeze descriptor library directly. Do not accept a project CLI that enumerates
resources, invokes a descriptor resolver, or injects descriptor-derived ports.

Do not modify traffic-e2e to complete a rewrite. Route a proven Recorder or
Replay capability gap to `traffic-e2e-system`, and do not add a
recording-backed workaround to target code. Likewise, never route a missing
recording capability into a source modification.

## Required Workflow

Read [workflow.md](references/workflow.md) before executing a rewrite. It
defines discovery and resume behavior, PR-base resolution, initialization,
case acquisition, target-code delegation, runtime evidence, E2E/comparison
loops, delivery, and the final decision record.

Read
[configuration-compatibility.md](references/configuration-compatibility.md)
before implementing or accepting target configuration loading and startup. It
defines how to discover the source configuration contract, load it compatibly,
and verify target startup with it.

For a remote task-service IPv4 source, also read
[remote-case-source.md](references/remote-case-source.md) before network
access. Freeze one snapshot and materialize at most one oldest unprocessed
recording without changing downloaded evidence.

The phase order is:

```text
select_slice -> record -> prepare -> e2e -> compare -> slice_done
```

Work on one active slice at a time. Resume valid existing evidence; do not
repeat completed phases or enter comparison without current runner-generated
proof that the affected E2E scope passes.

## Repair Priority

Response compatibility is the primary repair loop:

1. Count selected and executed cases, response-passing cases, and
   response-mismatching cases.
2. Group every structured response difference by field and proven cause.
   State the response cause before dependency cleanliness or blockers; if it is
   not yet proven, say so and continue diagnosis.
3. When required dependency evidence appears absent, require traffic-e2e's
   missing-evidence checkpoint before calling it a recording-data blocker.
   Follow its Breeze resource-capture result when applicable; re-record only
   after a changed apply, and otherwise continue diagnosis.
4. Repair target behavior or any response-driving dependency wiring. When a
   source-owned cache warm is causally required, apply a source-proven
   `runtime_state` background rule and make a new recording as part of this
   repair.
5. Rerun the same immutable cases until response assertions pass.
6. Only then classify remaining unused dependencies and apply an
   `independent` background rule when source evidence proves process ownership
   and response independence.
7. A recorder-rule change requires a new standard recording and E2E run.

Every non-complete result with a response mismatch must begin with the
traffic-e2e handoff model exactly as defined; do not rename or omit its keys,
and do not define a backend-rewrite variant. A generic conclusion without its
one real case, one Pointer, concrete source/candidate observations, and
diagnosis is not a valid handoff or final decision. Do not enumerate every
failed case, and do not claim that the representative explains other cases
without shared difference and code-path evidence. Delivery fields never
determine verification status.

An unrelated unused dependency must not preempt response diagnosis. Preserve
all independently evidenced categories so a capability blocker does not hide a
repairable response defect. Do not present a dependency or tool limitation as
the cause of a response mismatch without a demonstrated causal path. A dirty
dependency report is a later gate, never a stop signal while any response
assertion still fails.

## State And Decisions

Keep one explicit record for the active slice:

```text
scope, stage, case_source, source_revision, e2e_evidence,
comparison_evidence, repaired_case_evidence, response_status,
dependency_status, failure_categories, next_todo, todo_owner, resume_stage
```

Use `complete` only when the active slice is `slice_done`, current E2E and
comparison evidence both pass, all repository gates pass, and deliverable
changes have been delivered as required.

Use `action_required` while a response mismatch has an in-scope target,
environment, dependency-wiring, or configuration repair. Continue diagnosis
and implementation rather than ending on difficulty or failed attempts.
`action_required` is a working state, not a terminal outcome while authorized
in-scope repair remains.

Use `incomplete` only after every selected response assertion passes and the
remaining dirty dependency evidence has no source-proven rule that can be
safely applied. Use `blocked` only when response-driving external-system data
was not recorded or provided and the missing information prevents target-code
implementation. Dirty evidence alone never proves `blocked`. Every
non-complete result needs an owner, concrete TODO, acceptance check, and resume
stage.

Use `inconclusive` only when a target repair has passed E2E against the same
immutable case that evidenced it, but the first valid fresh comparison after
that repair does not observe the repaired case. This is terminal for the
current execution, not success. Do not start another standard or comparison
recording automatically. Keep `resume_stage: compare`; if code, policy,
configuration, and E2E evidence remain current, a later requested resume
returns directly to comparison.

A draft PR or code change is delivery evidence, not verification success.
