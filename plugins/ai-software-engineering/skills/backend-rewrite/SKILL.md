---
name: backend-rewrite
description: "Plan, implement, verify, and deliver backend service rewrites and migrations using production engineering standards and traffic-e2e behavior contracts. Use for cross-language ports, incremental API or capability migrations, compatibility rewrites, and capability replacements using local recordings, newly recorded traffic, or recordings fetched from a remote task-service IPv4 address; this skill owns migration sequencing, repair routing, completion state, and pull-request delivery."
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
- Treat source structure as evidence, not as target architecture. Use the
  smallest independently triggerable and verifiable slice; for HTTP traffic,
  default to one canonical API group.
- Preserve genuine dependency paths. Only a value proven to come directly from
  process environment, startup arguments, or machine-local configuration may
  move to an equivalent target input.
- Keep recordings immutable and assertion-only. Target code, configuration,
  tests, and fixtures must never consume expected responses or recorded
  dependency outputs.
- Verify existing target behavior before changing it. Preserve passing behavior
  and make only evidence-backed compatibility changes.

## Ownership

This skill alone owns migration scope, sequence, active-slice state, repair
priority, completion, branch/PR delivery, and the final decision.

Before traffic work, read and use
[`traffic-e2e`](../traffic-e2e/SKILL.md); it owns recording, replay, comparison,
diagnosis, and their evidence gates. Before target-code work, read and use
[`backend-engineering`](../backend-engineering/SKILL.md); it owns production
code quality and local verification. Companion results inform this workflow
but cannot advance, terminate, or declare the migration complete.

When source or target evidence includes the Breeze SDK, `brz-*`,
`crates/breeze/`, or `/data1/breeze/socks`, also read and use
[`breeze-sdk`](../breeze-sdk/SKILL.md) before Breeze target-code work. It owns
resource identity, descriptor lifecycle, and Breeze client construction;
rewrite retains slice sequencing, evidence gates, completion, and delivery.

Do not modify traffic-e2e to complete a rewrite. Route a proven Recorder or
Replay capability gap to `traffic-e2e-system`, and do not add a
recording-backed workaround to target code.

## Required Workflow

Read [workflow.md](references/workflow.md) before executing a rewrite. It
defines discovery and resume behavior, PR-base resolution, initialization,
case acquisition, target-code delegation, runtime evidence, E2E/comparison
loops, delivery, and the final decision record.

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

1. Inspect and report every structured response difference.
2. Repair target behavior or any response-driving dependency wiring.
3. Rerun the same immutable cases until response assertions pass.
4. Only then classify remaining unused dependencies and apply a background
   rule when source evidence proves process ownership and response
   independence.
5. A background-rule change requires a new standard recording and E2E run.

An unrelated unused dependency must not preempt response diagnosis. Preserve
all independently evidenced categories so a capability blocker does not hide a
repairable response defect.

## State And Decisions

Keep one explicit record for the active slice:

```text
scope, stage, case_source, source_revision, e2e_evidence,
comparison_evidence, response_status, dependency_status,
failure_categories, next_todo, todo_owner, resume_stage
```

Use `complete` only when the active slice is `slice_done`, current E2E and
comparison evidence both pass, all repository gates pass, and deliverable
changes have been delivered as required.

Use `incomplete` when a required input, qualifying traffic, runtime access, or
external observation is missing but work can resume. Use `blocked` for a proven
capability gap that prevents an applicable gate, or when the same root cause
repeats for three repair cycles without new evidence or progress. Every
non-complete result needs an owner, concrete TODO, acceptance check, and resume
stage.

A draft PR or code change is delivery evidence, not verification success.
