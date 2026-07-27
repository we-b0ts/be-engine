---
name: backend-rewrite
description: "Rewrite or migrate backend services against local recorded traffic or recordings fetched from a remote task-service IPv4 address while applying backend engineering standards and genuine traffic-e2e verification. Use for backend service rewrites, cross-language migrations, compatibility ports, or capability replacements that use traffic-e2e cases as the behavior contract and must deliver the resulting code through a pull request."
---

# Backend Rewrite And Migration

Coordinate backend implementation, traffic verification, and delivery. Keep
the companion skills authoritative for their own domains.

## Invocation Contract

Treat a concise request as sufficient when it identifies the target repository,
the rewrite or compatibility objective, and any available traffic-source or
runtime facts. Discover initialized project configuration, repository scripts,
case sources, API scope, startup commands, and current implementation state
from the target instead of requiring the user to restate the standard workflow.

Do not require the user to supply recording commands, generated run IDs,
durations, replay commands, comparison commands, repair-loop instructions, or
completion rules. Generate unique UTC run IDs, pass the required explicit
duration, retain exact artifact paths, and apply the workflow below
automatically. Ask only for a fact that cannot be discovered safely and would
materially change the implementation or authorize a new external effect.

When relevant code already exists, verify it first against traffic evidence.
Preserve passing behavior and make only evidence-backed compatibility fixes;
do not rewrite working code merely because the request uses the word
"rewrite".

## Required Companion Skills

Before recording or verifying traffic, use the companion
[`traffic-e2e`](../traffic-e2e/SKILL.md) skill: read its `SKILL.md` completely
and follow its reference routing. Before modifying target code, also use the
companion [`backend-engineering`](../backend-engineering/SKILL.md) skill: read
its `SKILL.md` completely and follow its reference routing for architecture,
migration, dependency clients, implementation language, and verification.

Treat both as mandatory for implementation. This skill owns rewrite sequencing
and delivery. `traffic-e2e` owns each recording and verification operation and
its evidence gates; `backend-engineering` owns production-code quality. Do not
copy or weaken their detailed contracts here.

## Runtime Evidence

When repository files and traffic artifacts do not establish effective
behavior, inspect an available authorized source or target runtime read-only.
Useful evidence includes effective configuration, environment variable names
and provenance, startup arguments, working directory, mounts, deployment
manifests, network wiring, and dependency endpoints. Do not print, persist, or
copy secret values into logs, recordings, commits, PRs, or handoff text.

Runtime inspection is an allowed diagnostic action, not a mandatory phase and
not authority to hard-code observed values. Preserve the provenance rules in
`traffic-e2e` target integration: only direct process environment, startup
arguments, or machine-local configuration may become equivalent target inputs;
values loaded through a runtime dependency must keep that genuine dependency
path. If essential runtime evidence is unavailable, report the missing
observation and owner as `incomplete`.

## Remote Case Sources

When the user supplies a remote task-service IPv4 address instead of a local
case source, read [remote-case-source.md](references/remote-case-source.md)
before contacting the service. Use this skill's bundled
`scripts/pluto-task.sh` by absolute path, freeze one remote snapshot, safely
materialize at most one oldest unprocessed recording, and preserve every
downloaded recording unchanged. Remote acquisition may use only the helper's
`recordings` and `download` operations unless the user separately authorizes
another task-service action.

## Workflow

1. Read repository instructions, migration notes, startup paths, initialized
   traffic-e2e configuration, recording scripts, current implementation, and
   any supplied case source. Determine the earliest required phase:
   initialization, standard recording, implementation/E2E, or comparison.
   Resume from existing valid evidence instead of restarting completed phases.
   Keep unrelated worktree changes out of scope.
2. Resolve the PR base before substantial work. If
   `<target-root>/.traffic-e2e/project.yaml` exists, use its exact `pr_base`.
   Otherwise use `dev-migration` unless the user explicitly requires another
   base; never infer a different base from remote HEAD, ancestry, repository
   defaults, or `main`/`master` conventions. Ensure the resolved branch exists
   locally or on `origin`; if it exists nowhere, create it from the confirmed
   source baseline and publish it. Create a named initialization or
   implementation feature branch from that base. Branch creation, commits,
   pushes, and PR delivery belong to this orchestration skill; the traffic-e2e
   configuration initializers never switch or create branches.
3. Initialize recording only when the required target configuration or scripts
   are absent. For a Platform department repository, read
   `../platform-recording-init/SKILL.md` completely and use it for that phase.
   Require generated project configuration to record the resolved `pr_base`.
   If initialization changes the repository, commit and push it and create the
   draft PR before implementation. When valid configuration already exists,
   validate and reuse it instead of regenerating it.
4. Establish one immutable canonical E2E case source. Preserve an explicit
   local source exactly. For a remote IPv4 source, follow the remote reference
   and select at most one recording for the invocation. Otherwise call the
   repository's `scripts/start-recording` with a generated unique UTC run ID,
   explicit `--duration-seconds 60`, and one `--api` selector for the active
   API. Work on exactly one active API at a time. When the user has not named an
   API and the stated traffic source is the listener on port 18061, first run
   `nc -kl4 18061` while no recorder owns that port, observe only enough of one
   request to identify a concrete method and path, stop the listener, and use
   that API as the selector. Do not persist or report headers, credentials, or
   bodies, and do not use an unscoped recording as API discovery. Resolve the
   exact finalized run; never choose a run merely because it is newest. If the
   observation window receives no qualifying traffic, report `incomplete`
   rather than inventing a request.
5. Confirm source routes, target facade, verification policy, dependency
   wiring, and genuine runtime clients. Prepare one canonical API group at a
   time. Run the existing implementation first when present, then implement or
   repair only the smallest cohesive behavior proved necessary by the cases.
   Target code, fixtures, configuration, and test support must never consume
   expected responses or recorded dependency outputs.
6. Run repository-focused checks and focused traffic E2E. Use `traffic-e2e`
   failure classification before changing product behavior, verification
   policy, dependency wiring, or recorder attribution. Repeat the focused
   implementation/E2E cycle until the selected groups pass, then run any
   required full round after shared behavior-affecting changes.
7. Only after the affected replay E2E scope passes, call
   `scripts/start-recording-comparison` with a new generated UTC run ID,
   explicit `--duration-seconds 60`, and the same affected `--api` scope.
   Preserve wrapper-owned runtime options such as shared Breeze and
   `--brz-no-fallback`. Run offline `traffic-e2e compare` against that exact
   finalized run and shared verification policy. Only the comparison report's
   per-API passed result is current validation success.
8. Delegate every comparison difference to `traffic-e2e` diagnosis. Fix code
   for a candidate defect, re-record inconclusive source drift, and change
   policy only for source-proven intentional non-determinism. If comparison
   exposes an API without a valid E2E contract, return to standard recording
   before modifying that API. After every code or policy change, pass affected
   E2E again and create a new comparison recording. Never reinterpret an older
   comparison as evidence for changed code.
9. Continue the E2E/comparison repair loop until both evidence gates pass.
   Review module boundaries, run all repository-required gates, and preserve
   exact artifact identities and remaining blockers.

## Loop State And Routing

Keep one explicit state record for the active API:

```text
api, stage, case_source, source_revision, e2e_evidence,
comparison_evidence, last_failure_category, next_todo, todo_owner, resume_stage
```

Advance only through:

```text
select_api -> record -> prepare -> e2e -> compare -> api_done -> select_api
```

Do not select another API until the active API is `api_done`. Do not enter
comparison without runner-generated proof that the active API's complete E2E
scope passed after the latest behavior, policy, attribution, or case-source
change. Route every non-passing result before acting:

- `target_behavior`: give an evidence packet to `backend-engineering`, repair
  the target, and rerun E2E against the same source;
- `target_environment`: repair the target runtime configuration or wiring and
  rerun E2E against the same source;
- `background_dependency`: prove process-level ownership, apply the narrow
  background rule, make a new standard recording for the same API, prepare it,
  and rerun E2E;
- `recording_configuration`: repair target-owned recording configuration, make
  a new standard recording, prepare it, and rerun E2E;
- `intentional_nondeterminism`: apply only source-proven policy, then rerun E2E
  before making a new comparison recording;
- `source_drift`: obtain a new comparison observation without reinterpreting
  the old report;
- `recorder_capability_gap` or `replay_capability_gap`: report `blocked` with a
  TODO owned by `traffic-e2e-system`; do not modify the traffic-e2e
  implementation or add a target workaround;
- `unresolved`: continue diagnosis without changing code, policy, or
  attribution.

A confirmed Recorder or Replay capability gap stops immediately after one
bounded reproduction proves that the genuine contract cannot be captured or
replayed and that target wiring or configuration is not the cause. For other
categories, stop as `blocked` when the same root cause repeats for three
consecutive repair cycles without new evidence or meaningful progress. Report
`incomplete` when work can continue but a required gate, qualifying traffic,
runtime access, or other external observation is still missing.

## Delivery

When deliverable target source, config, test, script, or documentation changes
exist, commit the intended changes on the feature branch, push them, and create
a draft PR against the resolved base before the final response. A blocked or
incomplete replay does not waive delivery; describe its exact evidence and
blockers in the PR.

Skip PR creation only when the user explicitly requests no PR or when no
deliverable target change exists. A project/task association is not required
unless repository instructions or the user separately require one.

For a remote case source, the final handoff must also identify the IPv4
address, frozen snapshot boundary, selected recording ID, cache root, archive
SHA-256, every resolved canonical case source, and their exact runner states.
Downloaded artifacts or helper success never substitute for replay completion
evidence.

## Final Decision Record

Constrain the final decision, not the investigation. Do not force commentary,
diagnosis, code review, or intermediate repair work into a report schema. Omit
inapplicable fields and do not emit placeholders or invented values.

For a verified API, use this short form:

```text
Status: complete
API: <METHOD pattern>
E2E: passed — <exact current report>
Compare: passed — <exact current report>
Delivery: <PR or delivered artifact>
Conclusion: <one explicit sentence>
```

For an API that cannot currently complete, use:

```text
Status: incomplete | blocked
API: <METHOD pattern>
Stage: <select_api | record | prepare | e2e | compare>
Conclusion: <one explicit sentence>
E2E: <not_run | failed | passed | stale> — <report when available>
Compare: <not_started | failed | passed | stale> — <report when available>
Category: <evidence-backed failure category>
Evidence:
- <exact artifact or observation>
Next TODO:
- Owner: <responsible actor or component>
- Action: <specific next action>
- Acceptance: <how completion will be verified>
- Resume from: <stage>
- Required transitions: <only re-record, rerun E2E, or new comparison if needed>
```

Use `complete` only when the API is `api_done` and current E2E and comparison
evidence both pass. If E2E is not current and passing, comparison must be
`not_started` or `stale`. For `background_dependency`, require re-recording and
resume from `record`. For a Recorder or Replay capability gap, use `blocked`,
set the owner to `traffic-e2e-system`, and state the required system change and
its acceptance check. Every `incomplete` or `blocked` result requires an
actionable owner, TODO, acceptance condition, and resume stage.

A draft PR or delivered change is not verification success. Do not use vague
handoffs such as “continue investigating”, and never use success wording while
an applicable gate is missing.
