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

Before recording or verifying traffic, read `../traffic-e2e/SKILL.md`
completely and follow its reference routing. Before modifying target code, also
read `../backend-engineering/SKILL.md` completely and follow its reference
routing for architecture, migration, dependency clients, implementation
language, and verification.

Treat both as mandatory for implementation. This skill owns rewrite sequencing
and delivery. `traffic-e2e` owns each recording and verification operation and
its evidence gates; `backend-engineering` owns production-code quality. Do not
copy or weaken their detailed contracts here.

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
   explicit `--duration-seconds 60`, and repeatable `--api` selectors when the
   affected scope is known. Resolve that exact finalized run; never choose a
   run merely because it is newest. If the observation window receives no
   qualifying traffic, report `incomplete` rather than inventing a request.
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

If the same root cause blocks three consecutive repair cycles without new
evidence or meaningful progress, stop the loop and report `blocked` with the
exact E2E and comparison artifacts. Report `incomplete` instead when work can
continue but a required gate, qualifying traffic, or other external
observation is still missing.

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
