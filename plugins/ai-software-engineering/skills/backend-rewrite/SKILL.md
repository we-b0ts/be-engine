---
name: backend-rewrite
description: "Rewrite or migrate backend services against local recorded traffic or recordings fetched from a remote task-service IPv4 address while applying backend engineering standards and genuine traffic-e2e verification. Use for backend service rewrites, cross-language migrations, compatibility ports, or capability replacements that use traffic-e2e cases as the behavior contract and must deliver the resulting code through a pull request."
---

# Backend Rewrite And Migration

Coordinate backend implementation, traffic verification, and delivery. Keep
the companion skills authoritative for their own domains.

## Required Companion Skills

Before modifying target code:

1. Read `../backend-engineering/SKILL.md` completely and follow its reference
   routing for architecture, migration, dependency clients, implementation
   language, and verification.
2. Read `../traffic-e2e/SKILL.md` completely and follow its reference routing
   for recording, grouping, genuine dependency replay, response assertions,
   failure diagnosis, and completion evidence.

Treat both as mandatory. This skill owns sequencing and delivery only; do not
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

1. Read repository instructions, migration notes, startup paths, and any
   supplied recording source. Determine whether the request is recording
   initialization, case recording, or implementation. When the user asks to
   initialize recording, or no recording setup exists yet, follow
   `traffic-e2e`'s project-initialization reference before requiring cases or
   modifying product code. Under an explicit `backend-rewrite` invocation,
   interpret a concise `<repo> repo init` request as this recording-
   initialization phase unless the user names another initialization scope.
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
3. Run recording initialization on the feature branch. The standard project
   initializer records the resolved base as `pr_base`; require the generated
   value to match. Commit and push the generated initialization, then create a
   draft PR targeting that base. If project configuration already exists,
   validate its `pr_base` instead of silently replacing it.
4. Confirm a canonical traffic-e2e case source for implementation. Preserve an
   explicit local case-source path exactly. For a remote IPv4 source, follow
   the remote-case-source reference, materialize candidates in ascending order,
   select at most one recording for the invocation, and inspect its resolved
   canonical sources before implementation. Otherwise, if cases must be
   recorded first, complete the traffic skill's recording gate. Then confirm
   the source route, target facade, replay policy, dependency wiring, and
   genuine runtime clients. Prepare one canonical API group at a time.
5. Implement the smallest cohesive production change that preserves the
   recorded contract. Do not read expected responses or recorded dependency
   outputs from target code, fixtures, configuration, or test support.
6. Run repository-focused checks and the canonical focused traffic replay.
   Delegate failure classification, replay policy, recorder attribution, and
   completion evidence to `traffic-e2e`; do not create parallel rules here.
7. Repeat focused implementation and verification only until the selected
   group passes. Run the required complete round after shared
   behavior-affecting changes.
8. Review module boundaries, run all repository-required gates, and preserve
   the exact traffic-e2e completion status and remaining blockers.

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
