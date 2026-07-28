# Backend Rewrite Workflow

Use this execution reference after the main skill establishes rewrite scope,
ownership, repair priority, and completion gates.

## Contents

- Discover and resume
- Resolve delivery base
- Initialize only when needed
- Establish one case source
- Inspect runtime evidence
- Delegate target-code work
- Run the evidence loops
- Route non-passing evidence
- Deliver and report

## Discover And Resume

Treat a concise request as sufficient when it identifies the target repository,
rewrite objective, and available traffic or runtime facts. Discover repository
instructions, migration notes, startup paths, initialized traffic-e2e
configuration, recording scripts, source routes, case sources, and current
implementation state. Ask only for a fact that cannot be discovered safely and
would materially change the implementation or authorize a new external effect.

Determine the earliest required phase: initialization, standard recording,
implementation/E2E, or comparison. Resume from valid evidence and keep
unrelated worktree changes out of scope. Generate unique UTC run IDs, pass
explicit recording durations, and retain exact artifact paths.

## Resolve Delivery Base

Resolve the PR base before substantial work. If
`<target-root>/.traffic-e2e/project.yaml` exists, use its exact `pr_base`.
Otherwise use `dev-migration` unless the user explicitly requires another
base. Never infer a different base from remote HEAD, ancestry, repository
defaults, or `main`/`master` conventions.

Ensure the base exists locally or on `origin`; if it exists nowhere, create it
from the confirmed source baseline and publish it. Create a named
initialization or implementation feature branch from that base. Traffic-e2e
configuration initializers never create or switch branches.

## Initialize Only When Needed

Initialize recording only when required target configuration or scripts are
absent. For a Platform department repository, read the
[`platform-recording-init` skill](../../platform-recording-init/SKILL.md)
completely and use it for that phase. Require generated project configuration
to record the resolved `pr_base`.

If initialization changes the repository, commit and push it and create the
draft PR before implementation. Validate and reuse existing configuration
instead of regenerating it.

## Establish One Case Source

Preserve an explicit local source exactly. For a remote IPv4 source, follow
[remote-case-source.md](remote-case-source.md) and select at most one recording
for the invocation. Otherwise invoke the repository's `scripts/start-recording`
with a unique UTC run ID, explicit `--duration-seconds 60`, and one `--api`
selector for the active API.

When the user has not named an API and traffic is expected on port 18061,
listen only long enough to identify one concrete method and path while no
recorder owns the port, then stop and use that selector. Do not persist or
report headers, credentials, or bodies, and do not use an unscoped recording
for discovery. If no qualifying traffic arrives, report `blocked` because the
external case input was not provided.

Resolve the exact finalized run; never choose a run merely because it is
newest. When request-header encryption is configured, require the named key
environment and keep its value out of commands, logs, cases, target
configuration, and supporting services.

## Inspect Runtime Evidence

When repository files and artifacts do not establish effective behavior,
inspect an available authorized source or target runtime read-only. Limit the
inspection to effective configuration names and provenance, startup arguments,
working directory, mounts, deployment metadata, network wiring, and dependency
endpoints.

Do not print or persist secret values. Runtime inspection is diagnostic
evidence, not authority to hard-code observed values. If essential evidence is
unavailable and target behavior cannot be implemented without it, report the
missing observation and owner as `blocked`.

## Delegate Target-Code Work

Confirm source behavior, target facade, verification policy, dependency wiring,
and genuine runtime clients. Before delegating `target_behavior`, provide:

```text
active scope, immutable case source and IDs, structured response difference,
causal dependency evidence, source behavior evidence, requested outcome
```

Source-process local caches belong to target implementation. Inspect and
reproduce cache-key derivation, bounded capacity and eviction, expiry or
refresh timing, negative caching, concurrent-load behavior, startup or warmup
behavior, and miss/error fallback only where they affect the active behavior
or operational contract. Equivalent target architecture is allowed.

When target-code work designs, implements, integrates, migrates, or reviews
business-independent remote-resource access managed through Breeze, read the
[`breeze-sdk` skill](../../breeze-sdk/SKILL.md) completely before delegating or
writing that code, and use it for that work. This explicitly includes
Memcached, Redis, MySQL, Kafka, queues such as MCQ or QueueService, Motan, and
other Breeze-managed remote resources. Add the resource type, source access
semantics, business/resource boundary, and relevant runtime or recorded
dependency evidence to the target-code packet. Let `breeze-sdk` determine the
reusable resource identity, runtime mode, and client lifecycle; keep SQL, keys,
messages, RPC contracts, provider mapping, and orchestration in the target
capability.

Use the
[`backend-engineering` skill](../../backend-engineering/SKILL.md) for
target-owned implementation and local checks. Record its result as:

```text
todo_status, changed_behavior, affected_apis, changed_resources,
resource_runtime_behavior, local_checks
```

The target-code task must not declare migration completion, start comparison,
change background attribution or replay policy, modify traffic-e2e, decrypt
recordings, or receive a recording key. This orchestration reruns E2E and
decides the next state.

## Run The Evidence Loops

1. Run repository-focused checks and focused traffic E2E against the immutable
   cases.
2. Use traffic-e2e diagnosis before changing product behavior, policy,
   dependency wiring, or recorder attribution.
3. Follow the main skill's response-first repair priority until the selected
   groups pass. Run a full round after shared behavior-affecting changes when
   required.
4. Only after affected replay E2E passes, invoke
   `scripts/start-recording-comparison` with a new UTC run ID, explicit
   `--duration-seconds 60`, and the same affected `--api` scope. Preserve
   wrapper-owned runtime options and the encryption-key boundary.
5. Run offline `traffic-e2e compare` against that exact finalized run and the
   shared verification policy. Only the report's per-API passing result is
   current comparison evidence.
6. Delegate comparison differences to traffic-e2e diagnosis. Fix candidate
   behavior, re-record inconclusive source drift, or change policy only for
   source-proven intentional non-determinism.
7. After every code or policy change, pass affected E2E again and create a new
   comparison recording. Never reinterpret an older report for changed code.

## Route Non-Passing Evidence

- `target_behavior`: delegate target code, then rerun E2E against the same
  source.
- `target_environment`: repair target runtime wiring, then rerun E2E.
- Response-driving dependency failure: repair target or Replay wiring needed
  to reproduce the source response, then rerun E2E.
- Response-driving process state: when source and recording evidence prove a
  scheduled dependency call builds local state required by the response,
  apply a narrow `runtime_state` background rule, make a new standard
  recording, prepare it, and continue response repair. Traffic E2E currently
  supports Breeze-backed Memcached `get` over a bounded numeric key series and
  delays source case admission until the configured first-load count. If the
  target still differs because its corresponding local cache has not completed
  initialization, repair target startup, readiness, or cache lifecycle from
  source evidence; do not treat target timing as a Replay capability gap.
- `background_dependency`: only after response assertions pass and source
  proves ownership plus independence, apply a narrow `independent` rule, make
  a new standard recording, prepare it, and rerun E2E.
- `recording_configuration`: repair supported configuration, make a new
  recording, prepare it, and rerun E2E.
- Missing or invalid configured request-header key: obtain the authorized
  secret and resume the same stage; use `blocked` when unavailable. A
  Recorder or Replay inability to honor configured encryption is a system
  capability gap.
- `intentional_nondeterminism`: apply only source-proven policy, rerun E2E, and
  then make a new comparison recording.
- `source_drift`: obtain a new comparison observation.
- `recorder_capability_gap` or `replay_capability_gap`: assign the exact system
  change and acceptance check to `traffic-e2e-system`; do not create a target
  workaround.
- `unresolved`: continue diagnosis without changing code, policy, or
  attribution.

A capability gap blocks the affected gate but does not suppress an independent
response repair. Stop the whole rewrite only when it prevents exercising the
response contract, or after response repair when the remaining gate cannot
advance.

Dirty dependency evidence never stops response repair. If any response
assertion fails, keep the result `action_required` and continue target,
environment, or response-driving dependency work.

Conclude that recording data blocks implementation only from one
representative case that proves all of the following:

- the relevant source response path, including process-local cache behavior,
  has been inspected;
- every corresponding behavior determinable from source code and configuration
  has an equivalent target implementation and focused verification;
- the exact response-driving external value or semantic exchange is absent or
  internally inconsistent in the recording and available runtime evidence;
- completing the response would require inventing external-system behavior.

Until that proof exists, keep a response mismatch as `action_required`.
Repeated failed implementation attempts are not evidence of a recording-data
blocker.

## Deliver And Report

Run repository-required gates and review module boundaries. When deliverable
target source, configuration, tests, scripts, or documentation exist, commit
the intended changes, push the feature branch, and create a draft PR against
the resolved base before the final response. A blocked or incomplete replay
does not waive delivery. Skip a PR only when the user explicitly requests no
PR or no deliverable target change exists.

For a remote source, identify the IPv4 address, frozen snapshot boundary,
selected recording ID, cache root, archive SHA-256, canonical case sources,
and exact runner states.

Begin every report for a non-passing E2E run with response diagnosis:

```text
response: selected cases, executed cases, passing cases, mismatching cases
representative case: case ID, fields, expected/actual shape, cause, evidence
```

The counts must come from the exact current report. Explain exactly one
representative non-passing case in detail; do not enumerate every failed case
in the final report. Use a response-mismatching case for `blocked` and a
response-passing dirty case for `incomplete`. Describe its structured fields
and expected-versus-actual shape without exposing secrets, connect it to source
and target behavior or a response-driving dependency, and state whether the
cause is proven. Do not claim the representative explains other cases without
shared difference and code-path evidence. A list of differing fields, unused
dependencies, or generic “dependency issue” is not a causal explanation.

After response diagnosis, report dependency cleanliness and other blockers,
then status, exact evidence paths, delivery, and next action. For a completed
slice, report its scope, current passing E2E and comparison reports, delivery
artifact, and one explicit conclusion. For any non-complete result also report:

```text
status, scope, stage, conclusion
E2E and comparison state with exact reports when available
all independently evidenced failure categories
next TODO: owner, action, acceptance, resume stage, required transitions
```

Do not emit placeholders or vague TODOs. Never use success wording while an
applicable gate is missing.
