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
absent. For a Platform department repository, read
`../../platform-recording-init/SKILL.md` completely and use it for that phase.
Require generated project configuration to record the resolved `pr_base`.

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
for discovery. If no qualifying traffic arrives, report `incomplete`.

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
unavailable, report the missing observation and owner as `incomplete`.

## Delegate Target-Code Work

Confirm source behavior, target facade, verification policy, dependency wiring,
and genuine runtime clients. Before delegating `target_behavior`, provide:

```text
active scope, immutable case source and IDs, structured response difference,
causal dependency evidence, source behavior evidence, requested outcome
```

When source code, runtime evidence, recorded dependency targets, or the target
contains Breeze, read and use `../../breeze-sdk/SKILL.md`. Add the complete
logical resource identity, operating mode (`independent`, `recording`,
`comparison`, or `replay`), and exact descriptor or port evidence to the
target-code packet. In replay mode, require read-only resolution and treat a
missing exact descriptor as a startup blocker; do not authorize creation,
mutation, or a protocol-default port.

Use `backend-engineering` for target-owned implementation and local checks.
Record its result as:

```text
todo_status, changed_behavior, affected_apis, changed_resources,
descriptor_behavior, local_checks
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
- `background_dependency`: only after response assertions pass and source
  proves ownership plus independence, apply the narrow rule, make a new
  standard recording, prepare it, and rerun E2E.
- `recording_configuration`: repair supported configuration, make a new
  recording, prepare it, and rerun E2E.
- Missing or invalid configured request-header key: obtain the authorized
  secret and resume the same stage; use `incomplete` when unavailable. A
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

For a completed slice, report its scope, current passing E2E and comparison
reports, delivery artifact, and one explicit conclusion. Otherwise report:

```text
status, scope, stage, conclusion
E2E and comparison state with exact reports when available
all independently evidenced failure categories
next TODO: owner, action, acceptance, resume stage, required transitions
```

Do not emit placeholders or vague TODOs. Never use success wording while an
applicable gate is missing.
