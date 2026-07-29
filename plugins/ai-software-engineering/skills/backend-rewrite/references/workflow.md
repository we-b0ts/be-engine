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

When `scripts/<project>-cli` already exists, inspect it during discovery before
accepting target startup or replay integration as valid. Check it against the
traffic-e2e [target integration contract](../../traffic-e2e/references/target-integration.md).
If it parses replay sessions or dependency artifacts to derive target
configuration, record a `target_behavior` dependency-wiring repair and complete
that repair before the next E2E attempt.

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
inspect an available authorized source or target runtime read-only. Trace each
response-driving value until its implementation and effective input are known:

```text
response assignment -> process-local state -> backend call -> framework wiring
-> configuration key -> effective runtime configuration -> resource hostname
```

Search pinned dependency source; inspect or decompile the exact packaged
artifact when necessary. If static files stop at a placeholder, inspect the
effective runtime configuration. Restart or recreate the source container
through its authoritative entrypoint only when startup is required to
materialize that configuration. Preserve its image, arguments, mounts,
network, and business behavior, and treat traffic from that diagnostic
lifecycle as non-evidence.

Never patch source code or artifacts, alter business switches, print secrets,
or hard-code a runtime observation. Record the last proven link and exact
missing link; use `blocked` only when the missing external observation prevents
target implementation.

## Delegate Target-Code Work

Confirm source behavior, target facade, verification policy, dependency wiring,
and genuine runtime clients. Delegate `target_behavior` with the active scope,
immutable case source and IDs, structured response difference, causal
dependency evidence, source behavior, and requested outcome.

Before the first genuine target E2E and after every target startup or
dependency-wiring change, re-review the complete `scripts/<project>-cli`
facade. Replace initialization-only mock behavior rather than layering runtime
inference onto it. Target commands must not parse replay sessions or dependency
artifacts to derive configuration. For Breeze-managed wiring, apply the
[`breeze-sdk` skill](../../breeze-sdk/SKILL.md); resource packages, not the
facade, own descriptor-library use and client construction.

Source-process local caches belong to target implementation. Inspect and
reproduce cache-key derivation, bounded capacity and eviction, expiry or
refresh timing, negative caching, concurrent-load behavior, startup or warmup
behavior, and miss/error fallback only where they affect the active behavior
or operational contract. Equivalent target architecture is allowed.

For Breeze-managed work, include the resource type, source access semantics,
business/resource boundary, and relevant runtime evidence. Let `breeze-sdk`
own reusable identity, descriptor policy, and client lifecycle; keep business
contracts in the target capability. Adding a resource must not require a
project-CLI change.

Use [`backend-engineering`](../../backend-engineering/SKILL.md) for target
implementation and local checks. Companion work cannot declare migration
completion or change traffic policy; this workflow reruns E2E and decides the
next state.

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
6. Delegate comparison differences to traffic-e2e diagnosis. Fix every
   candidate-only field, re-record a field-scoped inconclusive source change,
   or change policy only for source-proven intentional non-determinism.
7. After every code or policy change, pass affected E2E again and create a new
   comparison recording. Never reinterpret an older report for changed code.

## Route Non-Passing Evidence

- `target_behavior`: delegate target code, then rerun E2E against the same
  source.
- `target_environment`: repair target runtime wiring, then rerun E2E.
- Response-driving dependency failure: repair target or Replay wiring needed
  to reproduce the source response, then rerun E2E.
- Suspected missing dependency recording: resolve the source resource hostname,
  then follow traffic-e2e's missing-evidence checkpoint. A Breeze snapshot
  match is Recorder bypass; let resource-capture `plan/apply` own the config
  update. A changed apply requires a new standard recording; an unchanged plan
  returns to recording-path diagnosis. Keep this
  `recording_configuration/action_required`.
- Response-driving process state: when source and recording evidence prove a
  scheduled dependency call builds local state required by the response,
  follow traffic-e2e's guarded `runtime_state` procedure and record again. If
  target local state still differs, repair target startup, readiness, or cache
  lifecycle rather than treating target timing as a Replay gap.
- `background_dependency`: only after response assertions pass and source
  proves ownership plus independence, apply a narrow `independent` rule, make
  a new standard recording, prepare it, and rerun E2E.
- `recording_configuration`: repair supported configuration, make a new
  recording, prepare it, and rerun E2E.
- Missing configured request-header key: obtain the authorized secret and
  resume the same stage; this remains `action_required`, not a recording-data
  blocker.
- `intentional_nondeterminism`: apply only source-proven policy, rerun E2E, and
  then make a new comparison recording.
- `source_change`: require source-before/source-after change at the same
  response location; preserve unrelated candidate-only fields as
  `target_behavior`.
- `verification_policy`: remove or replace stale and unsupported response rules
  through the evidence-validating interface, rerun E2E, then create a new
  comparison recording.
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

Use the main skill's state and representative-case contracts. Begin a
non-passing E2E report with current selected, executed, passing, and mismatching
counts followed by exactly one representative case.

Use a response-mismatching case for `blocked` and a response-passing dirty case
for `incomplete`. Connect the selected fields to one causal path; never replace
it with a field list or generic dependency issue. When provenance remains
unresolved, report the last proven link, exact next missing link, and the
repository path, packaged symbol, configuration key, runtime path, or resource
already checked. Never summarize these states as “insufficient source-code
evidence” or “drift”.

Then report dependency cleanliness, independent blockers, delivery, status,
scope, stage, conclusion, exact E2E/comparison reports, and a next TODO with
owner, action, acceptance check, resume stage, and required transitions.

For a remote source, also retain its IPv4 address, frozen snapshot boundary,
recording ID, cache root, archive SHA-256, canonical case sources, and runner
states. Never use success wording while an applicable gate is missing.
