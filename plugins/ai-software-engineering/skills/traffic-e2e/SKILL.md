---
name: traffic-e2e
description: "Operate traffic-e2e across managed traffic recording, published case inspection and grouping, genuine dependency replay, response verification, failure diagnosis, and recorder feedback. Use when recording application traffic, replaying recorded cases, validating a rewrite or software change against recorded behavior, diagnosing recording or replay failures, or maintaining traffic-e2e policies and generated evidence. Do not invoke merely to develop or review the traffic-e2e tool implementation itself."
---

# Traffic E2E

Use traffic recording and replay to preserve one observable software contract:
the inbound request and expected response, every case-owned dependency call,
and every required side effect.

## Mandatory Semantics

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Recording and
replay completion are conjunctions of all applicable gates. A matching response
cannot compensate for invalid recording artifacts, dirty dependency evidence,
missing side effects, or incomplete case coverage.

Published recordings are immutable evidence. Never edit, rename, move, trim,
or synthesize their requests, expected responses, dependency files, summaries,
or run metadata to make replay pass.

`expected-response.json` is assertion-only. `dependencies.jsonl` and bootstrap
dependency files are recorder-owned replay inputs. Target product code, target
E2E code, test support, commands, and application config MUST NOT read them to
construct actual behavior or dependency results. Replay must exercise the
target's genuine production dependency clients through recorder-owned listeners.

Recording directories contain sensitive request, response, database, cache,
queue, credential-adjacent, and business data. Keep them out of Git, logs, and
unapproved copies. Respect configured header redaction and access policy; do
not silently weaken either for convenience.

## Reference Routing

- Read [recording.md](references/recording.md) before every managed recording
  or recording-failure diagnosis.
- Read [case-format.md](references/case-format.md) when resolving artifacts or
  deciding whether a case is publishable replay evidence.
- Read [case-grouping.md](references/case-grouping.md) for a collection or run
  with multiple canonical input directories.
- Read [target-integration.md](references/target-integration.md) before wiring
  target startup, configuration, identity, genuine dependencies, or the standard
  project facade.
- Read [route-pattern-feedback.md](references/route-pattern-feedback.md) after
  source-route resolution whenever a managed case-path-pattern plan applies.
- Read [dependency-replay.md](references/dependency-replay.md) when wiring or
  diagnosing dependency behavior.
- Read [replay-policy.md](references/replay-policy.md) before creating,
  changing, or validating replay policy.
- Read [replay-lifecycle.md](references/replay-lifecycle.md) for direct replay
  or low-level lifecycle diagnosis.
- Read [e2e-run.md](references/e2e-run.md) for the standard `init`, `prepare`,
  `run-api`, `run`, `status`, `recover`, and `abort` workflow.
- Read [aggregate-report.md](references/aggregate-report.md) when replaying a
  collection, multiple cases, runs, reports, or sessions.
- Read [verified-excludes.md](references/verified-excludes.md) only after final
  aggregate and response assertion evidence exists.
- Read [failure-diagnosis.md](references/failure-diagnosis.md) after the first
  failed recording or replay attempt.

## Managed Recording Workflow

1. Inspect the target's normal startup and authoritative
   `.traffic-e2e/recorder.toml` or explicitly supplied recorder config. Confirm
   upstreams, readiness, recording rules, output directory, body limits,
   redaction, dependency timing, access policy, bypass behavior, and enabled
   protocols. Do not create target-specific values by guessing.
2. Confirm the dedicated interception identity and how the dependency-producing
   target will run as that identity or share its network namespace. Build and
   setup work may run as the developer, but intercepted dependency traffic must
   come from the fixed identity. Do not widen interception to the login user,
   an arbitrary UID, or all processes.
3. Start managed recording with `traffic-e2e record --config <config>` and let
   the command own DNS, fake-IP interception, recovery, and shutdown. Use
   `--no-dns` only when routing is deliberately provided another way. Do not
   replace managed recording with low-level `diagnose` commands in normal use.
4. Start or restart the genuine target in its normal configuration. Wait for
   the configured readiness condition, not a guessed fixed sleep or a response
   that the application can produce before its business dependencies are ready.
5. Send only the intended trigger requests. Preserve the real authentication,
   headers, body, routing, and runtime dependency paths needed by the contract.
   Avoid overlapping matched requests because one recording case owns one
   active dependency window.
6. Allow the configured post-response admission window to close and already
   admitted dependencies to drain. Continuous background traffic must not keep
   a case open; do not raise drain timeouts to mask an ownership or protocol
   problem.
7. Stop recording cleanly so the run can finalize. Inspect `errors.jsonl`,
   `recording-run.json`, run-level summaries, and `failed/` before treating any
   case as published. Failed, partial, truncated, dirty, policy-rejected, or
   drain-timeout artifacts are diagnostics, never replay inputs.
8. Validate the selected case request, expected response, semantic dependency
   file, and summary. A published zero-dependency case requires the explicit
   empty `dependencies.jsonl` plus its zero-event summary; a missing dependency
   file is not equivalent.

## Replay And Verification Workflow

1. Resolve the supplied case, collection, or run. Ignore `failed`, `staging`,
   `.replay`, `.partial`, and `.truncated` artifacts. Retain the exact source and
   selected published case IDs for every completion claim.
2. Inspect the target entrypoint, normal startup, config, dependency wiring,
   existing tests, and source behavior when a rewrite or migration is involved.
   Require genuine clients and the same runtime path used outside E2E.
3. Create or reuse `.traffic-e2e/replay.yaml` with
   `expected_response: assertions_only`, validate it, and pass it explicitly.
   Audit target code and support for forbidden expected-response, dependency
   recording, fixture, or replay-control data flows.
4. For the standard workflow, generate `.traffic-e2e/e2e.yaml` with
   `traffic-e2e init`; do not hand-write or repair runner state. Confirm the
   project facade, replay policy, PR base, and optional recorder config/rule.
5. Prepare exactly one canonical API or capability group at a time. Resolve the
   source route before applying safe dynamic case patterns. Do not infer API
   identity from a directory name.
6. Run `traffic-e2e run-api` only until the complete selected group passes.
   Fix target behavior, target integration, recording quality, or narrowly
   supported replay policy according to evidence. Do not repeat a successful
   source merely to advance verification counters.
7. Compare JSON structurally and non-JSON according to the configured exact
   policy. Preserve field presence, scalar kinds, array semantics, status,
   dependency identity, ordering, errors, and required side effects. A stable
   mismatch is not automatically dynamic or ignorable.
8. After all selected groups pass, retain grouped evidence unless a later
   behavior-affecting change can invalidate an earlier group. When required,
   run one complete `traffic-e2e run`; repair failures through focused
   `run-api`, then restart the full round.
9. Use runner-owned reports, aggregation, progress, pattern feedback, and
   verified excludes. Do not parse partial output or manually edit generated
   local state to manufacture completion.

If the same root cause repeats for three consecutive cycles without new
evidence or meaningful progress, stop as `blocked` or `incomplete`. A final
success must occur after the last behavior-, wiring-, policy-, assertion-, or
structure-affecting change.

## Recording Completion Gate

MUST NOT call a recording usable unless:

1. managed recording shut down and finalized without unrecovered interception
   state;
2. the intended trigger reached the genuine source target after readiness;
3. each selected case is canonically published with complete request and
   expected-response bodies;
4. every selected case contains semantic dependency evidence and a summary,
   including explicit zero-dependency evidence when applicable;
5. no selected case exists only under `failed/`, `.partial`, or `.truncated`;
6. access-policy rejection, proxy error, unsupported protocol, unsafe capture,
   drain timeout, or truncation does not invalidate the selected contract;
7. sensitive artifacts remain in the approved recording location and outside
   version control.

When a gate fails, preserve the diagnostics, fix the target/config/recorder
cause, and record a new run. Never repair a published run in place.

## Replay Completion Gate

MUST NOT claim a selected replay scope passed unless:

1. every selected case belongs to exactly one canonical group and published
   recordings remain unchanged;
2. the final replay policy is validated, assertion-only, fingerprinted, and has
   zero unused applicable rules;
3. direct audit proves no expected response or recorded dependency result flows
   into target behavior, fixtures, branches, caches, or side effects;
4. the fixed interception identity produced dependency traffic through genuine
   target clients, or explicit no-intercept routing is independently valid;
5. every selected case ended cleanly and the final report is finalized with the
   exact case and session IDs;
6. exact aggregate evidence is complete and clean for every applicable case,
   report, and session;
7. response assertions pass after the last behavior-affecting change;
8. applicable case-path-pattern and verified-exclude workflows reached their
   canonical final statuses;
9. runner-generated progress reports the current selected logical run complete
   when the standard runner applies.

Target scripts, exit codes, summaries, hand-maintained counts, and prose notes
cannot replace canonical recorder and runner artifacts.

## Change Delivery Gate

When replay or migration work produces deliverable target source, config, test,
script, or documentation changes, commit the intended changes on the feature
branch, push it, and create a draft PR against the confirmed `pr_base` before
the final response. An `incomplete` or `blocked` E2E result does not waive this
delivery requirement; preserve the exact status and blockers in the PR.

Skip PR creation only when the user explicitly requests no PR or when no
deliverable target change exists. Keep unrelated pre-existing worktree changes
out of the commit and PR.

## Stop And Report

Do not invent requests, responses, rows, cache values, queue messages,
dependency parameters, side effects, source routes, or completion artifacts.
Stop when recording evidence, genuine dependency behavior, a supported policy,
or a required target fact is missing.

For design and diagnosis questions, answer normally. When executing replay or
making a completion claim, report `complete`, `incomplete`, or `blocked` with
the exact case source and IDs, final session/report, aggregate, policy,
assertion, pattern, verified-exclude status, verification command, and remaining
blockers. When the change delivery gate applies, also report the branch, commit,
and PR URL. Never use success wording while an applicable gate is missing.
