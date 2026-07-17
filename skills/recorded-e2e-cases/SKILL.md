---
name: recorded-e2e-cases
description: Replay, group, and diagnose E2E tests from traffic-recorder-proxy case, collection, or run directories, and maintain replay-time recorder feedback in the target repo. Use for recorded request/response artifacts, API-by-API grouping, dependency replay, aggregate reports, recorder.toml case_path_patterns, replay-verified API excludes, or case-driven failures.
---

# Recorded E2E Cases

Treat a recorded case as one contract: inbound request and expected response,
plus every case-owned dependency touch and required side effect.

## Mandatory Semantics

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Completion is
the conjunction of every applicable gate. Partial evidence remains
`incomplete` or `blocked`; a passing response cannot compensate for dirty or
missing dependency evidence.

Before replay, retain the exact completion case source and selected published
case ids. Never claim a parent collection or run passed after replaying a
subset.

`expected-response.json` is assertion-only. `dependencies.jsonl` and bootstrap
dependency files are recorder-owned replay inputs. Target product code, E2E
code, test support, commands, and application config MUST NOT read them to
construct actual behavior or dependency results. Recorded E2E must exercise
genuine target dependency clients through recorder-owned replay, not fixtures,
fakes, in-process mocks, or recording-backed target implementations.

## Reference Routing

- Read [case-format.md](references/case-format.md) when resolving artifacts.
- Read [case-grouping.md](references/case-grouping.md) for a collection or run
  with multiple canonical input directories.
- Read [route-pattern-feedback.md](references/route-pattern-feedback.md) after
  source-route resolution whenever a dynamic pattern or final managed
  case-path-pattern plan is applicable, including a static no-candidate plan.
- Read [dependency-replay.md](references/dependency-replay.md) when wiring or
  diagnosing dependency behavior.
- Read [replay-policy.md](references/replay-policy.md) before creating, changing,
  or validating dynamic rules.
- Read [replay-lifecycle.md](references/replay-lifecycle.md) for every replay.
- Read [e2e-run.md](references/e2e-run.md) when the target uses the standard
  migration runner, focused API iteration, full-round progress, or recovery.
- Read [aggregate-report.md](references/aggregate-report.md) when aggregate is
  applicable.
- Read [verified-excludes.md](references/verified-excludes.md) only after final
  aggregate and response assertions exist.
- Read [failure-diagnosis.md](references/failure-diagnosis.md) after the first
  failed replay.

## Workflow

1. Resolve the supplied case, collection, or run. Ignore `failed`, `staging`,
   `.replay`, `.partial`, and `.truncated` artifacts. Require canonical request
   and expected-response files and preserve published recordings exactly.
2. Inspect the target recorded-E2E entrypoint, normal startup, config, genuine
   dependency wiring, existing test convention, and migration notes linked from
   `AGENTS.md`. Require the case source as an explicit input. Consult any
   matching known lesson before the first replay or retry. Do not build one
   simultaneous implementation scope for a whole collection.
3. Create or reuse target `config/replay.yaml`, require
   `expected_response: assertions_only`, validate it, and pass it explicitly to
   every replay. Audit target code and wiring for forbidden expected-response,
   dependency-file, and fixture data flows before replay and before completion.
4. If `.migration/e2e.yaml` is missing, call `traffic-e2e-run init` with the
   confirmed target project CLI, replay policy, and PR base. The
   command generates and validates the file; do not hand-write it. If any
   required project fact cannot be confirmed from the target repository, ask
   the user for it before replay. Every later runner command must reject a
   missing or incomplete config or a PR base that no longer exists. `prepare`,
   `run-api`, and `run` must reject detached HEAD and the configured PR base.
5. For each API being migrated, select one unprocessed directory, use its first
   case only to discover the candidate source route, then call
   `traffic-e2e-run prepare`. Supply the confirmed source route and, for a
   dynamic route, its safe whole-segment pattern. Use only the canonical group
   and exact case ids returned by the runner.
6. During migration, call `traffic-e2e-run run-api --api '<METHOD pattern>'`.
   Fix the focused API and rerun it until its complete group passes. Focused
   attempts persist evidence but MUST NOT update full-round counts,
   `e2e-progress.yaml`, verified excludes, or the global `latest`.
7. Compare JSON responses structurally; use exact bytes only for non-JSON or an
   explicit exact-byte mode. Treat recorder reports and summaries as dependency
   coverage evidence. Unmatched, case-owned unused, unsupported, unsafe, or
   missing required side effects keep the group incomplete. A source-verified
   API-independent process-level HTTP host may be added through recorder-config
   plan/apply during focused diagnosis; its unconsumed recorded exchanges remain
   explicit non-blocking diagnostics, while unmatched target calls remain
   dirty. The host applies to every case in the named recording rule and is not
   attributed to active APIs. Unused bootstrap traffic is retained as a
   non-blocking startup diagnostic because traffic observed before readiness is
   outside the selected E2E contract.
8. After every published case is grouped and every migrated API passes its
   focused loop, call `traffic-e2e-run run` for one full round. The runner MUST
   start replay once, load bootstrap and the exact full case set once, execute
   cases sequentially, finalize once, aggregate once, then run per-API
   verified-excludes ensure and publish progress. Do not modify target behavior
   during a full round. One successful full round with finalized, complete,
   clean evidence makes generated progress `status: complete`.
9. If a full round fails, diagnose the affected API, return to `run-api`, fix
   it, and restart the full round from the beginning.

If the same root cause repeats for three consecutive cycles without new
evidence or meaningful progress, stop as `blocked` or `incomplete`. The final
verification is mandatory and never counted as a retry.

During migration, upsert a concise repository lesson only after the fix passes
verification and the lesson applies across multiple APIs, cases, or migration
scopes. Repetition within one API, case, run, or otherwise narrow scenario does
not qualify.
Record only a recognizable trigger, the action not to repeat, and the verified
resolution. Update an existing lesson instead of duplicating it. Leave raw
replay evidence and generated state out of prose.

## Non-Negotiable Completion Gate

MUST NOT claim a selected case source passed or completed unless all applicable
items hold:

1. Every selected case occurs in exactly one canonical group with persisted
   `traffic-case-group ensure` evidence; no selected directory is unprocessed or
   overlapping, and published recordings are unchanged.
2. The final report records the canonical replay-policy path and fingerprint,
   `expected_response: assertions_only`, rule applicability, and zero unused
   applicable rules. Direct audit proves no expected-response or recorder
   dependency value flows into target behavior, dependency implementations,
   fixtures, branches, caches, or side effects.
3. Recorded E2E uses genuine target dependency clients. For intercepted replay,
   pre-request evidence proves the dependency-producing process runs as the
   fixed user returned by `traffic-replay --print-intercept-user`. No target
   facade or state selects an arbitrary UID, user, or all-user interception.
4. Every selected case ended cleanly and the final version-five recorder report
   contains the exact case ids, session id, `finalized: true`, and
   `finalized_at`. Pending, active, live, non-finalized, or dirty state is
   incomplete.
5. Every collection/run source, multi-case selection, or multi-session source
   has a persisted `traffic-replay-aggregate` report for the exact case and
   session ids with complete, clean coverage. Only one published case in one
   finalized session may use `not_applicable_single_case_single_session`.
6. When source repo and managed recorder config exist, the persisted
   case-path-pattern plan is either confirmed no-change or every safe diff is
   applied through recorder tooling and a final replan has no diff. Missing
   prerequisites use only the canonical explicit non-applicable reasons.
7. When managed verified excludes exist, the full round's API assertion view
   and clean aggregate view cover the exact group and recorder-owned ensure returns
   `applied`, `already_present`, or `below_threshold`, with its required apply
   and verification evidence.
8. The full-round state is terminal, `.active` was atomically published as
   `latest`, and the runner-generated `.migration/e2e-progress.yaml` reports
   `status: complete` from one successful full round with finalized, complete,
   clean evidence. Focused attempts are never accepted as full-round completion
   evidence.
9. Target scripts and AI-authored facades remain orchestration helpers. Their
   exit status, summaries, hand-maintained counts, or ledgers do not replace
   canonical grouping, replay, aggregate, pattern, or exclude artifacts.

Repository migration notes are prevention memory only. Their presence or
wording never substitutes for any completion artifact above.

If any item is missing, report `incomplete` or `blocked` with the exact missing
artifact or action. Never turn a planned diff, stale report, partial case list,
or zero exit code into completion evidence.

## Stop And Report

Do not invent rows, downstream responses, cache values, queue messages,
dependency params, or side effects. Stop when a valid published case, semantic
dependency evidence, clean replay, or supported policy operation is missing.
Never add a response ignore without explicit user authorization. Tie recorder
feedback to exact artifact evidence such as missing fields, parse warnings,
truncation, unsupported protocol behavior, or ambiguous correlation.

An unmatched or ambiguous source route blocks automatic grouping or pattern
feedback, not unrelated replay work, unless route association is required to
select the requested scope.

## Output

Use the replay status template only when this turn executes replay, hands off
partial replay work, or makes a completion claim. Start that output with exactly
`complete`, `incomplete`, or `blocked`, then report the exact case source and
ids, canonical groups, final session/report, aggregate coverage, policy audit,
pattern status, verified-exclude status, verification command, and blockers.

For analysis, review, directory-selection, or design questions that do not
execute replay or claim completion, answer normally without a synthetic replay
status. Never use success wording while an applicable gate is missing.
