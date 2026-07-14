---
name: recorded-e2e-cases
description: Replay and diagnose E2E tests from traffic-recorder-proxy case, collection, or run directories, and maintain replay-time recorder feedback in the target repo. Use for recorded request/response artifacts, dependencies.jsonl dependency replay, aggregate replay reports, recorder.toml case_path_patterns, or case-driven failures requiring dependency evidence.
---

# Recorded E2E Cases

Treat a recorded case as an E2E recipe: the HTTP boundary and every case-owned
dependency touch form one compatibility contract.

## Mandatory Semantics

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Completion is
the conjunction of every applicable gate; one passing layer never compensates
for a missing layer. If the user narrows the task or a required tool/action is
unavailable, hand off the useful work but keep the result `incomplete` or
`blocked`. Never downgrade a missing gate to a warning.

Before replay, record the exact completion case source and selected published
case ids. A completion claim applies only to that set. MUST NOT claim that a
parent collection or run passed after replaying only a subset.

## Workflow

1. Resolve the supplied case, collection, or run directory. For collections,
   select every published case matching `request.json.uri`; ignore `failed`,
   `staging`, `.replay`, `.partial`, and `.truncated` artifacts. Preserve
   recordings exactly. Read [case-format.md](references/case-format.md) when
   parsing artifacts.
2. Load `request.json`, canonical `expected-response.json`,
   `dependencies.jsonl`, and `dependencies-summary.json` when present. Tolerate
   `expected_response.json` as user input without renaming it. Stop if a valid
   request or expected response is missing.
3. Inspect the target project's E2E runner, startup path, config, source repo
   reference, and dependency wiring. Reuse its conventions and isolate real
   dependencies only inside the recorded-E2E entrypoint. Require the selected
   case source as an explicit external input such as `--case-dir`; never
   hardcode or silently default to a developer-machine recording path.
4. When a source repo and target recorder config are available, read
   [route-pattern-feedback.md](references/route-pattern-feedback.md). During
   replay discovery, associate each case to a source API using method plus
   actual URI. Keep `traffic-replay` and recording artifacts read-only; apply
   confirmed feedback only through the target repo's explicit managed config.
5. Follow [replay-workflow.md](references/replay-workflow.md): use
   `traffic-replay` and `traffic-replay-cli` from `PATH`, wait for readiness,
   bracket every case with `begin` and `end --fail-on-dirty`, require a clean
   `finalize --fail-on-dirty --fail-on-incomplete` result, and retain its final
   session id and version-four report. Successful finalization means that exact
   report was atomically published before replay stopped; a write failure keeps
   the session open and is incomplete evidence.
   Read
   [aggregate-report.md](references/aggregate-report.md) and run
   `traffic-replay-aggregate` from `PATH` for every collection/run source,
   multi-case selection, or source replayed through multiple reports/sessions.
   Only one published case replayed in exactly one session/report can be marked
   `not_applicable_single_case_single_session`. Never calculate totals manually
   or make the target project parse replay report internals.
6. Build each request from its `request.json`; do not hardcode case-specific
   method, URI, headers, query, or body data. Compare JSON structurally and use
   exact bytes only for non-JSON or an explicitly configured exact-byte mode.
7. Treat `dependencies.jsonl` as the touch contract and its summary as the
   coverage checklist. Response compatibility alone is incomplete while replay
   has unexplained unmatched target calls, unused case exchanges, or missing
   required side effects. Recorded metrics are behavior. If evidence requires
   replay exceptions or background/noise classification, keep that policy in
   one source-controlled target file consumed by every orchestration and test
   layer; never duplicate case-id or dependency-signature allowlists in shell
   and target-language code.
8. Keep recorded params in replay evidence or E2E-only config. Normal runtime
   must derive dynamic values from request/session context, time, generated ids,
   dependency state, or explicit product config.
9. After replay, update a source-controlled target `recorder.toml` only when it
   has an explicit AI-managed `case_path_patterns` block. Use
   `traffic-recorder-config case-path-patterns plan`, inspect its diff and JSON
   report even when zero patterns or no diff are expected, then use `apply` for
   every confirmed safe diff; never edit the TOML directly. Treat a focused or
   partial case source as add-only. Rebuild or delete patterns only from the
   target's declared authoritative case collection and pass `--allow-delete`
   only after reviewing the authoritative plan. If the command or managed
   block is unavailable, report the exact prerequisite without changing or
   creating the config or managed block.
10. Run the focused case set first, then relevant project checks. Iterate at
   most three times and modify product code only after replay evidence and
   routing are complete and the failure is a real behavior defect.

For MySQL, match semantic `mysql_exchange` records by business target host,
port, database/schema, and username/role before SQL and params. Use semantic
column schema for target types. Load `dependencies-debug.jsonl` only to explain
missing semantic data or protocol failures.

For Kafka, use semantic `kafka_produce` and `kafka_delivery` records. V1 uses a
PLAINTEXT, uncompressed, non-idempotent, `acks=1` client profile and a one-broker,
one-partition replay facade. Match exact topic, key, headers, and value bytes;
require every expected produce and delivery to be consumed. Treat transactions,
Admin APIs, compression, authentication, unsupported API versions, unsafe
captures, and Kafka proxy errors as incomplete evidence rather than inventing
broker behavior.

## Non-Negotiable Completion Gate

MUST NOT report a selected case source as passed, complete, or delivered unless
all applicable items below are evidenced by canonical tools and artifacts from
the final state:

1. End every selected case, run the final replay report with
   `traffic-replay-cli finalize --fail-on-dirty --fail-on-incomplete`, and
   require its version-four report to contain the exact selected case ids,
   final session id, `finalized: true`, and `finalized_at`. A stale active case,
   pending case, live session, or non-finalized report is incomplete evidence.
2. For every collection/run source, multi-case selection, or source with more
   than one replay report/session, run `traffic-replay-aggregate` with
   exact repeated `--case-id` and `--session-id` values plus
   `--fail-on-incomplete --fail-on-dirty`. Require a persisted aggregate report
   for the exact completion case source with all selected published cases
   reported, no in-scope unreported cases, every reported case ended,
   `complete: true`, and no dirty evidence. The only allowed aggregate
   exemption is `not_applicable_single_case_single_session`, backed by one
   published case and one finalized session/report. Never substitute
   hand-maintained totals, target-runner output, or migration-ledger counts.
3. When a source repo and a target recorder config with an explicit AI-managed
   `case_path_patterns` block are available, always run
   `traffic-recorder-config case-path-patterns plan`, even when no pattern or
   change is expected. Persist and inspect its JSON report. Record `applied`
   only after applying every confirmed safe diff, persisting the apply report,
   and rerunning `plan` to prove the final config has no diff. Record
   `confirmed_no_change` only when the initial plan has no diff; a focused plan
   with no candidate patterns MUST report `no_candidates: true`. The only
   allowed non-applicable reasons are
   `not_applicable_missing_source_repo` and
   `not_applicable_missing_managed_config`; state the missing input explicitly.
   A missing command when all inputs exist is `blocked`, not non-applicable.
   `path_prefixes` controls capture scope;
   `case_path_patterns` controls case grouping, so broad capture is not evidence
   that grouping feedback is unnecessary. Apply a confirmed diff only through
   the managed command and keep focused case sources add-only.
4. Treat target-project scripts and command facades as orchestration helpers,
   not independent proof that this gate passed. MUST verify replay lifecycle,
   aggregate coverage, and route-pattern outcome from recorder-owned CLI output
   and artifacts. MUST NOT patch a target facade merely to manufacture or
   self-report completion evidence.

The following never satisfy this gate: a zero exit code from an AI-authored
facade, manually summed case counts, a stale report from before the final
change, `path_prefixes`, a planned-but-unapplied safe pattern diff, or a ledger
entry without its referenced canonical artifact.

If any applicable item is missing, report the result as `incomplete` or
`blocked` with the missing artifact or action. Do not use success wording.

## Stop And Report

Read [failure-diagnosis.md](references/failure-diagnosis.md) after the first
failed replay. Do not invent dependency rows, downstream responses, queue or
cache data, or params. Stop when evidence is incomplete, replay is dirty, or a
valid published case is unavailable; report the exact missing evidence and the
re-recording or data-supply step.

Never add response ignores without explicit user authorization. Suggest a
specific JSONPath only after replay proves the mismatch is an unstable field.
Report recorder improvements only when artifact evidence shows missing semantic
capture, poor correlation, truncation, or another recorder/replay gap.
Unmatched or ambiguous source routes block automatic pattern generation, not
dependency replay itself, unless route association is required to select the
requested API scope.

## Output

Start the final response with exactly one state: `complete`, `incomplete`, or
`blocked`. Then keep it short: exact completion case source and selected case
ids, final replay report and session ids, aggregate status/path and coverage,
case-path-pattern plan status/path, essential changes, verification command,
missing evidence, case-to-route status, and concise evidence-backed recorder
feedback. MUST NOT use success wording when any applicable gate is missing.
