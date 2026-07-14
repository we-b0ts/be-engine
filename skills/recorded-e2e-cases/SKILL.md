---
name: recorded-e2e-cases
description: Replay and diagnose E2E tests from traffic-recorder-proxy case, collection, or run directories, and maintain replay-time recorder feedback in the target repo. Use for recorded request/response artifacts, dependencies.jsonl dependency replay, aggregate replay reports, recorder.toml case_path_patterns, or case-driven failures requiring dependency evidence.
---

# Recorded E2E Cases

Treat a recorded case as an E2E recipe: the HTTP boundary and every case-owned
dependency touch form one compatibility contract.

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
   aggregate report, and stop the session. When one case source produces more
   than one replay report, read [aggregate-report.md](references/aggregate-report.md)
   and use `traffic-replay-aggregate` from `PATH`; never calculate totals
   manually or make the target project parse replay report internals.
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
   report, then use `apply`; never edit the TOML directly. Treat a focused or
   partial case source as add-only. Rebuild or delete patterns only from the
   target's declared authoritative case collection and pass `--allow-delete`
   only after reviewing the authoritative plan. If the command or managed
   block is unavailable, report feedback without changing the config.
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

Keep the final response short: selected case set and pass/fail state, aggregate
report path and published/reported/unreported coverage when applicable,
essential changes, verification command, missing evidence when blocked,
case-to-route and route-pattern feedback status, and concise evidence-backed
recorder feedback.
