---
name: recorded-e2e-cases
description: Replay and fix E2E tests from recorded traffic case directories or case collections under recordings/rule/uri-group. Use when working with request.json, expected-response.json or expected_response.json, dependencies.jsonl, dependencies-debug.jsonl, traffic-recorder-proxy dependency replay, MySQL mysql_exchange records, case-driven E2E tests, or failures where the HTTP request/response pair is insufficient without recorded dependencies.
---

# Recorded E2E Cases

Treat a recorded case as an E2E recipe, not just an HTTP fixture.

## Workflow

1. Resolve the case under `recordings/<rule>/<uri-group>/<case-id>` unless the
   user explicitly gives a different case path. Older recordings may use
   `recordings/<rule>/<case-id>`. A user path may also point at a case
   collection such as `recordings/<rule>/<uri-group>`; scan child case
   directories and select matching case sets by `request.json.uri`, not by
   directory name alone. Ignore `recordings/_runs`; it contains recorder run
   diagnostics and failed cases, not replay fixtures. Preserve recorded files
   exactly.
2. Load `request.json`, canonical `expected-response.json`,
   `dependencies.jsonl`, and `dependencies-summary.json` when present. Accept
   `expected_response.json` as a user spelling but do not rename or rewrite it.
   If a supplied directory only has `.truncated` or `.partial` files, stop and
   report that the case was not published as a valid recording.
   Read
   [case-format.md](references/case-format.md) when parsing fields.
3. Inspect the target project's existing E2E runner, server startup path,
   runtime config, and dependency wiring before adding anything. Prefer existing
   conventions.
4. Start managed dependency replay before asserting the HTTP response. Use
   `traffic-replay <case-or-collection-dir>` to start one replay session and
   `traffic-replay-cli` to control case lifecycle. Ensure
   `traffic-replay-cli`, `traffic-replay`, and `traffic-recorder-proxy` are on
   `PATH`; do not reference this skill's filesystem path from target-project
   tests. Wait for replay readiness before sending requests. For a case set,
   call `traffic-replay-cli begin <case-id>` before each recorded request and
   `traffic-replay-cli end <case-id> --fail-on-dirty` after assertions; finish
   with a clean aggregate report and stop the replay session. Replay defaults
   to owner filtering for the `trp-record` Unix user. Target-project E2E
   commands should pass no user-filter argument by default and should run the
   target process as `trp-record`. Use an exact `--owner-uid` only when the
   harness cannot run as that user and record why. Do not put `--all-users` in
   target-project tests, command facades, docs, or migration state; it is only
   for manual troubleshooting on an isolated machine. Do not hand-write
   substitute dependency mocks when replay data or relay behavior is missing;
   report recorder/replay improvements instead.
5. Build each test request from that case's `request.json`. Use recorded
   `method`, `uri`, headers, and body as the source of truth. Do not hardcode
   auth headers, query strings, bodies, or other case-specific request data in
   the target test. Remove or override only transport headers the target harness
   cannot set safely.
6. Drive the recorded request, or the closest equivalent route invocation, and
   compare it with `expected-response.json`. For JSON responses, compare parsed
   JSON structurally: object key order is irrelevant, but field presence, value
   type, `null`, empty string, and missing field must match exactly.
7. Treat `dependencies.jsonl` as the case-level dependency touch contract. Use
   `dependencies-summary.json` as the coverage checklist when it exists.
   Response compatibility alone is not success. All case-owned dependency
   touches, including auth/session calls and required side effects, must be
   replay-matched with the same dependency identity. For MySQL, identity
   includes the business target host, target port, database/schema, and
   username/role before SQL and params are compared. Unmatched or unused case
   dependencies block success unless the user explicitly approves a behavior
   change or the evidence proves a recording-correlation issue that should be
   reported upstream. Do not copy recorded dependency params into normal
   runtime config or product logic just to satisfy coverage.
8. Run a focused single-case or selected case-set E2E command first. After it
   passes, run the broader relevant suite or project-standard checks.
9. Iterate at most 3 times. Fix replay command options, target dependency
   routing, or recorder/replay evidence first. Modify product code only when
   dependency replay is complete and the failure clearly points to a real code
   bug.
10. After success, failure, or partial progress, review whether the replay pain
   indicates recorder improvement opportunities. Do not change the recorder from
   the target project; report evidence-backed feedback.

Read [replay-workflow.md](references/replay-workflow.md) for target-project
discovery, managed dependency replay, replay loops, and the fallback
`.recorded-e2e.yaml` configuration interface.

## Failure Rules

- Do not invent dependency rows, downstream responses, queue messages, cache
  entries, or parameters when recording evidence is missing.
- Load `dependencies-debug.jsonl` only when semantic dependency data is missing,
  incomplete, has parse warnings, or protocol-level debugging is required.
- If the case cannot be replayed because recording evidence is incomplete,
  stop and output a concise missing-dependency list with recommended
  re-recording or data-supply steps.
- Do not mark a case as passed while replay output has unexplained unmatched
  target calls or unused case dependency exchanges. Dynamic values such as
  timestamps, request ids, UUIDs, durations, or generated ids may be normalized,
  but the dependency touch itself must still be exercised.
- Recorded params are evidence, not defaults. Keep fixed recorded values in
  E2E replay config only; normal runtime must derive values from request input,
  system time, generated ids, database state, or explicit product config.
- If the HTTP assertion differs only in unstable fields, suggest JSONPath ignore
  entries but do not add them unless the user explicitly authorizes it.
- Use byte-level body comparison only for non-JSON bodies or when the user or
  project config explicitly requests exact bytes.

Read [failure-diagnosis.md](references/failure-diagnosis.md) for protocol-neutral
triage, MySQL-specific risk signals, and recorder feedback signals.

## Output

On success, keep the final response short: state whether the selected recorded
case set passes, what changed, and the essential verification command. On a
blocked case, include the missing evidence list. If recorder improvements are
indicated, include only the concise evidence-backed feedback. Avoid long reports
unless the user asks.
