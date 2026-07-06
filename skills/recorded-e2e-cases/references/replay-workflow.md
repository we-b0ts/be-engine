# Replay Workflow

Use this reference when turning a recorded case into a runnable E2E in another
project.

## Target Project Discovery

Inspect before editing:

- package/build files and existing test commands
- E2E or integration test directories
- app/server startup helpers used by tests
- fixture factories, database seed helpers, HTTP stubs, fake services, and mock
  adapters
- environment configuration for disabling external services

Use the project's existing E2E framework and mock style. If no framework exists,
add the smallest conventional test/mocking setup for that technology stack and
explain why. Do not introduce a broad new architecture just for one case.

## Replay Construction

Implement in this order:

1. Create or extend a test helper that can load one case from
   `recordings/<rule>/<uri-group>/<case-id>`. Older recordings may use
   `recordings/<rule>/<case-id>`.
2. Decode the recorded request body and prepare headers. Remove or override only
   headers that the target test harness cannot or should not set, such as
   hop-by-hop transport headers.
3. Build dependency mocks from `dependencies.jsonl`.
4. Start the app under test with real external dependencies isolated.
5. Send the recorded request or invoke the equivalent route.
6. Assert status and meaningful response body fields. Assert headers only when
   stable and relevant.

The replay is complete only when the request returns the expected response while
using dependency behavior reconstructed from the recorded dependency file.

Recorded dependencies are test evidence. Do not turn them into the app's normal
runtime data source unless the user explicitly asks for a replay-only tool. For
service rewrites, keep the production-like dependency boundary separate from the
recorded mock implementation.

## Dependency Mocking

Default to no real external network, DB, cache, queue, or third-party calls.
Use local test containers, embedded services, in-memory fakes, or stubs only when
the target project already treats them as test-isolated dependencies.

Before building mocks, classify each recorded dependency:

- `response-driving`: data directly needed to produce the expected response
- `auth/session`: data needed to establish request identity or context
- `required-side-effect`: calls the app must make but whose output does not
  shape the response, such as request logs or audit writes
- `unrelated/background`: process-wide, scheduled, lock, heartbeat, or other
  traffic captured near the request but not owned by the case

Mock response-driving and auth/session dependencies first. Represent required
side effects as narrow no-op or recorded-result mocks only when the app path
requires them. Do not fold unrelated/background dependencies into business
logic or runtime data models; note the evidence for ignoring them. If ownership
is ambiguous, treat it as recorder feedback rather than guessing.

For MySQL:

- Use `mysql_exchange` records as the primary mock source.
- Treat `response.columns` as query-level schema evidence. Use semantic fields
  such as `family`, `sql_type`, `unsigned`, `bits`, and `nullable`; do not
  infer language types from raw protocol flags or protocol type names.
- Match by normalized SQL and parsed `params`.
- Return resultset columns and rows for `response.status == "resultset"`.
- Return affected rows and last insert id for `response.status == "ok"`.
- Reproduce error code and message for `response.status == "error"`.
- Preserve dependency order when transactions, locks, repeated SQL, or session
  state matter.
- Treat missing SQL, missing params for prepared execution, missing semantic
  column schema, row truncation, and parse warnings as risk signals.

For non-MySQL dependencies:

- Apply the same evidence-first policy: identify the dependency call, expected
  input, recorded output, and ordering or state requirements.
- If semantic data is absent, inspect debug records or project logs only to
  explain what is missing.
- Do not synthesize Redis values, MQ messages, downstream HTTP payloads, or cache
  entries without recorded evidence or an existing target-project fixture that
  clearly supplies the same behavior.

## Assertion And Config Fallback

Prefer the target project's existing assertion configuration. If none exists and
the case needs configurable assertion behavior, create `.recorded-e2e.yaml` at
the target project root.

The fallback config is YAML, per case, and limited to assertion behavior plus
external dependency isolation. Use JSONPath selectors for response body ignore
paths. Keep it small; do not use it for broad test orchestration or mock data.

Minimum supported concepts:

- case key: `recordings/<rule>/<uri-group>/<case-id>`
- body assertion mode: semantic fields, exact body, or status-only
- ignored response JSONPaths
- ignored or asserted headers
- external dependency isolation flag

Never add ignore JSONPaths automatically. When a mismatch appears unstable,
suggest the JSONPath and wait for explicit user authorization before editing the
config.

## Run Loop

Use at most 3 iterations:

1. Run the focused single-case or nearest E2E command.
2. If it fails, classify the failure as missing/incomplete mock, incomplete
   recording, assertion drift, environment setup, or product code bug.
3. Fix mocks first when evidence exists.
4. Fix product code only when dependency replay is complete and the failure is a
   real behavior defect.
5. Re-run the focused command after each change.
6. Before finishing, note whether the mock/replay work exposed recorder data
   quality gaps, even if the case now passes.

After the focused case passes, run the broader relevant suite or project-standard
checks that are reasonable for the repository.

When dependency files contain both relevant business calls and unrelated
process-wide traffic, include a short working-note summary of which dependency
classes were used, no-oped, or ignored. Surface recorder feedback if better
dependency attribution, role tagging, or noise filtering would have reduced
manual triage.

## Final Response

On success, keep the final response short:

- pass/fail conclusion
- essential changes
- verification command
- concise recorder feedback when replay required guessing, debug-only data, or
  manual reconstruction that better recording could avoid

On blocked replay, include the missing evidence list and recommended next step,
such as re-recording with a dependency enabled or providing a fixture source.
