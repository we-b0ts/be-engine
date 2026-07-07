# Replay Workflow

Use this reference when turning a recorded case into a runnable E2E in another
project.

## Target Project Discovery

Inspect before editing:

- package/build files and existing test commands
- E2E or integration test directories
- app/server startup helpers used by tests
- runtime config, dependency wiring, and environment variables used by tests
- places where database, HTTP, cache, queue, or other external dependency
  endpoints can be pointed at replay listeners
- environment configuration for disabling or isolating real external services

Use the project's existing E2E framework and startup style. If no framework
exists, add the smallest conventional E2E setup for that technology stack and
explain why. Do not introduce a broad new architecture just for one case.

## Managed Replay Helper

This skill bundles a replay helper and config template:

- `scripts/replay.sh`
- `assets/replay.example.toml`

Before running the target E2E, set `TRAFFIC_RECORDER_PROXY_BIN` to an executable
`traffic-recorder-proxy` binary. The helper also checks common local candidates
and `PATH`, but the environment variable is the explicit, portable interface.

```bash
TRAFFIC_RECORDER_PROXY_BIN=/path/to/traffic-recorder-proxy \
  /path/to/recorded-e2e-cases/scripts/replay.sh path/to/replay.toml
```

Use the template as the starting config. Relative `case` and `report` paths are
resolved from the config file directory. Use `--no-intercept` only when the
target project already routes dependencies to the replay listeners.

## Replay Construction

Implement in this order:

1. Create or extend a test helper that can load one case from
   `recordings/<rule>/<uri-group>/<case-id>`. Older recordings may use
   `recordings/<rule>/<case-id>`. If the user supplied a collection directory
   such as `recordings/<rule>/<uri-group>`, inspect each child case's
   `request.json.uri` and select the case that matches the requested API path.
   If zero or multiple cases match, report the candidates and ask the user to
   choose.
2. Decode the recorded request body and prepare headers. Remove or override only
   headers that the target test harness cannot or should not set, such as
   hop-by-hop transport headers.
3. Start managed dependency replay with `scripts/replay.sh`, using
   `dependencies.jsonl` from the selected case and bootstrap dependencies
   discovered above the case directory. The canonical bootstrap file is
   `recordings/bootstrap-dependencies.jsonl`.
4. Point the app under test at the replay listeners and keep real external
   dependencies isolated.
5. Use `dependencies-summary.json`, when present, as the dependency coverage
   checklist for replay.
6. Send the recorded request or invoke the equivalent route.
7. Assert status and response body compatibility. Assert headers only when
   stable and relevant.

The replay is complete only when the request returns the expected response while
using dependency behavior replayed from the recorded dependency file, and the
dependency coverage summary is matched or explicitly explained.

For JSON responses, compare parsed JSON values, not serialized bytes. Object
key order and pretty formatting do not matter. Field presence and value type do
matter: missing, `null`, and `""` are all different. Arrays are ordered unless
the product contract or explicit assertion config marks them unordered. Use
byte-level body comparison only for non-JSON bodies or explicit exact-byte
assertion mode.

Recorded dependencies are replay evidence. Do not turn them into the app's
normal runtime data source. For service rewrites, keep the production-like
dependency boundary real and point only the E2E environment at replay listeners.

## Dependency Replay

Default to no real external network, DB, cache, queue, or third-party calls.
Use traffic-recorder-proxy replay as the dependency boundary. If a required
dependency type cannot be replayed from recorded evidence, stop with recorder
feedback instead of hand-writing substitute mock data.

Before relying on replay results, classify each recorded dependency:

- `response-driving`: data directly needed to produce the expected response
- `auth/session`: data needed to establish request identity or context
- `required-side-effect`: calls the app must make but whose output does not
  shape the response, such as request logs or audit writes
- `unrelated/background`: process-wide, scheduled, lock, heartbeat, or other
  traffic captured near the request but not owned by the case

Replay response-driving and auth/session dependencies first. Required side
effects must be replayed or explicitly explained when the app path requires
them. Do not fold unrelated/background dependencies into business logic or
runtime data models; note the evidence for ignoring them. If ownership is
ambiguous, treat it as recorder feedback rather than guessing.

For MySQL:

- Use `mysql_exchange` records as the primary replay source.
- Do not require successful `COM_STMT_PREPARE` exchanges for replay; they are
  protocol setup and belong in debug data. Preserve prepare failures because
  they are observed dependency failures or side effects.
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

## Dependency Coverage

Use `dependencies-summary.json` as an acceptance checklist when the case has
one. A target replay should produce a matching replay summary or equivalent test
evidence for:

- response-driving dependency calls
- auth/session dependency calls
- required side effects, including recorded dependency failures that the source
  behavior tolerated
- protocol, CRUD operation, table/host/topic/key-pattern, response status, row
  count, affected rows, and error code/message where applicable

Do not fail the E2E solely because unrelated/background traffic from the
recorded summary was not replayed. Instead, document why it is not case-owned.
If the summary shows a dependency category that the target test never exercises
and it is not safe to classify it as unrelated, treat the replay as incomplete.

For non-MySQL dependencies:

- Apply the same evidence-first policy: identify the dependency call, expected
  input, recorded output, and ordering or state requirements.
- If semantic data is absent, inspect debug records or project logs only to
  explain what is missing.
- Do not synthesize Redis values, MQ messages, downstream HTTP payloads, or
  cache entries. Treat missing semantic replay support as recorder/replay
  feedback.

## Assertion And Config Fallback

Prefer the target project's existing assertion configuration. If none exists and
the case needs configurable assertion behavior, create `.recorded-e2e.yaml` at
the target project root.

The fallback config is YAML, per case, and limited to assertion behavior plus
external dependency isolation. Use JSONPath selectors for response body ignore
paths. Keep it small; do not use it for broad test orchestration or dependency
payload data.

Minimum supported concepts:

- case key: `recordings/<rule>/<uri-group>/<case-id>`
- optional case collection key: `recordings/<rule>/<uri-group>` plus a selected
  case id after matching `request.json.uri`
- body assertion mode: strict JSON, exact bytes, semantic fields, or status-only
- ignored response JSONPaths
- ignored or asserted headers
- external dependency isolation flag

Never add ignore JSONPaths automatically. When a mismatch appears unstable,
suggest the JSONPath and wait for explicit user authorization before editing the
config.

## Run Loop

Use at most 3 iterations:

1. Run the focused single-case or nearest E2E command.
2. If it fails, classify the failure as incomplete recording, replay routing
   miss, unsupported replay behavior, assertion drift, environment setup, or
   product code bug.
3. Fix replay config, target dependency routing, or recorder/replay evidence
   first.
4. Fix product code only when dependency replay is complete and the failure is a
   real behavior defect.
5. Re-run the focused command after each change.
6. Before finishing, note whether replay exposed recorder data quality gaps,
   even if the case now passes.

After the focused case passes, run the broader relevant suite or project-standard
checks that are reasonable for the repository.

When dependency files contain both relevant business calls and unrelated
process-wide traffic, include a short working-note summary of which dependency
classes were replayed, explained, or ignored. Surface recorder feedback if
better dependency attribution, role tagging, or noise filtering would have
reduced manual triage.

## Final Response

On success, keep the final response short:

- pass/fail conclusion
- essential changes
- verification command
- concise recorder feedback when replay required guessing, debug-only data, or
  manual reconstruction that better recording could avoid

On blocked replay, include the missing evidence list and recommended next step,
such as re-recording with a dependency enabled or providing a fixture source.
