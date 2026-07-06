---
name: recorded-e2e-cases
description: Use when working with recorded traffic cases, E2E replay from recorded cases, case-driven E2E tests, request.json, expected-response.json or expected_response.json, dependencies.jsonl, dependencies-debug.jsonl, dependency replay, MySQL mysql_exchange records, generated dependency mocks, or cases where request/response alone is insufficient.
---

# Recorded E2E Cases

## Core Rule

Treat a recorded case as an E2E recipe, not just an HTTP fixture.

`request.json` and `expected-response.json` describe only the HTTP boundary.
Most non-trivial cases will not replay successfully unless dependencies from
`dependencies.jsonl` are recreated. Build the dependency layer first, then use
the HTTP files to drive and assert the E2E.

## Case Loading Workflow

1. Resolve the case directory.
   - If given a path, use it directly.
   - If given only a case id, search likely roots such as
     `recordings/<rule>/<case-id>/`.
2. Load these files first:
   - `request.json`
   - `expected-response.json`
   - `dependencies.jsonl`
3. Accept `expected_response.json` as a user spelling, but prefer the canonical
   file `expected-response.json`.
4. Load `dependencies-debug.jsonl` only when semantic dependency data is
   missing, has parse warnings, or protocol-level debugging is required.

If `dependencies.jsonl` is missing or empty for a case that clearly depends on
external systems, report the case as incomplete instead of trying to make the
HTTP pair pass by guessing data.

## Building The Replay

Use the host project's existing E2E framework, server startup path, and mock
style. Do not introduce a new framework unless the repo has none.

Map the case artifacts like this:

- `request.json`: inbound request method, path, query, headers, and body.
- `expected-response.json`: expected HTTP status, headers when relevant, and
  response body. Bodies may already be decoded from gzip/deflate.
- `dependencies.jsonl`: semantic dependency behavior required for the request
  to pass.
- `dependencies-debug.jsonl`: raw/protocol fallback for investigation.

The replay is complete only when the recorded request, or an equivalent route
invocation, returns the expected response while using the dependency behavior
from `dependencies.jsonl`.

## Dependency Replay

Prefer semantic dependency records over raw protocol payloads.

For MySQL, prefer `mysql_exchange` records:

- Match calls by normalized SQL plus parsed `params`.
- Normalize SQL by collapsing whitespace and preserving placeholders.
- Treat `statement_id` as connection-local context, not as a stable mock key.
- For `response.status == "resultset"`, return `response.columns` and
  `response.rows`.
- For `response.status == "ok"`, return `affected_rows` and
  `last_insert_id` when present.
- For `response.status == "error"`, reproduce `error_code` and
  `error_message`.
- Preserve ordering when transactions, locks, repeated SQL, or connection
  specific behavior matters.

Do not use `mysql_query` or `mysql_response.payload` as the primary mock source.
Those records belong in debug flows because raw/base64 protocol data is harder
to replay reliably than `mysql_exchange`.

## Incomplete Or Risky Cases

Before writing the final E2E, check for:

- Missing `dependencies.jsonl`.
- `mysql_exchange` records with missing SQL or missing params for prepared
  statement executions.
- Non-empty `parse_warnings`.
- Dependency calls present only in `dependencies-debug.jsonl`.
- Response mismatches that look like missing dependency state.

When these appear, state what is missing and use `dependencies-debug.jsonl` to
investigate. Do not silently invent rows, parameters, or downstream responses.

## Output Expectations

When creating or fixing an E2E from a case:

- Identify the case path and loaded files.
- Summarize the dependency records used, especially MySQL exchanges.
- Implement mocks from `dependencies.jsonl` before asserting the HTTP response.
- Assert the HTTP status and the meaningful response body fields from
  `expected-response.json`.
- Keep debug/raw protocol assertions out of the normal E2E unless they are the
  behavior under test.
