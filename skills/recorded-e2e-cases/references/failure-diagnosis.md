# Failure Diagnosis

Use this reference when a recorded E2E does not pass after the first replay
attempt.

## Classification Order

Classify failures in this order:

1. Incomplete recording
2. Missing or incorrect dependency mock
3. Environment or app startup mismatch
4. Assertion drift in unstable response fields
5. Product code bug

Prefer dependency and environment explanations until the recorded dependency
evidence is complete and the mocks are known to be hit.

## Incomplete Recording Signals

Stop and report a missing-dependency list when any required behavior lacks
evidence:

- `dependencies.jsonl` is missing or empty for a request that clearly uses
  external services
- dependency calls appear only in `dependencies-debug.jsonl`
- a dependency error was recorded instead of a semantic response
- downstream data is needed but no semantic record or trusted project fixture
  supplies it
- the recorded HTTP response depends on data that cannot be explained by the
  recorded dependencies

Do not infer missing rows, messages, cache entries, or third-party responses
from `expected-response.json` alone.

## Mock Failure Signals

Fix mocks before product code when:

- the app calls a dependency but no mock handles it
- SQL differs only by formatting, placeholder style, or harmless whitespace
- prepared statement params are parsed but the mock ignores them
- dependency ordering matters and the mock is stateless
- the mock returns a generic empty value but the recorded dependency returned
  concrete rows, affected rows, ids, errors, or messages
- the app attempts a real external connection during the replay

Record enough evidence in the working notes to know which dependency matched,
missed, or leaked to the network.

## MySQL-Specific Risks

Treat these as replay risks:

- missing `sql`
- `COM_STMT_EXECUTE` without parsed `params`
- resultsets without semantic `response.columns` schema fields such as
  `family`, `sql_type`, `nullable`, or numeric signedness
- non-empty `parse_warnings`
- `response.rows_truncated == true`
- use of `statement_id` as a global key
- transaction, lock, temp table, session variable, or repeated SQL behavior
  mocked without ordering or connection state
- `mysql_tls_rejected`, because MySQL TLS MITM is intentionally unsupported

Use `dependencies-debug.jsonl` to explain parser gaps, not as the primary mock
source. Raw/base64 payloads are less reliable than semantic `mysql_exchange`
records.

## Assertion Drift

Only classify a mismatch as assertion drift when dependency mocks were used and
the business behavior matches.

For JSON responses, diagnose against parsed JSON values. Formatting, whitespace,
and object key order are not assertion failures. Missing fields, extra fields,
`null` versus `""`, wrong scalar types, and unexpected array order are assertion
failures unless explicitly configured otherwise.

Common unstable fields:

- timestamps and durations
- trace ids, request ids, correlation ids, span ids
- random tokens or nonce values
- generated ids when the exact id is not business-relevant
- ordering in arrays that the product contract treats as unordered

Suggest JSONPath ignore entries for unstable body fields, but do not edit
`.recorded-e2e.yaml` without explicit user authorization. Prefer asserting
stable semantic fields over broad ignores.

## Product Code Bugs

Modify product code only when:

- dependency evidence is complete
- mocks are hit and return the recorded behavior
- the request is driven equivalently to the recording
- the remaining mismatch is a real behavior difference, not an unstable field
  or missing environment setup

Keep product fixes minimal and re-run the focused recorded E2E immediately.

## Recorder Feedback

After any replay attempt, decide whether the recorder should be improved. Do
this even when the E2E eventually passes.

Report recorder feedback when replay required:

- guessing dependency behavior from HTTP response shape
- reading `dependencies-debug.jsonl` because `dependencies.jsonl` lacked usable
  semantic data
- manually reconstructing a dependency input, output, ordering rule, cache
  state, queue message, or downstream HTTP response
- ignoring or working around missing SQL, missing prepared params, parse
  warnings, row truncation, or missing response metadata
- relying on raw MySQL protocol type names, type codes, or flags from debug data
  because `dependencies.jsonl` lacked decoded column schema
- relying on broad `active_window` matching where dependency ownership was
  ambiguous
- filtering substantial unrelated process-wide traffic, such as request-log
  writes, scheduler queries, locks, heartbeats, or background jobs, before the
  case-owned dependencies were clear
- adding large amounts of target-project fixture data that should have been
  captured as semantic dependency output
- identifying unstable response fields that the recorder could tag or summarize
  for later assertion configuration

Do not propose recorder changes just because the target project's test framework
was awkward. Tie feedback to recorded artifact evidence: file name, event type,
missing field, warning, or the exact manual reconstruction that was needed.

Phrase feedback as a small upstream improvement note, not as target-project
work. Examples of useful feedback categories are: add semantic capture for a
dependency type, enrich `mysql_exchange`, improve case dependency correlation,
avoid truncating needed values, or surface unstable response fields.

## Blocked Output

When blocked, output:

- case path
- missing evidence or incomplete dependency records
- why it is unsafe to invent the data
- recommended next step, such as re-recording with the missing service captured
  or supplying a trusted fixture
- recorder feedback, when the missing evidence suggests a recorder improvement
