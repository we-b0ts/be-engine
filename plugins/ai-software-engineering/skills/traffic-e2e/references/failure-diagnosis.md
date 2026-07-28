# Traffic E2E Failure Diagnosis

Use this reference when a recorded E2E does not pass after the first replay
attempt.

## Contents

- Diagnosis order
- Missing response-driving external evidence
- Replay failure signals
- MySQL-specific risks
- Response assertion mismatches
- Target behavior evidence
- Recorder feedback
- Blocked output

## Diagnosis Order

Diagnose a non-passing run in this order:

1. Structured response assertion result, including selected, executed,
   passing, and mismatching case counts
2. Response-driving target behavior, dependency, environment, app startup, or
   process-state mismatch
3. Missing response-driving external-system evidence, but only after causal
   diagnosis proves that its absence prevents target implementation
4. Assertion drift in source-proven unstable response fields
5. Remaining dependency coverage, side-effect, and background-attribution
   failures after response assertions pass

The response contract is the primary diagnostic output during migration.
Inspect and report every response mismatch before applying background
attribution. Dependency analysis belongs in that diagnosis when a dependency
can explain the observed response difference; unrelated unused traffic does not
preempt a target response finding. Preserve all independently evidenced failure
categories so that a system blocker cannot hide response defects.

## Missing Response-Driving External Evidence

Classify a recording-data blocker only after one representative
response-mismatching case proves all of the following:

- the relevant source response path and process-local state have been
  inspected;
- source code, configuration, target behavior, and runtime wiring do not
  explain or repair the difference;
- the response requires a specific external value or semantic exchange;
- that response-driving evidence is absent or internally inconsistent in the
  recording and available authorized runtime evidence; and
- completing the response would require inventing external-system behavior.

Signals that require this investigation include:

- response-driving dependency calls are absent from `dependencies.jsonl` or
  appear only in `dependencies-debug.jsonl`;
- a response-driving dependency error was recorded instead of its semantic
  response;
- `dependencies-summary.json` identifies a response-driving, auth/session, or
  required side-effect dependency that replay cannot reproduce;
- required prepared parameters, rows, messages, metadata, or ordering are
  absent or internally inconsistent; or
- the recorded HTTP response depends on an external value that the recorded
  semantic dependencies and available runtime evidence cannot explain.

None of these signals alone proves `blocked`. An empty `dependencies.jsonl`,
unused exchanges, unmatched target calls, or dirty dependency coverage can
exist without preventing response implementation. Continue response diagnosis
unless the causal proof above is complete.

Do not infer missing rows, messages, cache entries, or third-party responses
from `expected-response.json` alone.

Process-local cache behavior belongs to target implementation. Its absence from
recorded dependencies is not a recording-data blocker. If source-owned
scheduled dependency calls populate that cache, inspect their exact ownership,
resource, command, key derivation, bounds, and refresh behavior. When the
recorded calls are mixed into cases and their responses are required to build
the target cache, classify them as `runtime_state` and follow
[background-dependencies.md](background-dependencies.md) during response
repair.

For every unused case HTTP exchange, group observations by normalized
authority, method, and path only for diagnosis, then inspect the source that
initiates the request. Classify the narrow request family as background only
when all of these facts are explicit in source:

- startup, lifecycle, scheduler, or permanent-worker code owns the trigger;
- request context, API parameters, and API-scoped state do not control it;
- the selected API does not await, start, stop, or consume its result;
- the selected API response and required side effects do not depend on it.

Timing overlap, repetition, polling-like names, a successful response, and an
unused replay exchange are not ownership evidence. If any ownership fact is
unclear, keep the dependency case-owned and the replay incomplete.

After source proves HTTP independence and response assertions pass, follow
[background-dependencies.md](background-dependencies.md) and use the guarded
`background-dependencies plan` command. Inspect its narrow selector and matched
case IDs before `apply`, then create a new recording; the command cannot repair
the immutable old case. Record the source revision and a single-line
file/symbol explanation, never raw query values, credentials, headers, or
bodies. Use host-wide `allowed_unused_http_hosts` only as a compatibility
exception when an older recording cannot be replaced and source proves the
entire host is unrelated.

## Replay Failure Signals

Treat replay setup as part of the current response repair when it can explain
the structured difference. If the response already passes, retain the same
signals for the later dependency-coverage gate:

- the app calls a dependency but replay does not handle it
- the replay dependency coverage summary misses a recorded response-driving,
  auth/session, or required side-effect dependency
- the HTTP response passes but recorded case dependencies remain unused
- SQL differs only by formatting, placeholder style, or harmless whitespace
- prepared statement params are parsed but replay ignores them
- dependency ordering matters and replay lacks connection/session state
- replay returns a generic empty value but the recorded dependency returned
  concrete rows, affected rows, ids, errors, or messages
- the app attempts a real external connection during the replay
- the app only matches replay because normal runtime config contains recorded
  params such as fixed ids, timestamps, request ids, or table suffixes

Record enough evidence in the working notes to know which dependency matched,
missed, or leaked to the network.

## MySQL-Specific Risks

Treat these as replay risks:

- missing `sql` for a SQL-bearing command such as `COM_QUERY`,
  `COM_STMT_PREPARE`, or `COM_STMT_EXECUTE`
- missing MySQL dependency identity fields: business `target_host`,
  `target_port`, default `database`/schema, or `username`
- use of fake IPs or upstream IPs instead of the business/original target host
  for replay matching
- `COM_STMT_EXECUTE` without parsed `params`
- resultsets without semantic `response.columns` schema fields such as
  `family`, `sql_type`, `nullable`, or numeric signedness
- non-empty `parse_warnings`
- `response.rows_truncated == true`
- use of `statement_id` as a global key
- transaction, lock, temp table, session variable, or repeated SQL behavior
  replayed without ordering or connection state
- `mysql_tls_rejected`, because MySQL TLS MITM is intentionally unsupported

Use `dependencies-debug.jsonl` to explain parser gaps, not as the primary replay
source. Raw/base64 payloads are less reliable than semantic `mysql_exchange`
records.

## Response Assertion Mismatches

Inspect every structured response difference and compare source and target
behavior before changing assertion policy or applying background attribution.
Classify target code, response-driving dependency wiring, or response
construction that violates the source contract as `target_behavior`, and return
the structured difference and causal evidence to the calling orchestrator.
After the caller repairs it, rerun the same immutable cases. Only consider a
replay-policy strategy when the dependencies causal to that difference replay
correctly and source evidence proves the remaining difference is intentional.
Unrelated unused dependencies remain a later E2E gate; they do not suppress
this response finding.

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

Identify the exact JSON Pointer for a runtime-varying body field. Check whether
the current replay-policy version supports a narrowly scoped strategy and use
its plan/apply operation. A scalar mismatch or generated diagnostic candidate
does not by itself justify a policy change. If no supported strategy exists,
keep the case incomplete. Never add a broad ignore or weaken stable fields.

## Target Behavior Evidence

Classify a difference as `target_behavior` when:

- the request is driven equivalently to the recording
- the structured response difference is a real behavior difference, not an
  unstable field or missing environment setup
- every dependency that can causally explain that difference is replayed
  correctly, repaired as part of the response-driving wiring, or proven
  unrelated to the response

Do not require unrelated unused or source-proven background exchanges to be
clean before reporting this classification. Keep them recorded as separate
failures, and do not declare E2E complete until the later dependency-coverage
gate passes. If a missing or incorrect dependency can explain the response
mismatch, classify that causal path instead of prescribing a response-only
change.

## Recorder Feedback

After any replay attempt, decide whether the recorder should be improved. Do
this even when the E2E eventually passes.

Report recorder feedback when replay required:

- guessing dependency behavior from HTTP response shape
- reading `dependencies-debug.jsonl` because `dependencies.jsonl` lacked usable
  semantic data
- manually reconstructing a dependency input, output, ordering rule, queue
  message, or downstream HTTP response
- ignoring or working around missing SQL, missing prepared params, parse
  warnings, row truncation, or missing response metadata
- relying on raw MySQL protocol type names, type codes, or flags from debug data
  because `dependencies.jsonl` lacked decoded column schema
- relying on broad `active_window` matching where dependency ownership was
  ambiguous
- filtering substantial unrelated process-wide traffic, such as request-log
  writes, scheduler queries, locks, heartbeats, or background jobs, before the
  case-owned dependencies were clear
- discovering that a case dependency was intentionally replaced or dropped by
  a software change and therefore needs user-approved contract-change tracking
- discovering that a recorded dependency touch has no clear ownership in the
  selected request path and would require hardcoded recorded params to replay
- attempting to add target-project fixture data that should instead be
  recorder-owned semantic dependency output
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

- exactly one representative case path
- missing evidence or incomplete dependency records
- why it is unsafe to invent the data
- recommended next step, such as re-recording with the missing service captured
  or adding recorder-supported semantic capture for that dependency
- recorder feedback, when the missing evidence suggests a recorder improvement

Use `incomplete` only when all selected response assertions pass, dirty
dependency evidence remains, and source inspection proves no safe rule to
apply. Dirty evidence never stops diagnosis or repair of a response mismatch.
