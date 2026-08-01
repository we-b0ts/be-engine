# Traffic E2E Failure Diagnosis

Use this reference when a recorded E2E does not pass after the first replay
attempt.

## Contents

- Diagnosis order
- Missing response-driving external evidence
- Replay failure signals
- Vintage node aliases
- Response assertion mismatches
- Target behavior evidence
- Recorder feedback
- Dirty dependencies
- Non-passing handoff

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

For managed `run-api` and `run` results, use `gates.responses`, then
`gates.replay`, then `gates.dependencies` as the dispatch evidence. A dependency
gate of `unknown` means replay evidence is incomplete; do not treat it as dirty
dependency evidence.

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

When a response-driving dependency appears absent, first resolve its exact
source hostname. Trace the response assignment through process-local state,
the backend call, framework wiring, configuration key, and effective runtime
configuration. Search pinned dependency repositories; when implementation is
packaged, identify and inspect or decompile the exact artifact and class or
symbol. If static files stop at a placeholder, inspect the ready source
runtime. It is permitted to restart or recreate the source container through
its authoritative entrypoint when startup is required to materialize that
configuration; preserve its image and startup contract and inspect it
read-only.

Search the resolved hostname or logical resource in the Recorder-configured
Breeze snapshot. A descriptor match proves that Recorder bypassed the resource;
it is not evidence that source behavior or source code is missing. Follow the
resource-capture procedure in [recording.md](recording.md). A changed apply is
`recording_configuration/action_required` and requires a new standard
recording; verify the expected semantic exchange in that new run. An unchanged
plan returns to recording-path diagnosis. Do not maintain endpoint ports or
hostname lists manually, and do not use traffic from a diagnostic container
restart as recording evidence.

Do not infer missing rows, messages, cache entries, or third-party responses
from `expected-response.json` alone.

Process-local cache behavior belongs to target implementation. Its absence from
recorded dependencies is not a recording-data blocker. If source-owned
scheduled dependency calls populate that cache, inspect their exact ownership,
resource, command, key derivation, bounds, and refresh behavior. When the
recorded calls are mixed into cases and their responses are required to build
the target cache, classify them as `runtime_state` and follow
[background-dependencies.md](background-dependencies.md) during response
repair. Whether the mismatch comes from a cache hit, miss, stale entry,
different refresh timing, incomplete warmup, or a missing target cache,
never classify the response field as intentional nondeterminism and never
apply a dynamic response rule.

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

## Vintage Node Aliases

Treat `vintage-node-<ipv4-with-dashes>.trp.test` as a Recorder-generated
internal target alias, not as a source-owned domain, Vintage response address,
or target configuration value. For supported Vintage endpoint fields, Recorder
preserves the IP-shaped contract: it rewrites the real `IPv4:port` to an
allocated fake-CIDR `IPv4:port`, the application connects to that fake IP, and
semantic Motan evidence renders the registry's stable alias for the same
target.

When Motan replay shows a Vintage alias but the target connects to a real
numeric IP, inspect target startup, CLI, configuration, and runtime wiring for
Vintage node data dumped from source-process memory or a remote response, a
copied individual naming file, a locally parsed node snapshot, or an injected
endpoint list. These paths bypass the normal Vintage response rewrite and fake
IP interception. Restore the source-compatible flow through the reusable
`breeze-sdk` Vintage loader and Motan client: obtain and refresh nodes through
Vintage, consume its returned IP endpoints, and let Motan connect to them.
When source evidence proves an SDK-native snapshot exists, keep it complete
and loader-owned; never turn it into application configuration or direct
endpoint injection.

Accept the repair only when the target's normal Vintage lookup yields a
fake-CIDR IP under Recorder or Replay, the Motan connection uses that IP, and
the semantic dependency matches the stable Vintage alias. Never synthesize or
connect to the alias in application code, rewrite a snapshot to contain it, or
treat its absence as a recording-data blocker by itself.

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
return `verification_policy/action_required` with the missing policy capability
and acceptance check. Never add a broad ignore or weaken stable fields.

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

## Dirty Dependencies

When `gates.responses=passed`, `gates.replay=complete`, and
`gates.dependencies=dirty`, continue with
[dirty-dependencies.md](dirty-dependencies.md). Do not end the operation merely
because response behavior is correct, and do not start comparison while the
current replay evidence is dirty. Treat `gates.dependencies=unknown` as replay
evidence repair instead.

## Non-Passing Handoff

Use the main skill's representative-case and status contract. For `blocked`,
also report the proven response-to-runtime chain, exact missing link, absent or
inconsistent external evidence, why inventing it is unsafe, and the concrete
capture or semantic-recording action that would unblock implementation. Name
the exact source path or packaged symbol, wiring, configuration key, runtime
source, and resource hostname already proven; never collapse them into
“insufficient source-code evidence”, “source drift”, or “count drift”.

Include recorder feedback when the missing evidence identifies a recorder
improvement. Use `incomplete` only for response-passing dirty evidence with no
safe source-proven rule; dirty evidence never stops response diagnosis or
repair.
