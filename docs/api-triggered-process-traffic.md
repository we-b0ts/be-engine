# API-triggered process traffic

This reference covers Case API-origin attribution and rule construction. Case
coordinator command examples identify historical interfaces. Use the current
[Source session commands](session-regression.md) for managed migration.

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v3` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


An HTTP API can return while its asynchronous task continues to call dependencies.
Time-window recording can place those calls inside a later API's case. An
API-origin process rule reclassifies only source-proven, unused foreign-case
dependencies. The triggering API continues to execute and record normally.

Redis Replay also applies this origin proof before admitting target requests,
including focused runs whose triggering API is not selected. A proven foreign
Redis exchange in an ordinary pooled source lane does not block current-case
commands on that lane. Eager and lazy loading use the same proof. Original case
attribution and single-use responses remain intact; the report overlay still
reclassifies only unused evidence. A retained stateful command, incomplete or
ambiguous origin, or a request referencing the captured identity retains strict
lane ordering. No new recording or additional rule is needed when the existing
recording and configured API-origin rule already contain complete proof.

Redis request-rule applicability follows the same ownership overlay. Replay
retains each matching Source command's Case, connection and wire sequence. A
rule loses its Case obligation only when all of those occurrences are proven
unused background work and the Target never used the rule. Other Case
occurrences, actual rule use and incomplete occurrence inventories remain
required. Removing the process-owned rule restores the original obligation.
Historical reports without this occurrence inventory require fresh Replay
against the existing recording; they cannot be waived by rule name alone.

## Contract and first supported selectors

An ordinary process-owned rule remains unchanged. A Redis rule can additionally
declare `trigger_source`, `key_templates`, and exact trailing `arguments`.
GET, DEL, LRANGE and identity-bound EVALSHA are supported. LRANGE requires exactly
two canonical integer arguments; GET and DEL take none. One template selects
one complete key, with a single positive integer identity between fixed affixes.
`key_templates` are alternatives for one complete key. Multi-key DEL instead
uses an explicit ordered `key_sequence`; every key must carry the same identity.

```yaml
process_owned_dependencies:
  - name: response-cancel-cleanup
    protocol: redis
    ports: [6379]
    command: DEL
    key_templates: ['chat:cancel:{subtask_id}']
    trigger_source:
      kind: api
      method: POST
      path: /api/v1/responses
      request_body_json:
        /background: true
      capture:
        subtask_id:
          protocol: mysql
          target_host: db.example.test
          target_port: 3306
          database: app
          username: writer
          operation: INSERT
          table_patterns: ['subtasks_*']
          row_match: {role: ASSISTANT}
          column: id
    source_revision: 0123456789abcdef
    source_evidence: >-
      responses.py:create starts a background task; dispatcher.py:finish
      calls unregister_stream, which deletes its subtask cancellation key.
```

`request_body_json` means the inbound **request body parsed as JSON**.
`/background` is a JSON Pointer to the top-level `background` member, so the
example matches `{"background":true}`. It does not inspect `?background=true`,
the response JSON, HTTP status, or a current request being compared against a
foreign task. Missing members, string `"true"`, malformed or duplicate-member
JSON do not match boolean `true`. Conditions are optional when source proves
every request on the declared method/exact path follows the asynchronous branch.

The capture runs against semantic dependencies of each recorded trigger case.
It requires exactly one successful, explicit-column, single-row COM_QUERY
INSERT matching the endpoint, database, username, table and typed row predicates.
The selected column must contain a positive integral value within `u64`.
The lexer normalizes equivalent SQL decimals, including trailing-zero forms
such as `120` → `12e1`; identity extraction restores the exact decimal integer
without floating point, and numeric row predicates use exact decimal equality. Unselected audit
columns may use argument-free `NOW()` or `CURRENT_TIMESTAMP()`; those expressions
never satisfy a capture or row predicate. Prepared INSERTs, multi-row INSERTs,
other expressions, executable comments, failed writes, ambiguous captures and
reused identities do not authorize classification. Capture does
not inspect expected responses or make recording values available to target code.

The planner correlates exact Redis key identities after the INSERT. It retains
the original trigger case. A later request referencing that same captured
identity may reclassify unused Redis GET/LRANGE and bounded read-only MySQL
SELECTs through the existing API-origin rule. No per-request API allowlist,
additional rule, fixed background count or new recording is required. Identity,
endpoint, operation template, timestamp and complete-record checks still apply;
an unmatched identity cannot inherit another POST's origin. An independently
recorded unique POST for another identity is evaluated as a separate origin.
Same-resource DEL, Lua invocations, UPDATEs and transaction inheritance remain
strict. Nonempty uninspectable victim bodies remain case-owned.

Same-resource read permission applies only to unused report entries after
matching. It does not relax Redis lane ordering, synthesize responses or change
finite consumption. Reclassified entries identify the POST and include
`api_trigger_source.same_resource_read: true`. Removing the existing rule
restores their original case ownership.

This is a rule-authorized read exemption, not coroutine attribution. When the
background task and the current request issue identical reads, Replay may
consume a recorded background read and leave an equivalent request read unused.
The rule can classify the leftover without deciding which identical invocation
it originally represented. The number of eligible entries follows each
recording, and never exceeds immutable evidence. Consequently these shared
reads no longer provide a strict missing-call-count check for the current
request; precise caller/count verification requires additional recording
provenance. Response differences and target-side failures remain failures.
A common ID alone does not prove the caller: source review must establish that
the selected operation is the detached task's operation and identify any APIs
that can perform the same operation. Do not use this rule when that ownership
cannot be established. Never infer ownership just from an unused exchange.

The remaining identity protection covers mutation and transaction provenance,
rather than excluding a whole route prefix. A detached task may itself react to cancellation or
failure and collect its terminal result after the original HTTP response.
Those background cleanup calls can still be process-owned. Trace indirect
callers as well as direct ones: a result collector may call an accumulated-content
helper, which reads streaming content and finalizes blocks. A helper also used
by a polling/cancel endpoint does not establish the owner of every invocation.
Plan verifies recorded identity and scope; source evidence must establish the
background call chain and describe overlapping current-request callers. It
does not claim coroutine tracing.

Only `unused_recorded` entries are moved to the process-level diagnostic view.
Unmatched target calls, unsupported/unsafe traffic, response differences and
trigger-owned required dependencies remain failures. API-triggered rules do
not enable Redis first-value snapshots, repeat responses, interpret scripts,
or alter dependency arguments, delivery or finite consumption. Redis ordering
excludes only proven foreign work on ordinary pooled lanes; current-request
commands and retained stateful lanes keep their original order.

## Plan and apply

Use the current dirty-cluster evidence ID and source proof. The engine generates
the persisted rule, recording identity and bounded affected-case report; do not
write recording IDs, observed task IDs or case paths into policy.

```bash
backend-rewrite --target-root /absolute/target dependency-rule plan redis api-triggered \
  --evidence-id <current-dirty-evidence-id> \
  --ownership process-owned --name response-cancel-cleanup \
  --source-evidence 'responses.py:create -> dispatcher.py:finish -> session.py:unregister_stream starts detached work and deletes only its cancellation key' \
  --port 6379 --command DEL --key-template 'chat:cancel:{subtask_id}' \
  --trigger-source '{"kind":"api","method":"POST","path":"/api/v1/responses","request_body_json":{"/background":true},"capture":{"subtask_id":{"protocol":"mysql","target_host":"db.example.test","target_port":3306,"database":"app","username":"writer","operation":"INSERT","table_patterns":["subtasks_*"],"row_match":{"role":"ASSISTANT"},"column":"id"}}}'

backend-rewrite --target-root /absolute/target dependency-rule apply <returned-plan-id>
```

For a GET use `--command GET` and its source-proven key template. For LRANGE use
`--command LRANGE --argument=0 --argument=-1` and the list key template. Keep
the same trigger selector/capture for rules produced by the same source branch.
The plan reports affected foreign cases, trigger cases, unique matches and
ambiguous-origin/reference counts, without disclosing captured ID values.
No matched unused foreign exchange, a foreign recording boundary, or overlapping
target failure evidence rejects the plan. Apply rechecks policy, Replay report
and immutable recording identity; changes require a new plan. Normal coordinator
reclassification updates affected shared-session projections without changing
recording JSONL. Removing a rule restores original case ownership.

## MySQL SELECTs from the same API origin

MySQL rules use the same `trigger_source` descriptor and capture. Add
`identity_value_index` beside the existing `selector` to bind one zero-based `?`
slot in its SELECT template to the captured positive integer. Every endpoint,
table, projection, fixed predicate and other literal remains subject to the
ordinary bounded SELECT matcher. `?` slots are counted in template order, not
wire parameter order; fixed literals and LIMIT constants do not occupy slots.

```yaml
process_owned_dependencies:
  - name: response-result-lookup
    protocol: mysql
    selector:
      target_host: db.example.test
      target_port: 3306
      database: app
      username: writer
      table_patterns: ['subtasks_*']
      sql: SELECT id FROM {{table}} WHERE id = ? LIMIT 1
    identity_value_index: 0
    trigger_source:
      kind: api
      method: POST
      path: /api/v1/responses
      request_body_json: {'/background': true}
      capture:
        subtask_id:
          protocol: mysql
          target_host: db.example.test
          target_port: 3306
          database: app
          username: writer
          operation: INSERT
          table_patterns: ['subtasks_*']
          row_match: {role: ASSISTANT}
          column: id
    source_revision: 0123456789abcdef
    source_evidence: >-
      responses.py:create starts detached execution; result_collector.py:finish
      reads only its own assistant subtask before persisting the terminal result.
```

Use the existing MySQL planner with both additional flags:

```bash
backend-rewrite --target-root /absolute/target dependency-rule plan mysql \
  --evidence-id <current-dirty-evidence-id> \
  --ownership process-owned --name response-result-lookup \
  --source-evidence 'responses.py:create starts detached work; result_collector.py:finish reads its captured assistant subtask' \
  --target-host db.example.test --target-port 3306 --database app --username writer \
  --table-pattern 'subtasks_*' --sql 'SELECT id FROM {{table}} WHERE id = ? LIMIT 1' \
  --identity-value-index 0 \
  --trigger-source '{"kind":"api","method":"POST","path":"/api/v1/responses","request_body_json":{"/background":true},"capture":{"subtask_id":{"protocol":"mysql","target_host":"db.example.test","target_port":3306,"database":"app","username":"writer","operation":"INSERT","table_patterns":["subtasks_*"],"row_match":{"role":"ASSISTANT"},"column":"id"}}}'
```

The identity slot must be an equality or singleton `IN (?)` predicate after
WHERE. OR/NOT, multiple identities, locks and identity slots in a
projection or LIMIT are rejected. COM_QUERY and COM_STMT_EXECUTE require
recorded SQL with literal values already bound; unbound parameters are not
guessed. Only successful complete resultsets with full row metadata qualify.
New MySQL Replay summaries preserve `connection_id` and `query_sequence` together
with the endpoint and SQL fingerprint. Classification can identify a proven
transaction boundary even when another connection records identical COMMIT SQL.
Fingerprint-only historical reports remain usable when every identical exchange
has compatible proof. If those reports are ambiguous, rerun Replay against the
existing recording to obtain wire identities; rerecording is unnecessary. Missing
transaction starts or sequence gaps do not authorize the missing prefix or its members.
A direct source-proven UPDATE-to-COMMIT handoff can independently establish
the COMMIT caller as described below. Duplicate summaries
cannot authorize more exchanges than were recorded.
The plan's `unmatched_evidence_reasons` reports missing transaction prefixes and
ambiguous historical summaries even when other exchanges match. A missing wire
identity requests a fresh Replay, whereas a missing immutable transaction prefix
remains required after Replay unless the narrow direct-write handoff is proven.

An existing ordinary rule with the same name and exact SELECT selector can be
replaced by this narrower origin-bound rule through plan/apply. It is never
reused as proof of API ownership, and a reverse widening is not implicit. Other
overlapping rules remain conflicts. This also restores trigger-owned entries
previously classified by the broad rule. No recording or target behavior changes.

## Atomic DEL key sequences and Lua invocations

For multi-key cleanup, replace `key_templates` with the exact argument order:

```yaml
command: DEL
key_sequence:
  - 'chat:streaming:{subtask_id}'
  - 'chat:streaming:blocks:{subtask_id}'
  - 'chat:streaming:text_block:{subtask_id}'
  - 'chat:streaming:thinking_block:{subtask_id}'
  - 'chat:context_metrics:{subtask_id}'
```

Use repeated `--key-sequence-template` instead of `--key-template`. Missing,
extra, reordered or mixed-identity keys reject the whole exchange. This does
not authorize subsets, arbitrary DEL keys or Redis snapshots.

Some Lua callers put a task ID in ARGV while KEYS use date/hour buckets. Such
calls can still use the API origin, without guessing an ID from a date:

```yaml
command: EVALSHA
script:
  sha1: '1111111111111111111111111111111111111111' # replace with source script digest
  keys:
    - {prefix: 'metrics:failed-state:', numeric_middle: true}
    - {prefix: 'metrics:as-of'}
  argv_count: 2
  identity_argv_index: 0
```

Pass this descriptor as `--script JSON`, with the normal `--trigger-source`.
For each key, `numeric_middle: true` requires 1–20 decimal digits between its
fixed affixes. `numeric_middle: false` (the default) requires the exact key
`prefix + suffix`; it does **not** mean a wildcard middle. For a fixed key such
as `metrics:as-of`, use `prefix: metrics:as-of` and an empty suffix. Splitting it
as `prefix: metrics:as-`, `suffix: f` leaves an unallowed `o` in the middle.
Plan failures report the specific `KEYS[index]` and the violated condition,
without exposing dependency argument values.
SHA-1, numkeys, ordered key families and total ARGV count remain exact; numeric
middles are bounded decimal strings. `identity_argv_index` counts ARGV only,
starting at zero. Lua is never evaluated by classification. Other arguments
and finite Replay responses keep their normal comparison/consumption behavior.

A successful, single-digest `SCRIPT EXISTS` is associated only with an already
proven EVALSHA in the same case, on the same connection at the next wire
sequence, after origin capture. Standalone probes, gaps, different connections,
different digests and missing invocations remain unclassified. No blanket
SCRIPT or EVALSHA process exception is added.

## MySQL UPDATEs and complete transactions

MySQL ownership preparation includes immutable Global prefixes and Case tails.
A background UPDATE admitted just before an HTTP request and its COMMIT captured
inside that request therefore retain one proven transaction owner. A Global
record has no invented HTTP request or Case origin. A missing association alone
does not authorize exclusion; ambiguous connections, mixed trigger identities,
incomplete responses and active-transaction gaps remain required.

Recorder precomputes rule-independent transaction facts and policy-dependent
ownership after its writers are sealed and the completed run is published.
Managed Replay rebuilds stale or missing results during dependency-index
preparation, before its readiness budget starts. Standalone Replay uses the same
fallback. Caches bind the complete Case/Global inventory, file identities,
request facts, rule fingerprint and analysis version; rule changes reuse valid
transaction facts. Cross-process locks serialize cold construction. Warm ownership
loads read no SQL or response payloads. Global construction reuses paged metadata
and seeks only the selected original exchanges.

Before Target admission, Replay retains only compact ownership keys for selected
Cases. Proven foreign operations do not impose that Case's consumption obligation
or outrank its own matching candidates. Finite delivery and failures stay with
the protocol adapter. The report's `process_owned_mysql_exchanges` retains the
original wire identity, rule and trigger Case. Policy reclassification restores
these original obligations before checking the current rules, so removing a rule
does not preserve an old exemption. Business COMMITs remain required.

The API-origin MySQL planner also accepts a single-table UPDATE with literal
or `?` assignments and an identity predicate. For example:

```text
--sql 'UPDATE {{table}} SET status = ? WHERE id = ?' --identity-value-index 1
```

The identity slot still counts all template `?` positions, including SET.
Exactly one captured positive identity must constrain the WHERE predicate.
Only successful OK responses affecting zero or one row qualify. Expressions,
unbounded writes, joins, INSERT/DELETE and ordinary process-owned write rules
are rejected. Live matching, write access gates and transaction execution are
unchanged; only source-proven unused foreign-case evidence is reclassified.

`include_transaction_boundaries` also recognizes a direct UPDATE-to-COMMIT handoff
when the transaction prefix is absent. The immediately preceding exchange must
be a successful single-row UPDATE with its own unique API-origin proof, on the
same connection at the preceding sequence. Both exchanges require complete
responses, clean transaction flags and independent foreign-request scope; the
write must remain in a transaction and COMMIT must finish it. Source evidence
must establish that the detached task owns that database session and commits
its write. This attributes only the COMMIT call. Missing-prefix statements and
unbound reads do not inherit ownership. No extra rule or option is required;
without `include_transaction_boundaries`, COMMIT remains required.

For complete-transaction inheritance, `--include-transaction-boundaries` requires
a complete sequence on one recorded connection, consistent
server transaction flags, successful complete responses, a known start and end,
and origin-bound statement witnesses identifying one trigger case. Missing
sequences, reused/ambiguous connections, mixed origins and incomplete groups
keep unbound transaction members required.

A helper read without a task ID may be admitted through repeatable
`--transaction-member JSON` (persisted as `transaction_members`). Each value
is an ordinary read-only MySQL selector with exact endpoint/database/user,
bounded tables and SQL shape. All unbound statements in the transaction must
match those explicit members. Members cannot authorize writes and never match
outside a complete origin-anchored transaction. For example, a task update
may read its team configuration in the same exclusive database transaction.
Source evidence must establish that call chain and session ownership.

On an existing named API-origin MySQL rule, plan/apply can update
`include_transaction_boundaries` and `transaction_members` while keeping the
source, SQL selector and identity slot unchanged. This produces a reviewed diff
and rechecks immutable evidence; no delete/recreate step is needed. Changing
the anchor still conflicts.

Existing configured API-origin MySQL rules can jointly prove a transaction;
all anchors must name the same trigger case. No wildcard transaction rule is
created. Fingerprint-only historical summaries require compatible proof for
every identical boundary/member exchange. Existing safe optional session
cleanup remains supported independently; recorded ROLLBACKs are not necessarily
dirty dependencies.

## Recording reuse and cost

Complete historical recordings can be reused when the trigger request, INSERT
and foreign dependency are present. Missing/truncated evidence cannot be
reconstructed. This classification does not claim that the asynchronous task's
eventual result or full lifetime was captured or verified.

New recordings retain matching idle Redis/MySQL exchanges as finite Global evidence
with `global_dependency_reason: api_trigger_candidate`; active-window calls
remain in their original cases until evidence proves their origin. Neither
request selection nor dispatch is changed by the rule.

Origin indexes are private disposable files outside immutable recording trees,
keyed by the rule content, format version and source file identity. A cold plan
or evidence-reclassification pass reads source bodies/dependencies. Optional
MySQL locations reuse existing protocol indexes; compact SQL token counts and
integer hashes filter unrelated rows before authoritative record reads. Rules
sharing a trigger share capture discovery and candidate scans. Complete
transaction analysis reads only connections with a proven origin, while counting
identical SQL on every connection to preserve ambiguity checks. Warm loads
validate file metadata and reuse the index without decoding dependency payloads.
Rules and recordings changing invalidate the cache. Concurrent focused operations
share a file lock so they do not duplicate a cold build. Unconfigured operation
does no origin-index I/O. `status` reads existing classification summaries and
rule fingerprints only; it never scans recording bodies or builds the index.
