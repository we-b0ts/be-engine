# API-triggered process traffic

An HTTP API can return while its asynchronous task continues to call dependencies.
Time-window recording can place those calls inside a later API's case. An
API-origin process rule reclassifies only source-proven, unused foreign-case
dependencies. The triggering API continues to execute and record normally.

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
the original trigger case and every request on the trigger's resource path
(including polling/cancellation descendants). Foreign requests explicitly
referencing the same identity in their URI or body are ambiguous and remain
case-owned. Nonempty uninspectable victim bodies also remain case-owned.
A common ID alone does not prove the caller: source review must establish that
the selected operation is the detached task's operation and identify any APIs
that can perform the same operation. Do not use this rule when that ownership
cannot be established. Never infer ownership just from an unused exchange.

This route protection refers to inbound polling or cancellation requests and
their own dependencies. A detached task may itself react to cancellation or
failure and collect its terminal result after the original HTTP response.
Those background cleanup calls can still be process-owned. Trace indirect
callers as well as direct ones: a result collector may call an accumulated-content
helper, which reads streaming content and finalizes blocks. A helper also used
by a polling/cancel endpoint does not establish the owner of every invocation.
Plan verifies recorded identity and scope; source evidence must establish which
caller owns the selected operation. It does not claim coroutine tracing.

Only `unused_recorded` entries are moved to the process-level diagnostic view.
Unmatched target calls, unsupported/unsafe traffic, response differences and
trigger-owned required dependencies remain failures. API-triggered rules do
not enable Redis first-value snapshots, repeat responses, interpret scripts,
or alter dependency arguments, delivery, lane ordering or finite consumption.

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
transaction starts or sequence gaps still remain required. Duplicate summaries
cannot authorize more exchanges than were recorded.

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

Add `--include-transaction-boundaries` to include related COMMIT/ROLLBACK. The
engine requires a complete sequence on one recorded connection, consistent
server transaction flags, successful complete responses, a known start and end,
and origin-bound statement witnesses identifying one trigger case. Missing
sequences, reused/ambiguous connections, mixed origins and incomplete groups
keep the transaction evidence required.

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
