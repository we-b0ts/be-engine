# API-triggered process traffic

An HTTP API can return while its asynchronous task continues to call Redis.
Time-window recording can place those calls inside a later API's case. An
API-origin process rule reclassifies only source-proven, unused foreign-case
dependencies. The triggering API continues to execute and record normally.

## Contract and first supported selectors

An ordinary process-owned rule remains unchanged. A Redis rule can additionally
declare `trigger_source`, `key_templates`, and exact trailing `arguments`.
Version one supports GET, single-key DEL and LRANGE. LRANGE requires exactly
two canonical integer arguments; GET and DEL take none. One template selects
one complete key, with a single positive integer identity between fixed affixes.
Templates are alternatives, not permission for multi-key DEL.

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
The selected column must contain a positive canonical integer. Unselected audit
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

## Recording reuse and cost

Complete historical recordings can be reused when the trigger request, INSERT
and foreign dependency are present. Missing/truncated evidence cannot be
reconstructed. This classification does not claim that the asynchronous task's
eventual result or full lifetime was captured or verified.

New recordings retain matching idle Redis exchanges as finite Global evidence
with `global_dependency_reason: api_trigger_candidate`; active-window calls
remain in their original cases until evidence proves their origin. Neither
request selection nor dispatch is changed by the rule.

Origin indexes are private disposable files outside immutable recording trees,
keyed by the rule content, format version and source file identity. A cold plan
or evidence-reclassification pass reads source bodies/dependencies. Warm loads
validate file metadata and reuse the index without decoding dependency payloads.
Rules and recordings changing invalidate the cache. Concurrent focused operations
share a file lock so they do not duplicate a cold build. Unconfigured operation
does no origin-index I/O. `status` reads existing classification summaries and
rule fingerprints only; it never scans recording bodies or builds the index.
