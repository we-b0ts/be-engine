# MySQL SQL time rules

Runtime-generated timestamps in SELECT, INSERT, UPDATE and DELETE can be validated with
explicit `dependency_rules.mysql.sql_values` rules. One rule can atomically
select multiple scalar SQL slots and exact JSON Pointer fields inside a string
slot. These cover text literals, bound parameters and prepared statements with
inline values and no parameters, in either source/target protocol direction.
Existing captures remain usable; targets retain normal clocks, writes and
database error handling.

The selector is a tokenized SQL template. Each `?` represents one SQL value.
`sql_values` indexes template slots from zero, independently of wire parameter
positions. A slot can select the whole scalar with `time`, or selected fields
inside a JSON string with `json`. Unselected slots must retain the recorded
value. JSON values outside selected pointers must remain structurally equal.
All other SQL tokens and finite consumption stay exact; database/SQL scope is
independent of inbound request paths.

```yaml
dependency_rules:
  - id: api-key-last-used-at
    protocol: mysql
    mysql:
      database: app
      sql: UPDATE kinds SET json=?, updated_at=? WHERE id=?
      sql_values:
        0:
          json:
            /spec/cloudConfig/nevisIpObservedAt:
              time: preserve_relative
              format: "%+"
        1: {time: preserve_relative}
```

Add this section to the existing verification policy. The rule applies to the
selected database and SQL across all inbound APIs. A concrete table stays exact;
no URL path, host, user or wire command is required. Ordinary replay still
matches source and target connection identity.
The template is shared by source and target after bound values are materialized;
it is not a SQL rewrite from one side to the other.

For source-proven sharded tables, use `{{table}}` with `tables` (exact physical
names), `table_series` (at most 4096 names), or `table_patterns` (at most 64
identifier patterns containing one `*`). For example:

```yaml
- id: subtask-updated-at
  protocol: mysql
  mysql:
    database: task_manager
    sql: UPDATE {{table}} SET updated_at=? WHERE {{table}}.id = ?
    table_series: {prefix: subtasks_, start: 0, end: 1023, width: 4}
    sql_values: {0: {time: preserve_relative}}
```

Every `{{table}}` in one statement binds to the same physical table, and source
and target must bind to that same table. The example covers `subtasks_0155` and
`subtasks_0640` independently; it cannot match a source write to one shard with a
target write to another. Stable keys, predicates, database identity and finite
recorded consumption still apply. The marker can replace a whole table name or
a table qualifier, including backticked names; literals, column/alias names and
identifier fragments are unsupported. Table selectors require `{{table}}`, and
`{{table}}` requires declared table bounds. Existing concrete rules need no change.
Table patterns match only ASCII identifiers up to 64 bytes and reject a bare `*`.
Source proof must justify the selected table family as well as its generated time.
When an initial write also captures a generated identity, the
[joint identity/time planner](dynamic-value-rules.md#plan-a-generated-mysql-identity-with-current-time-values)
inherits these same table bounds from the identity capture and applies both
ordinary rules atomically. Its admission checks the entire declared family for
time-rule conflicts, including tables not present in the current witness.

`time: preserve_relative` compares
`(target_value - source_value) - (target_request_time - source_request_time)`
with the engine's fixed 5-second tolerance. The source anchor is the immutable
inbound request timestamp; Replay captures the target anchor before sending that
case's request. Both anchors are required, with no current-clock fallback.
A common timezone offset cancels in the difference, and moving cutoffs such as
`now - 24h` preserve their recorded offset without configuring it.

MySQL `%Y-%m-%d %H:%M:%S%.f` strings (including microseconds) and integer Unix
seconds are supported. Set `format` only for another representation; `%+` accepts
RFC 3339. No per-rule `tolerance`, `timezone` or `offset` is generated.
Legacy `replay_now`, explicit `tolerance: 5s`, timezone and offset options remain
readable and normalize to the relative comparison; other tolerances are rejected.
Each source/target pair must share the same scalar category. JSON pointers must
be exact, non-root, non-overlapping pointers; wildcards are not supported.
Recorded database errors are still returned as errors.

In `sql_values` mode, both `COM_QUERY` and `COM_STMT_EXECUTE` are covered.
The previous nested `time: {relative_to: replay_now, ...}` syntax remains
accepted as a compatibility alias for the relative comparison. Explicit legacy
case, endpoint and username selectors remain supported, but the planner generates
only database/SQL scope. Source-code proof stays in the plan report and
coordinator plan record, rather than the runtime configuration.

Templates are limited to one statement, 64 KiB and 16384 tokens. Recorded and
target SQL statements may contain up to 1 MiB, including scalar/JSON literals,
and retain the same one-statement and 16384-token limits. Bound parameters retain
their existing validation; this byte limit applies to SQL text. Executable comments
and optimizer hints remain unsupported. Quoted `?` does not create a slot;
`*` is a SQL token, not a glob. Functions cannot replace scalar slots. Legacy
`params` rules retain their behavior and cannot be combined with `sql_values`
in one rule. Overlapping dynamic rules fail. SELECT time rules replay the recorded
columns and rows, including COUNT queries and prepared-statement metadata. A
count query and a row query need separate templates even when both use slot zero.
Moving cutoffs preserve the recorded source offset; stable filters, ordering
and limits remain exact.

Ordinary queries with no dynamic values need no time rule. Text queries and
prepared statements with bound, inline or mixed scalar values match by exact
tokens after binding, including `IN (SELECT ...)` subqueries. Prepared metadata
uses the same recorded bound values to resolve result columns. This does not
reorder or simplify subquery predicates; types and stable values remain exact.

## Coordinator plan/apply

Response, Replay and Dependency issues with MySQL dirty evidence expose the
`mysql_sql_time` planner. Use the current dirty-cluster evidence id:

```sh
backend-rewrite --target-root /path/to/target dependency-rule plan mysql-time \
  --evidence-id evidence-current --rule-id kind-write-times \
  --database app \
  --sql 'UPDATE kinds SET json=?, updated_at=? WHERE id=?' \
  --time-value '{"value_index":0,"json_pointer":"/spec/cloudConfig/nevisIpObservedAt","format":"%+"}' \
  --time-value '{"value_index":1}' \
  --source-evidence 'kind.py:updated_at and cloud_device_ip_index.py:nevisIpObservedAt use current time'

backend-rewrite --target-root /path/to/target dependency-rule apply <plan-id>
```

Repeat `--time-value` with a JSON object for an atomic multi-location plan. Each
object requires `value_index` and may set `json_pointer` and `format`.
The original `--value-index` plus optional `--format`
remains supported for one scalar slot; it cannot be combined with
`--time-value`.

If the same first capture statement contains a newly generated identity and
current timestamps, use `rule plan --dynamic-value RULE_JSON --mysql-time
COMPANION_JSON`. The companion declares a separate rule id, explicit time
locations and source proof; it inherits the capture's exact endpoint, database
and SQL. Both ordinary rules are proved against the same immutable exchange and
applied atomically before one fresh Replay. Stable fields and existing identity
bindings remain strict. Distinct JSON Pointers in one SQL value are supported;
overlapping ownership is rejected. See [joint identity/time
planning](dynamic-value-rules.md#plan-a-generated-mysql-identity-with-current-time-values).

For a table template, add repeatable `--table` or `--table-pattern`, or use
`--table-prefix subtasks_ --table-start 0 --table-end 1023 --table-width 4` with
`--sql 'UPDATE {{table}} SET updated_at=? WHERE {{table}}.id = ?'`. These bounds
are persisted in the pending plan and generated policy. Plan/apply requires a
same-case witness with the same physical table on source and target.

Plan requires source-code proof and uses current active API evidence for the
correlation, without adding an API selector to the generated rule. Optional
`--target-host`/`--target-port` and `--username` filter the evidence lookup only.
Source and target evidence must still have the same endpoint, database and user.
It correlates an unmatched target statement with an immutable recorded statement in the
same case. Every selected time must differ, parse and preserve its distance from
its own request anchor within 5 seconds, while all unselected SQL and JSON values
remain equal. The replay report must contain that case's captured target request
timestamp; old reports require a fresh replay before planning. Wrong keys,
malformed source times, parse warnings,
unfinished replay and unrelated APIs cannot authorize the plan. SELECT resultsets
must have complete columns and rows, with no truncation or client termination. The preview
includes the policy diff and a case id.

Apply edits only `dependency_rules` in `.traffic-e2e/verification.yaml`. It does
not reclassify writes as background, clean failed reports or start recording.
The coordinator invalidates validation and uses normal Replay with the existing
evidence. Direct plan application rejects a changed policy; identical repeated
plans reuse the existing rule.

Other proven engine failures that surface as HTTP errors can enter
`replay_capability_gap` from a `Response` issue using current non-empty
dirty-cluster evidence. Response-only evidence cannot select this route. Repair
verification retains the same recording and returns to Replay validation.

Acceptance: `cargo test --lib sql_time`, `cargo test --lib count_distinct` and
`cargo test --lib rewrite::repair` cover actual SQLx/TLS clients, protocol
directions, cached rebinding, stable fields, errors and finite evidence.
