# MySQL SQL time rules

Runtime-generated timestamps in INSERT, UPDATE and DELETE can be validated with
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
              time: replay_now
              format: "%+"
        1: {time: replay_now, tolerance: 5s}
```

Add this section to the existing verification policy. The rule applies to the
selected database and SQL across all inbound APIs. The table is already part of
the SQL template; no URL path, host, user, wire command or duplicate table field
is required. Ordinary replay still matches source and target connection identity.
The template is shared by source and target after bound values are materialized;
it is not a SQL rewrite from one side to the other.

`time: replay_now` defaults to zero offset, 5 seconds tolerance, UTC and MySQL
`%Y-%m-%d %H:%M:%S%.f` datetime strings (including microseconds). Integer Unix
seconds are also accepted. Override `tolerance`, `offset`, `format` or `timezone`
beside each selected time only when necessary; `%+` accepts RFC 3339 values such
as Python `datetime.isoformat()` output. Every source value must parse, and every
target value must satisfy its own offset/tolerance around Replay's current time.
Each source/target pair must share the same scalar category. JSON pointers must
be exact, non-root, non-overlapping pointers; wildcards are not supported.
Recorded database errors are still returned as errors.

In `sql_values` mode, both `COM_QUERY` and `COM_STMT_EXECUTE` are covered.
The previous nested `time: {relative_to: replay_now, ...}` syntax remains
supported with its original parsing semantics. Explicit legacy case, endpoint
and username selectors remain supported, but the time-rule planner generates
only database/SQL scope. Source-code proof stays in the plan report and
coordinator plan record, rather than the runtime configuration.

Templates are limited to one write, 64 KiB and 4096 tokens. Executable comments
and optimizer hints remain unsupported. Quoted `?` does not create a slot;
`*` is a SQL token, not a glob. Functions cannot replace scalar slots. Legacy
`params` rules retain their behavior and cannot be combined with `sql_values`
in one rule. Overlapping dynamic rules fail. SELECT compatibility remains under
its existing metadata/projection contract.

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
object requires `value_index` and may set `json_pointer`, `tolerance`, `offset`,
`format` and `timezone`. The original `--value-index` plus optional time flags
remains supported for one scalar slot; it cannot be combined with
`--time-value`.

Plan requires source-code proof and uses current active API evidence for the
correlation, without adding an API selector to the generated rule. Optional
`--target-host`/`--target-port` and `--username` filter the evidence lookup only.
Source and target evidence must still have the same endpoint, database and user.
It correlates an unmatched target write with an immutable recorded write in the
same case. Every selected time must differ, parse and fall in the captured replay
interval plus its configured offset/tolerance, while all unselected SQL and JSON
values remain equal. Wrong keys, malformed source times, parse warnings,
unfinished replay and unrelated APIs cannot authorize the plan. The preview
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
