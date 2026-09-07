# MySQL SQL time rules

Runtime-generated timestamps in INSERT, UPDATE and DELETE can be validated with
explicit `dependency_rules.mysql.sql_values` rules. These cover text literals,
bound parameters and prepared statements with inline values and no parameters,
in either source/target protocol direction. Existing captures remain usable;
targets retain normal clocks, writes and database error handling.

The selector is a tokenized SQL template. Each `?` represents one scalar value.
`sql_values` indexes template slots from zero, independently of wire parameter
positions. Unselected slots must retain the recorded value. All other SQL
tokens, endpoint/database/username, case scope and finite consumption stay exact.

```yaml
version: 3
expected_response: assertions_only
dependency_rules:
  - id: api-key-last-used-at
    protocol: mysql
    case: {method: GET, path: /api/v1/responses/*}
    target: {host: db.internal, port: 3306}
    mysql:
      command: COM_QUERY
      database: app
      username: app_user
      sql: UPDATE api_keys SET last_used_at=?, updated_at=now() WHERE api_keys.id=?
      sql_values:
        0:
          source_evidence: security.py:get_auth_context assigns datetime.utcnow() before commit
          time:
            relative_to: replay_now
            offset: 0s
            tolerance: 5s
            format: '%Y-%m-%d %H:%M:%S%.f'
            timezone: '+00:00'
```

In `sql_values` mode, either `COM_QUERY` or `COM_STMT_EXECUTE` selects both query
encodings. The example permits a current UTC `last_used_at`; the key id and
`updated_at=now()` stay exact. Selected source and target values must share the
same scalar category: string or integer Unix seconds. Source strings must parse
in the declared format, and actual values must satisfy the offset/tolerance
around Replay's current time. `%.f` accepts microseconds. Recorded database errors
are still returned as errors.

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
  --evidence-id evidence-current --rule-id api-key-last-used-at \
  --target-host db.internal --target-port 3306 \
  --database app --username app_user \
  --sql 'UPDATE api_keys SET last_used_at=?, updated_at=now() WHERE api_keys.id=?' \
  --value-index 0 --tolerance 5s \
  --format '%Y-%m-%d %H:%M:%S%.f' --timezone '+00:00' \
  --source-evidence 'security.py:get_auth_context assigns datetime.utcnow() before commit'

backend-rewrite --target-root /path/to/target dependency-rule apply <plan-id>
```

Plan uses the active API scope and requires source-code proof. It correlates an
unmatched target write with an immutable recorded write in the same case. Only
the selected value may differ, and the target time must fall in the captured
replay interval plus the configured offset/tolerance. Wrong keys, malformed
source times, parse warnings, unfinished replay and unrelated APIs cannot
authorize the plan. The preview includes the policy diff and a case id.

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
