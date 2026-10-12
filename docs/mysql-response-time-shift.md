# MySQL result time shifts

A recorded lease read can contain an absolute UTC expiry five minutes after its
recorded request. Returning those bytes years later makes the lease appear expired.
An explicit version-3 dependency rule can translate selected DATETIME/TIMESTAMP
result columns by `target request_begin - recorded inbound request timestamp`:

```yaml
version: 3
expected_response: assertions_only
dependency_rules:
- id: lease-expiry
  protocol: mysql
  case: {method: POST, path: /leases/*/acquire}
  target: {host: db.internal, port: 3306}
  source_evidence: 'Lease:acquire stores UTC now plus the lease duration'
  mysql:
    database: app
    sql: SELECT expires_at,owner FROM leases WHERE id=? FOR UPDATE
    response_time_shift:
      expires_at:
        time: preserve_relative
        format: mysql_datetime
        preserve_values: ['1970-01-01 00:00:00']
```

The selector requires an exact endpoint, database, inbound API scope, bounded
SELECT template and 1..32 exact physical column names. Existing SQL table
templates remain available. DATETIME and TIMESTAMP values must represent UTC;
there is no configurable offset, timezone or tolerance. SQLx text and prepared
result delivery both preserve null cells, fractional precision (up to six digits)
and all unselected cells. Incomplete rows, truncated results, missing or ambiguous
columns, unsupported metadata, invalid dates and absent request anchors fail.
Up to sixteen explicit `preserve_values` per column retain source-proven fixed
sentinels, such as the epoch meaning an absent lease. They compare as datetimes
independently of fractional display precision and retain their original bytes.

Replay translates delivery copies only. The SQL, parameters, session identity,
recorded lane order and finite exchange consumption retain their ordinary checks.
These rules do not authorize changed SQL arguments and cannot share a rule with
`params` or `sql_values`. Original recordings and reports remain unchanged.

Use the coordinator's ordinary reviewed rule transaction. Supply the dependency
entry as JSON to `backend-rewrite rule plan --dependency-request RULE_JSON` with
the current query/evidence identifiers requested by the engine. The coordinator
binds the active API and source proof. Planning requires current-policy, complete,
finalized Replay with a matched same-case query, complete immutable semantic
results and both request timestamps. Apply rechecks file fingerprints and requires
fresh Replay before acceptance. This also works when the original failure is an
HTTP response mismatch rather than a MySQL query mismatch.

Managed E2E captures `request_begin` immediately before sending the inbound
request. Manual Replay must issue `traffic-e2e diagnose replay-control --session
SESSION request-begin CASE_ID` before sending it.
