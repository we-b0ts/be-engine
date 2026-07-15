# Replay Dynamic-Value Policy

Each target repository owns one source-controlled `config/replay.yaml`. Pass it
explicitly to every recorded replay:

```bash
traffic-replay --policy config/replay.yaml /path/to/case-group
traffic-replay-policy validate --policy config/replay.yaml
```

This policy is independent of recorder `case_path_patterns`:

- `case_path_patterns` groups recorded inbound API paths.
- replay policy matches legitimate runtime-generated dependency fields.

## Required Contract

Every policy starts with:

```yaml
version: 1
expected_response: assertions_only
rules: []
```

`expected-response.json` is an assertion oracle only. Target product code,
dependency mocks, E2E setup, and replay policy generation must not read its
status, headers, or body to create the actual response, dependency result,
branch decision, cache result, or side effect. The policy parser requires this
declaration; migration review must also verify the target harness obeys it.

Do not put recorded values, response bodies, secrets, absolute case paths, or
case-id exceptions in the policy. Use selectors and semantic validation only.

## Rule Scope

Every rule must select the inbound case API by method and path, then select one
dependency by protocol and a narrow dependency identity. HTTP rules require a
target host, dependency method and dependency path. MySQL rules require a SQL
pattern plus at least one target host, database, or username.

Case and HTTP paths use segment-aware patterns: `*` stays inside one segment
and `**` crosses segments. SQL patterns are normalized for whitespace, case,
and backticks; `*` and `?` are wildcards.

## Dynamic Fields

Version one supports scalar MySQL parameters and single-occurrence HTTP query
parameters:

- `bind`: capture the actual runtime value in the current case.
- `ref`: require the actual value to equal a value bound earlier in that case.
- `validate: uuid`, `uuid_v4`, or `non_empty`: validate shape without comparing
  the recorded literal.
- `time`: require a timestamp relative to `replay_now`, with an offset and
  tolerance.

Example:

```yaml
version: 1
expected_response: assertions_only
rules:
  - id: audit-insert
    case:
      method: GET
      path: /api/resources/*
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "INSERT INTO request_log_* (uuid, request_time) VALUES (?, ?)"
      params:
        0:
          bind: audit_id
          validate: uuid_v4
        1:
          time:
            relative_to: replay_now
            tolerance: 2s
            format: "%Y-%m-%d %H:%M:%S"
            timezone: "+08:00"

  - id: audit-update
    case:
      method: GET
      path: /api/resources/*
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: audit
      username: audit_writer
      sql: "UPDATE request_log_* SET response_status=? WHERE uuid=?"
      params:
        1:
          ref: audit_id
```

Durations accept integer `ms`, `s`, `m`, `h`, and `d` units. A time value may
be RFC 3339, Unix seconds, or use an explicit Chrono format and numeric
`+HH:MM`/`-HH:MM` timezone.

## Evidence And Failure

Replay reports include the canonical policy path, content fingerprint,
`assertions_only` declaration, rule applicability, match counts, field
operation counts, and unused applicable rules. An applicable rule with zero
matches is dirty evidence and fails `end`, `finalize --fail-on-dirty`, and
aggregate dirty checks. Rules outside the selected case API are reported as
non-applicable and do not make focused replay dirty.

A query field cannot be both policy-managed and passed through the global
`--http-ignore-query-param` option. Replay rejects that configuration at
startup.

Version one does not apply JSONPath rules inside response bodies or MySQL JSON
strings. It also does not pass bindings into the target runner's HTTP response
assertion process. Keep such cases incomplete instead of reading
`expected-response.json` to inject a recorded value.
