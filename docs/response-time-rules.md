# JSON response time rules

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v1` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


Use a source-proven JSON timestamp rule for a generated time field. The
default `request_window` mode checks that each value is within five seconds
of its own request start. An expiry or scheduled time instead needs an
explicit `time: preserve_relative` mode:

```yaml
response_rules:
  json:
    "POST /api/sessions":
      timestamp:
        - pointer: /expires_at
          format: rfc3339
          time: preserve_relative
          source_evidence: SessionService:create sets expiry from current time plus TTL
          source_example: "2024-01-02T04:04:05Z"
          target_example: "2024-01-02T05:04:05Z"
```

Replay uses the immutable source `request.json.timestamp` and the target's
captured `request_sent_at`. It checks:

```text
abs((target_value - target_request) - (source_value - source_request)) <= 5 seconds
```

The source observation supplies the offset; no application TTL, configurable
offset, tolerance or current-clock fallback is added to the engine. A wrong
TTL or an unchanged absolute expiry on a later request fails when its offset
differs by more than five seconds. Missing anchors, invalid formats, overflow,
null/boolean/container values and mismatched JSON types fail. RFC3339 requires
a timezone in the value and compares instants, so equivalent timezone
representations work without an additional timezone configuration.
Numeric formats support JSON numbers and numeric strings of the same type.
Supported formats are `unix_seconds`, `unix_milliseconds`, `rfc3339` and
`amz_date`. Wildcard pointers check every selected array item; other fields,
array structure, headers and status remain subject to their existing assertions.

The coordinator plans the rule from current evidence and source proof:

```bash
backend-rewrite rule plan \
  --evidence-id <current-evidence-id> \
  --body-codec json --kind timestamp \
  --timestamp-format rfc3339 --timestamp-mode preserve-relative \
  --json-pointer /expires_at \
  --source-evidence 'SessionService:create sets expiry from current time plus TTL' \
  --source-example '2024-01-02T04:04:05Z' \
  --target-example '2024-01-02T05:04:05Z'
```

Use actual observations for the example arguments. Plan preflights the exact
recorded/target response witnesses with the same comparator used by Replay;
apply checks the frozen witnesses and policy again. Apply the returned plan,
then run fresh Replay with the existing recording. The mode is valid only for
`timestamp`, and omitting it preserves the existing request-window behavior.
`duration` retains numeric elapsed-time semantics. `random` does not validate
expiry derivation and must not substitute for a time rule.
