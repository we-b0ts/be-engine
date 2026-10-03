# Redis response time-shift rules

Recorded absolute timestamps can age between capture and Replay. If source and
target use identical expiry logic, this can cause extra dependency reads even
when the earlier response matched successfully. The explicit `time-shift`
capability preserves that response's original relative age. It is separate from
JWT inbound request transformation and from assertion comparison rules.

## Worker discovery and coordinator plan/apply

There is deliberately no automatic hint or candidate detector. A field name,
integer magnitude, elapsed time or unmatched GET/HGET does not establish expiry.
Workers consult the scenario index in
[API implementer diagnosis](../plugins/ai-software-engineering/skills/backend-rewrite/references/api-implementer-diagnosis.md#rule-discovery-from-source-diagnosis)
and trace cache initialization, expiry, refresh and downstream consumers.
For example, case 1 reads a token, case 2 reuses it during recording, but the
same code refetches during Replay because the recorded timestamp is now stale.
The field to transform is in case 1's already matched response.

The worker returns current dirty-cluster evidence, the selector, response JSON
Pointer, explicit timestamp format and source proof. The coordinator can plan
without a hint or `applicable_rule_planners` entry:

```bash
backend-rewrite --target-root /path/to/target dependency-rule plan redis time-shift \
  --evidence-id <current-dirty-cluster-evidence-id> --rule-id tauth-token-time \
  --host rm7455.eos.grid.sample.test --port 7455 \
  --command HGET --key token_v2 --hash-field 3061639762 \
  --json-pointer /timestamp --timestamp-format unix-milliseconds \
  --source-evidence 'app/services/tauth.py:67 _is_token_valid: timestamp is Unix milliseconds; age < 3h gates cache reuse; timestamp is not signed'

backend-rewrite --target-root /path/to/target dependency-rule apply <plan-id>
```

Plan requires a finalized current API attempt with at least one selected,
successfully matched response. It checks all selected exchanges within the same
completed standard recording, including earlier cases and Global evidence.
Successful matching proves availability, not expiry causality. Source proof is
required and retained in the plan record, not copied into runtime YAML.
Errors, nil responses, missing timestamps/fields, unsupported JSON types,
truncation, diagnostic snapshot hits and reusable snapshot seeds are rejected.
Plan previews affected source cases and policy; it exposes no token contents.
Apply rechecks policy, report and selected recording fingerprints. It invalidates
API verification and returns the normal next command for fresh Replay.
There is no new recording, offline failure reclassification or acceptance on apply.

## Compact policy and selectors

```yaml
dependency_rules:
  - id: tauth-token-time
    protocol: redis
    target: {host: rm7455.eos.grid.sample.test, port: 7455}
    redis:
      command: HGET
      key: token_v2
      hash_field: "3061639762"
      response_json:
        /timestamp: {time: preserve_relative, format: unix_milliseconds}
```

`database` defaults to 0. `command` is GET or HGET; HGET requires
`hash_field`, and GET forbids it. Both key and hash field use the same byte
selector syntax:

| Selector | Meaning |
| --- | --- |
| `"3061639762"` | Exact bytes |
| `{prefix: "app:"}` | Prefix |
| `{suffix: ":token"}` | Suffix |
| `{prefix: "app:", suffix: ":token"}` | Both affixes |
| `{numeric: true}` | Nonempty ASCII decimal string, preserving leading zeros |
| `{prefix: "app:", numeric: true, suffix: ":token"}` | Decimal middle between affixes |

Legacy `{kind: exact, value: ...}`, `kind: affix` and `kind: numeric`
selectors remain readable. Empty unconstrained patterns and unknown fields fail.
CLI offers `--key-prefix/--key-suffix/--key-numeric` and
`--hash-field-prefix/--hash-field-suffix/--hash-field-numeric`.
Alternatively, `--numeric-key-pattern 'app:<id>'` or
`--numeric-hash-field-pattern '<id>:token'` selects one numeric middle.
An exact value cannot be combined with a pattern. Broader patterns require
source proof that all selected responses share the stated time semantics.

JSON Pointers are exact (including ordinary array indices and escaped keys).
Wildcard expansion is not supported. Formats are `unix_seconds` and
`unix_milliseconds`, requiring signed-64-bit integer values. Each plan selects
one field; a response_json map or multiple non-overlapping rules can select
several fields. Timestamp format and preserve_relative remain explicit.

## Runtime contract

After ordinary endpoint/session/command/argument matching and recorded response
delay, immediately before delivery:

```text
new_timestamp = recorded_timestamp + (response_send_time - recorded_response_time)
```

The offset uses the field's declared unit. All selected fields in a delivered
response use the same time anchor. The engine always transforms an immutable
response copy, with no cumulative shifting. Original relative expiry/future
validity is preserved; timestamps are never reset to now. The application's
expiry duration remains in normal product code and need not be configured here.

Only selected JSON scalar values change semantically; credentials, arrays and
other fields retain their values. RESP bulk lengths are rebuilt. JSON duplicate
members are rejected; frames are bounded to 1 MiB and overflow fails explicitly.
Recorded files, request identity, lane ordering, target cache implementation and
finite consumption are unchanged. Reusable/background snapshots cannot be
combined with this rule. Successful delivery records bounded rule IDs and
offsets, never credentials. Failed transformation/delivery remains dirty.

## Shared reads across cases

When a source cache outlives an individual API case, an existing time-shift
rule can be promoted to `recording_run` scope. This applies to ordinary,
successful GET or HGET exchanges in the completed recording run, including
multiple cache refreshes. These remain request-owned evidence; sharing does
not classify the reads as process-owned background work.
The key and HGET field must be exact selectors. The planner requires a
finalized Replay report containing an unmatched read with the same request
identity in another case, plus source evidence for the shared cache lifetime.

```bash
backend-rewrite --target-root /path/to/target dependency-rule plan redis cross-case \
  --evidence-id <current-dirty-cluster-evidence-id> --rule-id tauth-token-time \
  --source-evidence 'app/services/tauth.py: module cache retains the token across requests; inspect refresh and expiry'

backend-rewrite --target-root /path/to/target dependency-rule apply <plan-id>
```

The resulting rule adds `replay_scope: recording_run` and retains the source
evidence. Replay loads the selected sibling exchanges into the run inventory
in capture-time order, reports each origin case and rule ID, and consumes each
exchange only once. A later recording with no selected reads still starts:
the rule creates no inventory, and any actual unrecorded target read remains
unmatched. Planning a new rule still requires exact unmatched-request and
recorded sibling evidence. Other Redis commands retain their case scope.
A partial connection lane, a snapshot, or an unsafe response fails validation;
every read in a shared lane must be selected. The recording remains unchanged;
fresh Replay verifies the repaired contract.

If the selected timestamp participates in a signature or a later dependency
argument, simple field translation may not be applicable; source review must
establish that contract before planning. Current support neither re-signs opaque
Redis tokens nor relaxes subsequent dependency matching.
