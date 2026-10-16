# API Implementer Rule Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when source
analysis, current evidence, or a rule hint suggests generated values,
non-contractual order, or a rule capability gap. Use only relevant sections;
the common evidence and handoff contracts still apply.

## Rule Discovery From Source Diagnosis

For a random identity shared across protocols, return one capture (MySQL SQL
template/value index, Redis SET/HSET value, or HTTP dependency JSON pointer),
exact allowed host/port
endpoints and source generator/lifetime proof. `rule plan --dynamic-value`
correlates later decoded references without enumerating every decoded request reference;
format is optional. See [dynamic value rules](../../../../../docs/dynamic-value-rules.md).
For a current-date filename in `Content-Disposition`, return the header parameter,
calendar format, timezone and exporter proof for `rule plan --header-date`.
It checks `filename*` too and retains static filename/header/body assertions;
see [header date rules](../../../../../docs/response-header-date-rules.md).
Only the coordinator plans/applies these rules, followed by fresh verification.

For a JSON expiry or scheduled timestamp generated as current time plus a
source-proven offset, return its pointer, timestamp format, source proof and
observed source/target examples for `timestamp` with `time: preserve_relative`.
The coordinator uses `--timestamp-mode preserve-relative`; default timestamp
rules check the request-time window instead. Relative comparison keeps the
offset from each side's captured request within five seconds, so wrong TTLs
and fixed absolute expiry values remain checked. Existing recordings are reusable.
See [JSON response time rules](../../../../../docs/response-time-rules.md).

Check `facts.policy_freshness` before recommending a plan. If it requires fresh
Replay, keep the source diagnosis and return the structured `refresh_command`
to the coordinator. Any policy edit can stale earlier evidence, including a
rule for another API. The coordinator follows normal review/scheduling gates,
reuses the recording run, and obtains new evidence. Changing evidence IDs or
selectors cannot fix this mismatch; it does not prove an engine capability gap.

For API issues, consult these capabilities after tracing source and target
behavior. Engine hints and mechanical candidates are additional evidence;
their absence does not mean a documented capability is unavailable.

| Proven scenario | Capability and next investigation |
| --- | --- |
| An inbound JWT in a Bearer header or named URL query parameter expired between capture and Replay | JWT `preserve_relative`; inspect the returned `jwt-time-validity` query and prove the exact token location, authentication path, expiry leeway, and signing-key source. |
| A DOCX download differs because OPC ZIP metadata and `docProps/core.xml` creation time are generated per request | DOCX response-body rule; prove the generated XML timestamp in source, select it explicitly, verify that its source-to-target delta tracks elapsed request time, and keep every other decompressed package part exact. |
| Random SET NX ownership tokens differ from recordings, or a script/DELEX references that token | Redis `lock`; inspect `redis_lock_candidates`, prove random tokens and conditional release from source, and return host, port, key selector plus source evidence. One rule correlates all supported references; never remove the lock or independently ignore token arguments. |
| Redis writes differ at a source-generated ZADD score or ZREMRANGEBYSCORE cutoff | Dependency request `time: preserve_relative`; inspect `dependency_request_candidates` from `dirty_clusters`, then return endpoint/key, `commands.argument_values` (ZADD index 1, ZREMRANGEBYSCORE index 2), timestamp format and source proof for `rule plan --dependency-request`. See [dependency request rules](../../../../../docs/dependency-request-rules.md). |
| EVAL/EVALSHA carries generated scalar or JSON ARGV timestamps | Dependency request `time: preserve_relative`, including `unix_microseconds`; prove the exact script digest and raw argument indices (ARGV[n] = numkeys + 1 + n). Select exact JSON pointers inside the ARGV value, preserving KEYS and stable business fields. If Source reads the clock independently at different stages, declare `clock_group` per time field: copies and derived windows stay together, independent reads use different names; omission retains the existing rigid group. Prove each group from Source. See [dependency request rules](../../../../../docs/dependency-request-rules.md#script-json-and-microsecond-timestamp-copies). |
| A JSON PUBLISH message carries a generated completion time alongside a random publisher UUID | Compose a dependency request time contract on an exact channel with the existing PUBLISH UUID binding. Prove the time generator and, for timezone-free ISO strings, the fixed `utc_offset`; do not classify the timestamp as random. Source messages without selected time pointers retain ordinary matching. See [PUBLISH JSON time contracts](../../../../../docs/dependency-request-rules.md#publish-json-timestamps-and-publisher-uuids). |
| A recorded Redis response timestamp makes an otherwise correct cache expire during Replay, causing extra reads or an error branch | Redis `time-shift`; inspect earlier successfully matched GET/HGET responses, including previous cases, and prove their time semantics. |
| A matched MySQL SELECT returns an absolute lease or expiry that is stale during Replay | Explicit MySQL `response_time_shift` through `rule plan --dependency-request`; prove exact UTC result columns and fixed sentinel values. See [MySQL result time shifts](../../../../../docs/mysql-response-time-shift.md). |
| Fast Replay keeps a process TTL cache warm across requests that were farther apart in recording | Currently unsupported. Retain strict unused-dependency evidence and return source-proven TTL semantics as an engine capability gap. |
| Shared HTTP initialization was recorded in another case | HTTP `cross-case`; verify same-run request identity and source sharing semantics. |
| An outbound HTTP array or Redis write collection differs only in order | Protocol-specific `unordered`; prove collection semantics and inspect exact order witnesses. |

The two CLI entrypoints group supported planners; they are not disjoint policy
categories. Both can author `verification.yaml` `dependency_rules`.

| Entrypoint | Examples of supported planners |
| --- | --- |
| `rule plan/apply` | Inbound JWT time translation, response assertions, generated identities (`--dynamic-value`), dependency request contracts and MySQL result time shifts (`--dependency-request`). |
| `dependency-rule plan/apply` | Protocol-specific ownership, cross-case scope, HTTP/Redis unordered values, Redis lock/publish/response time-shift, and MySQL time values. |

Check both `rule plan --help` and the relevant protocol's `dependency-rule plan`
help before declaring a capability gap, even when dynamic candidates or planner
hints are absent. The coordinator plans and applies with current evidence and
source proof, followed by fresh Replay.

Redis `time-shift` has no automatic hint: a numeric value, field name, elapsed
time, extra read, or missing exchange cannot establish business time semantics.
Its documented read-only entrypoint is
`backend-rewrite dependency-rule plan redis time-shift --help`. Return the current
dirty-cluster evidence ID, source-selected endpoint/key/hash-field, response JSON
Pointer, timestamp format, and source proof to the coordinator. Proof establishes
the expiry/cache calculation, units, and downstream uses, including signatures.
An absent `applicable_rule_planners` hint does not rule out this documented
capability. Supply the expiry proof and exact inputs; immutable response matching
alone does not establish expiry causality. Use exact JSON Pointers and explicit
Unix seconds or milliseconds; prove any broader key/field selector shares those
semantics. A signed timestamp or downstream dependency argument needs additional
compatibility proof; this rule neither re-signs Redis tokens nor relaxes matching.

JWT diagnosis uses the failed attempt's time and `signing_key_discovery`, never
the current clock or raw tokens in notes. A 401, missing key, or unverified
signature is insufficient proof. Trace authentication and configuration
precedence; return current evidence, header, supported HMAC algorithm, key alias,
expiry leeway, source proof, and either the effective environment variable name
or read-only mounted dotenv path and field. Existing bindings may be reused.
The capability supports Bearer HS256/HS384/HS512 with integer NumericDate claims;
it preserves relative validity and does not justify weakening authentication.
Do not apply rules or run Replay.

## Supported Protocol Rules

Use this table only to discover a rule worth investigating. A listed rule does
not prove that the observed difference is safe to ignore.

| Problem stage | Protocol | Rule | Repairs |
| --- | --- | --- | --- |
| `dirty_clusters` with positive rejection-count evidence; source-proven `ip_capture` preflight | HTTP JSON | Response URL pointers | Capture later HTTP(S) calls to an IP obtained from an upstream JSON URL; requires source proof and fresh recording. |
| `dirty_clusters` during a response, Replay, or dependency issue | Memcached | `protobuf-timestamp` | A `SET` value mismatch where source proves that one selected top-level protobuf varint field is current Unix seconds; all other protobuf fields must remain equal, and each timestamp must be within the engine-owned fixed five-second window around its own `SET`. |

Run the exact `help` command returned with the rule before planning it. Add a
row only when the corresponding evidence hint, help command, planner, and
runtime behavior are all implemented.

Memcached `SET` exptime is not a protocol rule. Replay already keeps `0` and
relative expirations exact and compares absolute expirations by the remaining
TTL at each `SET`, with a fixed five-second tolerance. Do not plan a rule for an
exptime-only mismatch.
