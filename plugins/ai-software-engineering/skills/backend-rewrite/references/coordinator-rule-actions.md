# Coordinator Rule Actions

Only the confirmed workflow coordinator plans/applies rules. Require the worker's
Source conclusions and exact proposed selectors; return semantic questions to the
Source owner. Rules live in the single file named by `project.policy`; default
`.traffic-e2e/policy.yaml`. Declare one global JSON field-format map under
`json.fields`. APIs, SSE data, MySQL JSON columns and Redis values share it;
JSON carriers require no repeated codec declaration. Enable `mysql` for native
DATE/DATETIME/TIMESTAMP metadata inference and use `mysql.tables` only for other
explicit scalar formats. Keep additional contextual/stateful behavior under
`rules`. See [global field formats](../../../../../docs/resource-field-contracts.md).
At the first relevant mismatch, inspect the existing global paths and require
Source-proven time/identity formats or unordered semantics. An identity rule
only describes a format; correspondence is maintained internally from complete
typed Source values. A missing mechanical draft does not postpone a valid proposal.
See [unified rule contracts](../../../../../docs/unified-rule-contracts.md) and
[worker diagnosis](api-implementer-rule-diagnosis.md).

## Unified Rule Transaction

All value, stateful, input, ownership, sharing and acquisition effects use:

```text
backend-rewrite rule plan --file rule.yaml --evidence <current-evidence-id>
backend-rewrite rule apply --plan <returned-plan-id>
```

The proposal may be one rule, a list, or a full `traffic-policy/v2` authored
document containing `json`, `mysql` and contextual `rules`. A supplied `json`
or `mysql` section replaces that whole section atomically; omission preserves
it. `json: {fields: {}}` clears JSON formats. Legacy resource/response amendments
retain their supported additive semantics.
Review affected surfaces, immutable Source scope, complete coverage, staged
relationships, strict remainder, residual failures and verification obligations.
Discovery drafts prefill observed selectors and request missing Source facts;
a candidate never authorizes its own proof. PB requires actual typed schema
bindings. Do not guess clock units, a timezone, a key source or random permissions.

For ordinary JSON fields, declare each root-relative pointer once with
`kind` and `formats`; time always uses relative differences. Identity formats
may include literal prefixes. Equal complete typed Source IDs must remain equal
in Target across supported fields and carriers, while distinct IDs cannot merge.
The engine establishes that correspondence internally. Reads reuse established
Target IDs and anchor unknown inputs. Derived keys/URLs, hashes, signatures and
finite state retain additional typed effects and evidence requirements.

Use `mysql.tables.<logical-name>` with a physical `pattern` and column `fields`
for explicit scalar identities or formats that native metadata cannot infer.
Do not add API, SQL-template or value-ordinal copies of a global JSON strategy.
Known PB schemas remain explicit; unrecognized encoding compares exact bytes.
Review system-wide Source coverage and independent Target evidence after global
changes. Missing Target evidence requires genuine Replay. Calendar dates retain
an explicit format `utc_offset` where local-date semantics require it.

Discovery is paged independently from complete plan coverage. Follow
`pagination.next_page.command` for omitted candidate/Source-location summaries
and `pagination.next_scan.command` for remaining observations, including long
SSE streams. Counts describe one bounded scan window. Inspect the separate
`source_entry.location_count`/`summary_omitted` and explicit
`bounded_analysis.nonresumable_limits`; an empty page does not prove a missing
capability. Continuations reject an obsolete active issue. Supported dependency
capability hints still require independent Source conclusions and full planning.

For SSE, discovery's `source_entry.locations` locates observed data, but
ordinary field formats belong in the same global JSON map used by other
carriers. Nested terminal output may need a distinct root-relative pointer.
Event presence, order, envelopes and unselected text remain strict. See
[SSE value contracts](../../../../../docs/sse-value-contracts.md).
When `policy_freshness.requires_fresh_replay` is true, follow its refresh command
and scheduling gates before planning; discovery observations remain diagnostic.

Apply only the returned reviewed plan. Concurrent policy, evidence, key, schema,
Source inventory or execution changes invalidate it. A changed rule requires
fresh genuine Replay before acceptance; capture and snapshot changes additionally
return consolidated Recording requirements. Continue runnable APIs while refresh
waits. Reclassification preserves original unused provenance and never certifies
old Target behavior under a changed runtime contract. A byte-identical no-op
neither reorders rules nor creates a rerun obligation.

Pending plans block verification admission. After an interrupted apply, follow
`rule recover` exactly: the engine checks the recorded write intent and current
policy before rollback/retirement. A foreign policy edit keeps recovery blocked;
never overwrite another author's changes or delete state. Old serialized plans
are retired by this same recovery path; the `dependency-rule` command and old
flag-specific authoring APIs are unavailable.

Planning may run while a different API is replaying; use its completed published
evidence. The API route currently reserved/running cannot supply old-attempt
planning evidence. Plans remain independent of unrelated API progress.

If Apply returns `traffic_e2e_report.status: wait_required`, keep the reviewed
plan: it has not been applied or queued for automatic application. Follow the
returned status command. After the current complete Replay attempt finishes,
the engine pauses `auto_next` and returns `plan_apply_required`, whether that
attempt passed or now requires implementation. Review and execute the returned
Apply command, then continue with `next` and its normal configuration commit and
verification gates. Stale plans return recovery guidance. Preserve failed API
issues; applying a rule does not establish a pass or replace implementation work.

Use `case-pattern` for pre-inventory capture catalog bootstrap. The Source-gap
`route`/`recorder-capture` workflows below remain explicit acquisition owners and
write the same unified policy atomically. They are not value relaxations.

## Redis APPEND Streams

For Source-proven nonempty APPEND buffering, use `effect.kind: redis_append_stream`
with an explicit Redis resource/database and key selector. Require ordered
byte concatenation and observation/reset boundary proof; differing chunk sizes
alone are insufficient. Complete Source preflight checks cumulative RESP lengths
and preserves fresh Replay obligations. Other calls, including expiry refreshes,
retain ordinary finite matching. See [APPEND streams](../../../../../docs/redis-append-stream.md).

## Redis Independent Polling

For Source-proven cancellation polling concurrent with unrelated writes,
`effect.kind: redis_read_commutation` permits finite nil GET observations to
cross their incidental connection order. Require an explicit Redis
resource/database and key selector plus the independent-task Source proof.
Complete preflight rejects non-nil reads, mutations, ambiguous key access and
stateful read lanes. Every recorded read remains required; this does not
authorize optional or extra polling. Use the unified plan/apply transaction and
fresh Replay before attributing any remaining count mismatch. See
[finite read commutation](../../../../../docs/redis-read-commutation.md).

## Redis Read-back

Global JSON and scalar MySQL identity formats provide mapped same-Case read delivery
and unknown-input anchors. For additional native Redis write-then-read flows,
update the existing `identity`
or `redis_sequence` rule with `effect.read_back`; do not duplicate its capture
or introduce a Target cache to compensate for a recorded generated ID. Require
the worker's exact same-key write/read Source proof and selected fields. GET
can return the matched SET value; LRANGE can return selected RPUSH/LSET JSON
fields. Planning requires positive complete Source witnesses and Apply retains
fresh Replay obligations. See [Redis read-back](../../../../../docs/redis-read-back.md).

## Recorder Capture

Use this route only after the worker proves that source code consumes one exact
response-driving endpoint absent from recorded dependencies and returns one
source file/symbol proof. The hostname is required; the port is optional and
should be included when source evidence proves it.

Run:

```text
backend-rewrite route \
  --cause missing-recorded-resource \
  --evidence-id <returned-evidence-id> \
  --endpoint <source-proven-hostname[:port]> \
  --source-ref '<single-line source file/symbol proof>'
```

The route reverse-resolves the hostname through configured Breeze snapshots,
accepts only one canonical resource, and verifies that the resource is not
already captured. A source-proven port may disambiguate resources sharing a
domain. Shared or unknown domains, already captured resources, and IP literals
are rejected; never supply a guessed Breeze descriptor or resource name. A
successful route returns the ordinary recorder-capture plan report and does not
enter `system_repair_required`.

Execute the exact returned apply argv. Apply is immediate, add-only, atomic,
and stale-safe. If serialized Replay verification is live, inspect
`status` and wait before retrying. A successful apply reports
`recording_refresh_pending=true`, lists waiting APIs, and returns either another
API's next command or the consolidated external recording requirement. For a
scoped waiting API, poll current `status`; never execute its stale acceptance.

After capture apply, continue runnable work and
read [coordinator-recording.md](coordinator-recording.md) when the engine
returns the consolidated refresh.

## HTTP Response URL Capture

For a source-proven IP omission, run the defect preflight using current issue
evidence and the source call location:

```text
backend-rewrite route --cause unrecorded-ip \
  --evidence-id <returned-evidence-id> --case-id <case-id> \
  --endpoint <IP:port> --ip-origin http-response \
  --source-ref '<source file:line symbol: address acquisition and missing-call proof>'
```

The preflight returns `accepted: false` and stays outside system repair. With an
unknown origin it requests investigation; static/hardcoded endpoints receive
source configuration/mock guidance. The `ip_capture` evidence correlates the
reported endpoint with recorded response IDs and JSON pointers. This is source
response evidence, not firewall packet evidence. It includes no full URL query,
credentials or unrelated response body.

Execute the returned `applicable_rule_planners[].command` with the worker's
proven pointer and source-consumption result. Set its required
`BACKEND_REWRITE_SOURCE_EVIDENCE` input to a one-line source file/line/symbol
proof; a field name alone is insufficient. The plan previews the acquisition
rule and returns the exact apply command. Apply persists rules in
the file named by `project.policy`, then follows the same consolidated refresh as
Breeze capture. `status` restores pending apply commands. Workers return the
source inputs; the coordinator performs the state mutations.

For `recorder-capture plan-http-response`, first omit `--pattern-checked`.
Its `path_pattern_review_required` response contains the observed path and
existing rules, but no plan ID or apply command. Send those facts to the source
owner and require a complete method/path pattern and brief proof of URL
consumption and source path construction, even when no previous rule exists.
Repeat the planner with the returned `--path-pattern`, `--source-evidence`, and
explicit `--pattern-checked`; do not infer dynamic segments from path similarity.
The planner takes `--name HOST --path-pattern 'GET /path/*' --pointer /field`,
without separate authority/method arguments or a generated hash name.

A checked plan returns `status: planned`, reuses a covering rule or previews
consolidation of fully covered rules with matching selectors and filters.
Match `traffic_e2e_report.replaced_rules` and the policy diff to the supplied
scope before applying. Both new and consolidated rules use the same refresh.

The preflight does not apply an assertion selector or ignore differences.
Pending capture plans and unresolved supported candidates block capability-gap
submission. If a matching rule already exists, inspect its activation and fresh
recording evidence before reporting the exact remaining engine defect; do not
keep creating duplicate rules or modify historical recordings.

## Evidence And Ownership Invariants

Evaluate gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Dirty dependencies cannot preempt a response mismatch.

Dependency cleanliness is evaluated per active case. Clusters contain
case-scoped unmatched, unsupported, unsafe, and unused-case events grouped by
protocol and endpoint. Each has a stable `cluster_id`, bounded operations, a
representative case, and correlated source pre-readiness count. The complete
recording-global bootstrap and configured process-owned summary is available
only from `source_process_traffic`;
`unused_global`, startup context, and case-external target activity do not fail
the case gate.

Process ownership and response causality are independent. A matching
process-owned rule carries no response-state classification and does not
implement destination state. If the worker proves that the dependency drives
state, return its initial-load, refresh, cache, fallback, or readiness repair
to the implementation owner. `initial_load_timeout_ms` only bounds source
recording observation.
