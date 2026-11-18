# Coordinator Rule Actions

Only the confirmed workflow coordinator plans/applies rules. Require the assigned
API implementer's or repository analyst's Source conclusions and exact proposed
selectors; return semantic questions to the Source owner. Follow the
[shared rule evidence contract](rule-policy.md): relevant
API `rule_hints`, queries, planners and current actions drive the work. Rules live
in the single file named by `project.policy`; default
`.traffic-e2e/policy.yaml`. Declare one global JSON field-format map under
`json.fields`. APIs, SSE data, MySQL JSON columns and Redis values share it;
JSON carriers require no repeated codec declaration. Enable `mysql` for native
DATE/DATETIME/TIMESTAMP metadata inference and use `mysql.tables` only for other
explicit scalar formats by table/column without repeated database selectors.
Use `redis.keys` for scalar formats, key formats, ordered commands and supported
key-local state behavior; omit resource/database selectors. `http.headers`
formats retain strict presence/count/order; missing SDK headers require a Target
fix, not a policy waiver. Additional uncovered compound behavior stays native. See [global field formats](../../../../../docs/resource-field-contracts.md).
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

The proposal may be one rule, a list, or a full `traffic-policy/v3` authored
document containing global formats, dependency lifetimes and any additional
native `rules`. Ordinary proposals add new fields and append new formats to
existing declarations, preserving the old order and deduplicating exact matches.
Unmentioned fields remain unchanged; `json: {fields: {}}` does not clear them.
Intentional changes, removals or clears use `traffic-policy-change/v1` with
`replace_sections` and the complete desired maps for those sections. Review all
removals. `replace_rules` independently names native replacements and is optional;
see the [shared proposal contract](rule-policy.md).
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
Target IDs and anchor unknown inputs. Generic URL fields use `kind: url` with
`formats: [url]`; decoded query text uses the same global pointer formats.
Verified JWT fields use `kind: jwt` with an optional named `signature` profile;
root `signatures` defines the algorithm and startup key once. The old authored
identity `formats: [jwt]` syntax is rejected; there is no keyless JWT policy mode.
`api` request positions explicitly authorize re-signing; response positions retain
nonce echoes and signed expiry companion checks. For Source-proven compound strings,
encoded content, DOCX fields, generated headers or learned-response addresses,
consult [content formats and carrier bindings](../../../../../docs/content-policy-layout.md)
when the evidence calls for them. Supported multipart boundaries need no policy.
See [signature profiles](../../../../../docs/signature-profiles.md).

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
Source inventory or execution changes invalidate it. A changed matching or delivery contract requires fresh genuine Replay for the
affected API scope. Only genuinely missing Source evidence requires new recording
for its actual origin scope. An independently proved foreign-unused overlay may
reuse the unaffected API's original complete attempt. Continue runnable APIs while refresh
waits. Attribution proofs preserve original unused facts and never invent consumption
or certify behavior under a changed runtime contract. A byte-identical no-op
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

Use the case pattern portion of `repository-analysis` for pre-inventory capture catalog bootstrap. The Source-gap
`route`/`recorder-capture` workflows below remain explicit acquisition owners and
write the same unified policy atomically. They are not value relaxations.

## Redis Key Behavior And Dependency Lifetimes

Declare `state.append: concatenate`, `read_commutation: true`, `state.expire: refresh`
or scalar identity `read_back: true` on a bounded `redis.keys` pattern. No API,
resource alias or database selector is needed. The engine retains actual
endpoint/database/authentication partitions and complete causal Source proof.
APPEND preserves all ordered bytes and read/reset fences; finite nil polling
retains its call counts; explicit state.get permits variable observations and
transient nil permits 0..N nil reads; positive TTL refresh retains exact TTLs; current-ID
read-back cannot borrow a future/deleted identity. Historical reads before an
owned successful SET stay finite. Inspect the earliest Target admission error.

`commands` lists ordered Redis operations. Selected scalar time arguments use
one format; script operations retain exact script digests. Optional `key_format`
describes a generated wildcard key segment. Complete JSON values always use
root `json.fields`. Do not author bindings, shared clock groups or relations.
See [key declarations](../../../../../docs/redis-key-contracts.md),
[APPEND](../../../../../docs/redis-append-stream.md),
[read-back](../../../../../docs/redis-read-back.md) and
[state contracts](../../../../../docs/redis-state-contracts.md).

A redis_loop_state hint identifies a possible Source loop, polling/retry body or
debounce flush. Have the implementer prove the full condition, body, writers and
cleanup before selecting each key-local effect. Business writes remain required;
allowed_state_omissions reports skipped nil observations separately from actual
delivery. Use current issue detail evidence for plan/apply and fresh fast Replay.

Keep dependency lifetime classification separate from formats:

```yaml
source_revision: immutable-source-image-v1
localcache:
  requests:
    - redis: {operation: HGET, key: token_v2, field: '3061639762'}
    - http: {host: auth.example.com, method: GET, path: /.well-known/jwks.json}
process_dependencies:
  tasks:
    refresh_signing_keys:
      requests:
        - http: {host: auth.example.com, method: GET, path: /keys/}
```

Use actual logical Source task names; one task may contain requests from several
protocols. `localcache.requests` declares finite initialization dependencies, not
cache objects or blanket reusable responses. HTTP lifetime entries require a
host, and actual observed ports remain paired. MySQL process requests keep
precise SQL selectors and transaction boundaries. Each proposed entry supplies
independent Source proof; runtime output omits evidence metadata. These
classifications do not implement initial load, refresh, fallback or readiness
state in Target. `async_api` separately records one finite asynchronous case
through its configured end resource, dependency failure or engine deadline.

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
the file named by `project.policy` and requests a consolidated recording refresh.
`status` restores pending apply commands. Workers return the
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

## Independent Dependency Attribution

The repository analyst alone investigates disputed or unknown Source ownership.
When the implementer flags unused Source UUIDs with the current method evidence
ID and a bounded factual reason, submit the `claim_command` returned by
`dependency-attribution show --api <canonical-route>`. Those inputs are enough
to request analysis. The analyst owns tracing the true trigger, proving or
rejecting the return, and assessing the applicable lifecycle rule.

For `dependency_attribution_required`, dispatch the returned assignment to the
read-only repository analyst. Dedupe by assignment ID and generation.
This action is only for concrete ownerless Source occurrences or returned
ownership disputes. All ownerless occurrences need effective process/async-API
rules and positive attribution before formal Replay; empty review does not
release the gate. A new batch with known owners needs no attribution analyst.

For an unused ownership return after a premature client transport end,
`context.client_abort_origins` identifies earlier Source candidates. The
analyst may prove an origin separated by multiple Cases. A detached business
task still needs its applicable async rule. A proved disconnect path uses the
engine rule `engine.client_abort_tail:v1` and exact claimed UUIDs. Follow the
returned Replay obligation for the changed origin scope.

A report of missing traffic already claims ownership for its API. Keep that
diagnosis with the existing implementer: require its own async lifecycle rule or
an exact recording omission and interception/response-IP-URL rewrite inputs.
`investigate` retains authenticated Target requests as API-owned work; use the
returned `show --api` view and coordinator `resolve` command to publish that
implementer's conclusion. When foreign ownership is suspected and only a Target
observation is available, keep its observation and evidence IDs as unresolved.
The engine currently requires concrete unused Source UUIDs to open an ownership
claim. Keep the disputed ownership analysis with the repository analyst.

Use `dependency-attribution rules` for effective task/lifecycle group identities
and the async `scenarios` with their current triggers and ends. Inspect other
relevant declarations in `project.policy` and include them in the analyst
assignment. After tracing the Source branches,
retries and cleanup, require an explicit rule assessment alongside the ownership
proof. Keep the assessment and any rule proposal in the analyst's accompanying
result; the `dependency-attribution/v3` submission keeps its existing schema:

- An existing rule covers the actual trigger and analyzed ending path: reuse it. No
  byte-identical plan/apply is needed merely because another batch needs proof.
- A rule is missing or its trigger/end is incomplete, and Source proves a
  supported correction: obtain the smallest rule proposal and its Source
  justification. For an async API, require the completed ownership analysis to
  produce end templates, necessary reply/message conditions and occurrence counts
  from the complete effective Case tail. Count from Case admission and retain
  the original occurrence references in the accompanying evidence. Declare only
  trigger conditions and alternative end resources, not intermediate requests.
- Source does not establish a supported ending condition, or an adequate rule has an
  execution gap: retain the concrete limitation and use ordinary independent
  per-occurrence attribution where supported. Keep effective rule bindings,
  Source proof and genuine Replay/capture obligations. Policy or engine repair
  does not introduce an additional gate on that existing fallback.

Do not accept an async attribution handoff that omits its rule assessment. A new
tail requires either the minimal proposal or a concrete explanation of existing
coverage/unsupported evidence. Author rules under `recording.async_api`, before
independent optional `recording.case_paths`; the logical `async_api` replacement
section and `capture.async_api` identity are unchanged. Do not also emit the legacy
root spelling. This follows ownership analysis; it does not make
the proposed end the proof of ownership. Once all ends have matched, close new
admission immediately and drain admitted requests, without a silence interval;
a single end follows this same rule. Partial matches permit a fixed one-second probe.
A subsequent relevant request start cancels closure eligibility until another
fresh end matches; silence alone cannot restore it. Probe closure requires no relevant
request in flight. Only unambiguously process-owned requests are ignored. There
is no absolute deadline while waiting for the first or next end after the
complete primary response. Without a fresh end, five continuous minutes of
relevant business I/O silence and no relevant request in flight close the Case
normally with completion unobserved, keeping Source running for rule analysis.
Real business activity restarts that interval; writer queues and definite process
traffic do not. The primary HTTP transport timeout remains separate; explicit
shutdown or actual capture failure can interrupt observation.
No window configuration or all-of grouping belongs in the proposal. Native Redis
nil uses `when_response: {kind: nil}`; omit the condition for any successful reply.
PUBLISH message fields remain under `when_message`.

For a supported correction, publish the Source-proven process/async rule through
unified rule plan/apply before applying the attribution proof. Merely binding an
existing rule does not close a diagnosed missing or incomplete rule proposal.
Use the context's exact `rule_planning` Source-only evidence token and command;
no actual Replay is required to obtain that planning evidence. Review and apply
the returned plan, obtain fresh attribution context, and bind the analyst's
submission to its exact policy fingerprint, rule IDs, Source inventory and
expected revision. Rebind the already established analysis; fresh transaction
identities do not require repeating it. Do not reuse the pre-apply context, fabricate API attempts or
apply value waivers through attribution planning. Names or exclusion evidence
alone cannot authorize a pass.

`dependency-attribution show --api <canonical-route>` is the factual Target view
for all method contracts, hypotheses, original Source IDs, actual unmatched
Target IDs, receipts and pending origin obligations. Follow every pagination
command. Resource/operation discovery is an investigation hint; all actual
requests still require strict matching. `ai-verified` is engine-issued for a
complete unused-only real attempt whose foreign occurrences have independent
positive ownership proof. It does not close original-owner obligations or the
whole batch. Do not re-record an unrelated API merely because an async rule was
added elsewhere. Close an origin obligation with `dependency-attribution verify`
only after its actual required execution/capture; process/startup closure belongs
to strict WholeSource execution. A workflow-contract receipt leaves that debt
pending. A `claim_rejections` result withdraws only a mistaken
claim; its negative Source proof leaves original dirty execution facts and cannot
authorize a pass.

After final candidate review, follow `BatchReplay` for one actual complete final
workflow-contract session. Method results come from that same session. The current sealed Source
run must be complete and must contain every required workflow method; scoped
recapture cannot erase the durable method requirement. Inspect actual batch
requests through `dependency-attribution batch` pages and explicit session-bound,
bounded `target` queries. Do not publish private queried values in summaries or
equate authenticated observations with Source ownership or consumption. Only the
engine's current complete-session receipt closes final batch verification. See
[dependency attribution](../../../../../docs/dependency-attribution.md).

For a policy update after ordinary API completion, `verification request --focused
--api <route> --reason <policy-change>` requests fresh API Replay without entering
final acceptance. It can also retire idle final admission blocked on recording
completeness. Follow its returned action; preserve the complete final Source gate,
active repair issues and all outstanding obligations. See
[Redis state contracts](../../../../../docs/redis-state-contracts.md).
