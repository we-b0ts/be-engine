# Rewrite Problem Diagnosis

Use this reference for every `implementation_required` action. Problem
diagnosis is a required rewrite phase, not optional troubleshooting. Its result
chooses the only repair attempted before the coordinator-issued acceptance.
Select the diagnosis path from `action.details.work_scope.kind` before reading
work-item evidence.

## Contents

- Work-scope contract
- Process-output issues
- API evidence queries
- Response, missing-recording, cache, runtime, and Replay issues
- Dirty dependency and comparison issues
- Repair routing and blocker criteria

## Work-Scope Contract

The coordinator supplies the active issue identity and work scope in
`action.details`. After the state-machine coordinator confirms the current dispatch,
execute the single `action.commands.evidence` command. Its overview returns the
complete bounded issue in `facts.issue`, including possible causes and a
representative when available. Treat possible causes as hypotheses. Scoped
status restores this compact action and evidence entrypoint, not diagnostics.
The sole acceptance command is
`action.commands.acceptance`; return it unchanged to the orchestrator and never
execute it as a worker. In both worker roles, prove one cause from source and
target code, make one coherent repair, and run focused local tests.

For `work_scope.kind=api`, exact further evidence-query argv are under the
overview's `queries`. Traffic facts come only from the overview, returned queries
and immutable artifacts. Standard and comparison artifacts are readable,
read-only diagnostic evidence. Start from the representative `case_dir`
returned by the coordinator and inspect its complete contents. Inspect other
cases under `.traffic-e2e/local/artifacts/` only when they help distinguish
hypotheses. Use bounded coordinator queries before inspecting
`.traffic-e2e/local/runtime/`.
Runtime inspection is read-only and diagnostic: do not infer the active run by
recency, edit state, or use ad-hoc scripts to recreate a coordinator query.
Never patch multiple speculative categories in one iteration.

For an API work item, evaluate gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Select the active issue's largest bounded cluster and representative. Preserve
the distinction between a present JSON `null`, a missing Pointer, unavailable
evidence, and a non-JSON body. Map key order and JSON formatting are already
ignored. Array order, type, presence, empty string, and scalar value remain
real differences until source evidence proves otherwise.

The response, dependency, Replay, and comparison sections below apply only to
API work items. A process-output worker follows the next section and returns
after completing that diagnosis path.

## Process-Output Issues

For `work_scope.kind=process_output`, execute the single
`action.commands.evidence` command after dispatch confirmation. The overview
has no API `queries`. Start from `facts.issue.comparison_observation`, which
identifies the process-output ID, configured path, classification, comparison contract, and source/target
presence. Do not look for an API representative or `case_dir`, execute API
evidence queries, inspect dependency traffic, or invent a recording operation.

For a missing metrics profile with source present and target absent, trace the
ordinary product output path:

```text
configured output -> component loading -> initialization -> startup -> write
or flush -> observation timing -> shutdown
```

Confirm the configured path and source-side presence from the overview, then
inspect the corresponding source and target component wiring.

When `comparison_observation.rule_candidate` names
`allow_target_missing`, first inspect the source startup/configuration and
indirect-emitter paths described by the candidate. The candidate is not an
allowance. Return its `metric`, a dependency path ordered from the direct
dependency to the indirect emitter, and one structured `emitter_evidence`
object only when source code does not start the interaction and the interaction
does not affect source behavior. `emitter_evidence.inspected_paths` must name
the source and dependency source paths actually read, and `description` must
explain why the indirect dependency emits independently without affecting
source behavior. Do not include boolean eligibility fields. If either
eligibility condition is not proven, do not return rule inputs; repair the
target's normal startup, configuration, output creation, flush, or shutdown
behavior.

Do not create a replay-only file, copy a recorded output into the target, or
make target code read coordinator artifacts.

For a target repair, return the exact work scope and issue ID, proven cause,
changed files and shared impact, patch or commit, local test results, unchanged
acceptance command, and unresolved risks. For an eligible rule candidate,
return the same work scope and issue identity plus only the three requested rule
inputs and unresolved risks; no target patch or local test is required. The
main orchestrator owns rule planning/application and acceptance; the worker
does not run process-output comparison itself.

## API Evidence Queries

Run only query IDs returned by the overview's `queries` or a subsequent
evidence report:

| Problem signal | Evidence | Command |
| --- | --- | --- |
| Response differences need complete case context | `case_response_differences` | Execute the returned evidence command whose query ID ends with `case-response-differences-...-page-0`. |
| Case-scoped dependency evidence is dirty | `dirty_clusters` | Execute the returned evidence command whose query ID ends with `dirty-clusters`. |
| Startup, background refresh, or local-cache state may affect behavior | `source_process_traffic` | Execute the returned evidence command whose query ID ends with `source-process-traffic`. |
| Target startup or lifecycle failed | `target_runtime_diagnostics` | Execute the returned evidence command whose query ID ends with `target-runtime-diagnostics`. |

Always execute the exact opaque command returned by the current action or
evidence report. The suffixes above are discovery labels; never reconstruct a
query ID.

- `case_response_differences`: for a response issue, the first entry in the
  overview's `queries` returns one fixed-size page of every structured response difference in the
  representative case, including normalized Pointer patterns and explicit
  expected/actual value presence. A case that produced no usable target
  response assertion evidence appears as one `response_unavailable` difference
  at `$response`, not as zero response differences. Its optional
  `unavailable_reason` is an observed transport classification: for example,
  `target_connection_closed` proves that the target-side HTTP connection ended
  before a complete response, but does not by itself distinguish a panic from
  another target abort. Execute the first page before changing target code.
  When more differences are needed to distinguish a coherent cause, execute
  only the exact `facts.next_page.command`; never construct a cursor;
- `representatives`: the representative case ID, exact immutable standard or
  comparison `case_dir`, and bounded structured response or dependency
  difference; it does not prove the cause;
- `source_variation`: source values across recorded cases; variation alone
  does not prove nondeterminism or cache ownership;
- `collection_equivalence`: array multiset equality; equality does not prove
  that source order is irrelevant;
- `dependency_correlation`: response outcomes against dependency cleanliness;
  correlation does not prove response causality;
- `source_process_traffic`: recording-global, bounded source bootstrap and
  configured process-owned traffic grouped by protocol, endpoint, and
  operation, including Redis snapshot counts. Timing, frequency, and configured
  rule matches do not prove response causality or replace request-owned target
  behavior;
- `dirty_clusters`: case-scoped dirty events grouped by protocol and endpoint,
  with a stable `cluster_id`, bounded operation counts, an exact representative
  case, and a correlated source pre-readiness count. The complete
  recording-global source-process summary remains in `source_process_traffic`.
  It excludes `unused_global` and case-external target activity, and does not
  prove request or process ownership. For a dependency issue it also returns
  `applicable_rule_planners` only for supported protocols present in those
  clusters. Whenever a supported dependency-value rule exists for a protocol
  present in the clusters, it separately returns `rule_hints` with a short
  applicability hint and an exact read-only help command. Rule availability
  does not prove applicability. It also returns the selected case's exact
  `representative_dependencies_command` when available;
  MySQL supports source-proven process-owned SELECT templates with exact
  connection identity and exact, numeric-series, or patterned physical tables,
  including `AS {{table}}_id` aliases tied to the selected table. Return the
  source-proven selector inputs to the state-machine coordinator, which plans and applies
  the rule to reclassify existing unused evidence without a new recording;
  target unmatched queries and incomplete evidence remain dirty.
- `policy_applicability`: structural rule eligibility; eligibility does not
  authorize a rule;
- `attempt_delta`: convergence against the previous attempt; improvement does
  not identify the cause.

Use the smallest query set that can distinguish the current hypotheses. Then
inspect the representative case and trace the corresponding source and target
path. Read other artifact cases only when the representative is insufficient.
Do not run every query merely because it is available.

### Supported Protocol Rules

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

For dependency topology, execute the representative result's
`dependencies_command`, or the dirty-cluster result's
`representative_dependencies_command`. The compact summary groups by target and
returns one exact `detail_command` per target. Execute only the relevant target
detail before reading raw `dependencies.jsonl`; do not recreate this projection
with Python or shell parsing. The tool reads the recording internally; raw-file
inspection is only needed when omitted or truncated facts block the diagnosis.
The detail contains bounded representative MySQL
exchanges with SQL (up to 8192 bytes), typed parameters, database, username,
attribution, result status, row counts, column names, warnings, and an original
record locator. It omits row payloads and explicitly marks truncated previews
and omitted examples. Redis details preserve each key/argument/response
association, and Memcached details preserve key/outcome associations. A dependency response preview is at most 256 bytes
and carries its encoding, original length, and truncation state. Memcached flags
are intentionally neither interpreted nor returned. Complete small Redis scalar
responses also carry a decoded `response_value`; larger or structured responses
retain only their bounded frame preview.

Only a dependency event attributed to an active case participates in that
case's cleanliness gate. Treat source pre-readiness traffic as reference for
startup jobs, warmup, and local-cache hypotheses. Do not repair, suppress, or
re-record traffic merely because the same endpoint appears during startup.

## Response Issues

Execute the returned `case_response_differences` first page before changing
target code. Use the API-level `response_diagnosis.failure_clusters` to select
the largest coherent cluster, and inspect additional returned pages only when
the first page does not distinguish its cause. Do not interpret matching
Pointer patterns alone as proof that the differences share one implementation
cause.

Use the recorded request, expected response, dependencies, and structured
response difference from the representative case to trace response
construction backwards:

```text
response field/status -> target construction -> local state/cache -> client
call -> framework wiring -> configuration -> external dependency
```

Classify exactly one cause:

- `target_behavior`: source and target construct stable behavior differently;
- `target_environment`: authentication, startup input, request context,
  readiness, CA, port, or client wiring differs;
- `local_cache/runtime_state`: cache lifecycle or process-local state differs;
- `dependency_behavior`: the target calls, selects, or consumes a dependency
  differently;
- `intentional_nondeterminism`: source code proves current time, duration,
  UUID, or random generation; nonce and random salt are uses of `random`, and a
  derived scalar uses its root mechanism with the derivation in source evidence;
- `unordered_contract`: source collection type and API contract prove order is
  irrelevant and bounded evidence proves equal contents;
- `comparison_counter`: source ownership and type prove a live counter that is
  valid only for comparison policy;
- `missing_external_evidence`: one exact required external value or exchange is
  absent and cannot be derived without invention.

Environment handling is not limited to this failure classification. If source
analysis proves during implementation that target logic requires an
application-owned environment variable, follow [startup.md](startup.md)
immediately and return the startup input without waiting for a runtime failure.

For a status mismatch, inspect authentication/preconditions, source error
mapping, boot/request context, and dependency-driven branches before inspecting
body-field policy. For array order, prove both equal contents and a source
ordering contract; map/set iteration is a hypothesis, not proof.

## Missing Recorded Dependency Evidence

Treat a recording omission as a bounded hypothesis when a response, Replay, or
comparison difference traces through source code to one exact response-driving
backend endpoint, but the representative recording contains no corresponding
dependency target or exchange. The absence alone is not proof of Breeze bypass,
an external-data blocker, or a Recorder capability gap.

Prove the hypothesis in this order:

1. Trace the differing response field or status through source construction,
   cache/loading lifecycle, and the exact dependency client call. Identify the
   source-proven hostname and port when source configuration proves one.
2. Execute the representative `dependencies_command`, inspect any potentially
   equivalent returned target detail, and read raw immutable dependency
   evidence only when the bounded projection cannot establish presence or
   absence. Do not infer omission from a truncated preview or one empty
   protocol cluster.
3. Exclude a target call-topology defect, a legitimate source cache/snapshot
   path that made no dependency call in the recording lifecycle, an equivalent
   endpoint recorded under another resolved target, and unsupported Replay of
   evidence that is actually present.

When those checks prove that the source consumes an exact response-driving
endpoint that is absent from recorded dependencies, return the evidence ID, the
`hostname[:port]`, and one single-line source file/symbol proof to the
orchestrator. The hostname is required and the port is optional; include a
source-proven port when available. Never guess a Breeze resource or descriptor.

The orchestrator reports those facts through `backend-rewrite route --cause
missing-recorded-resource`. The coordinator resolves the endpoint through the
configured Breeze snapshots and verifies that the unique resource is currently
bypassed. A successful route returns an API-scoped recorder-capture plan instead
of entering system repair: apply its exact next command, park that API as
`awaiting_recording_refresh`, continue other runnable APIs, and let the
coordinator schedule one consolidated full-scope recording after they drain. If
the endpoint is unknown, ambiguous, or already captured, retain the exact
source/recording proof and returned error and continue diagnosis. Use
`recorder-capability-gap` only when the required capture mechanism itself is
unsupported.

## Redis Connection Pool Differences

Ordinary Redis GET/MGET and other supported data commands do not require the
target to reproduce source connection counts, pool sizes, or per-call client
creation. Replay matches across physical connections while preserving exact
endpoint, database, authentication identity, RESP version, arguments, source
lane order and finite exchange counts. Keep normal target connection reuse;
this capability needs no rule or fresh recording.

If ordinary reads fail only because one pooled target connection spans several
short recorded connections, investigate an old engine or a replay capability
gap. Do not change target code to create one Redis client per read or separate
pools solely to satisfy physical lane matching. Inspect the returned Redis
dependency details for true session constraints: a source lane containing
transactions, subscriptions, blocking operations, scripts or unknown commands
retains whole-lane binding, and its remaining exchanges cannot move to another
target connection. Authentication/database differences and missing, extra or
out-of-order calls remain target behavior issues when proven by source evidence.

## Rejected Egress And IP Capture Preflight

When response/dependency verification fails, the issue overview's
`facts.issue.egress_rejections` and `dirty_clusters` may report REJECT packet-count deltas and sampled time
windows. Treat these as investigation leads: they identify no IP or origin,
include retries/background traffic, and do not prove response causality. A null
count means the read or rule generation was unavailable, not zero rejections.
A clean passing run needs no investigation based only on these counters.

Follow `rule_hints[].help` to discover response URL rewriting. Trace the source
call and the missing dependency before submitting a system defect. Return the
current evidence ID, case ID, literal IP:port and source citation to the
coordinator, which runs `route --cause unrecorded-ip`. The route returns missing
inputs or `ip_capture` evidence. For a source-proven `http-response` origin,
matching JSON fields produce `applicable_rule_planners` commands. Complete
plan/apply and verify the consolidated fresh recording before escalating a
remaining engine defect. Static/hardcoded addresses require source
configuration or a source mock. Unknown origins require investigation; do not
invent a response pointer. A matching IP in recorded JSON alone does not prove
source consumption or the absence of an equivalent recorded endpoint.

## Local Cache And Runtime State

A response-affecting local cache is target behavior. Preserve source cache:

- key construction and namespace;
- miss and negative-cache behavior;
- warmup and readiness relationship;
- expiry, refresh, and stale-value behavior;
- bounds and eviction;
- concurrent load/coalescing behavior;
- fallback when the backing dependency fails;
- process restart and snapshot semantics.

Prove the complete path:

```text
response -> cache read -> key -> hit/miss branch -> loader dependency ->
write/refresh -> readiness or request lifecycle
```

Use `source_process_traffic` only to prioritize source startup schedulers,
background refreshers, and cache loaders for the returned endpoints. An absent
endpoint is not proof that no process-local cache exists, and a high interaction
count or configured process-owned match is not proof that the traffic populates
a response-driving cache.

Do not apply a generated-scalar rule for a cold, missing, stale, differently keyed,
partially loaded, or differently refreshed cache. Do not materialize recorded
cache results as target fixtures or boot configuration. Repair the target cache
or its genuine dependency path and rerun the same immutable group.

## Target Runtime Issues

When no response assertion completed, inspect the bounded lifecycle error and
then the normal target boundary:

1. compile and launch path;
2. supplied boot/config roots and source-compatible loader, including declared
   static startup files and directories mounted read-only at their original
   absolute source paths from `.traffic-e2e/local/startup/mounts`; these runtime
   inputs may contain configuration required during startup or request
   handling;
3. configured port and readiness endpoint/status;
4. Replay CA trust and dependency client construction;
5. container identity, foreground process ownership, and bounded `SIGTERM`
   shutdown behavior; and
6. runtime-writable directories. When logs contain `Permission denied` or
   `EACCES`, confirm each image-local path exists and is writable by numeric
   UID/GID `998:998`. Repair both `Dockerfile.recording` and `Dockerfile.e2e`,
   for example:

   ```dockerfile
   USER 0:0
   RUN install -d -o 998 -g 998 -m 0775 /data1/weibo/data
   USER 998:998
   ```

   Do not recursively change ownership of configuration or credential trees;
   runtime-provided writable mounts do not require image-layer ownership.

Repair product startup, composition, configuration loading, or
`.traffic-e2e/Dockerfile.e2e`. Do not add case execution, report parsing,
Replay control, or expected-response access to the target repository.

## Replay Issues

`replay=incomplete` means the coordinator did not publish complete lifecycle
evidence. Use the returned issue and dirty-cluster query to distinguish:

- target never emitted the expected genuine dependency call;
- semantic dependency evidence exists but Replay cannot match or reproduce it;
- interception, readiness, begin/end, finalize, or cleanup failed;
- the recording lacks required semantic evidence.

For the last case, follow
[Missing Recorded Dependency Evidence](#missing-recorded-dependency-evidence)
before classifying a capability gap or external-data blocker.

If target topology differs, repair target behavior. If semantic evidence exists
but the coordinator lacks support, return the current evidence ID, source
reference, and exact required system change to the orchestrator. It owns
`backend-rewrite route` and the coordinator-issued
`repair verify <repair-id>` acceptance. Never implement a target workaround for
a Replay capability gap or supply an arbitrary acceptance command.

## Dirty Dependency Issues

Inspect dirty dependencies whenever the coordinator returns `dirty_clusters`,
including while the active issue is a response mismatch. Response equality is
not a prerequisite for discovering a dependency-value rule. Continue to use
the gate order above when deciding which failure owns the next repair.
Classify the representative protocol cluster by source ownership:

- request-owned and required: repair target call topology or Replay support;
- process-owned and case-independent: use a supported process-owned recording
  rule; separately repair target state behavior when source and response
  evidence prove the dependency is response-driving;
- unresolved: retain the dirty evidence and name the missing proof.

Timing overlap, high volume, scheduler names, unused exchanges, asynchronous
execution, and passing responses do not prove process ownership. A
recording-rule proposal must use
the current dirty-cluster evidence ID and one protocol-specific planner returned
in `applicable_rule_planners`. Run its exact read-only help argv and return only
the source-proven selector inputs to the orchestrator. Replay evidence, case
source, and source revision come from coordinator state and are not rule
inputs. The orchestrator owns `backend-rewrite dependency-rule plan|apply`;
every plan requires `--ownership request-owned|process-owned|unresolved`. A
request-owned result is an explicit target implementation requirement and
never returns an applicable process-owned rule plan. The orchestrator also owns
the apply report's exact `next`; the coordinator then reclassifies the same
focused replay report. Never manually rewrite replay reports, trim traffic, or
edit immutable request/response/dependency capture files.

For dependency value mismatches, inspect each entry returned in
`rule_hints`. Run its exact `help` command, then verify the described value
mechanism in source and in the representative dependency details before
planning it. In the currently supported Memcached case,
`protobuf-timestamp` applies only to a `SET` value whose selected top-level
protobuf varint field is source-proven current Unix seconds. The hint is a
discovery mechanism, not authorization to apply the rule.

## Comparison Issues

For one representative comparison difference, distinguish:

- candidate-only stable difference: target behavior;
- source-before/source-after change at the same Pointer: source change or
  possible nondeterminism requiring source proof;
- proven generated scalar: concrete `timestamp`, `duration`, `uuid`, or
  `random` rule candidate;
- proven equal-content unordered array: unordered rule candidate;
- proven live numeric counter: comparison-only counter candidate;
- cache hit/miss/staleness/warmup: target behavior, never policy.

JSON time rules support array Pointers such as `/data/*/generated_at`.
Timestamp plans require `--timestamp-format unix-seconds`, `unix-milliseconds`,
or `rfc3339`; each value must fall within five seconds of its own captured
request start. Duration plans require `--unit milliseconds`, `seconds`,
`minutes`, or `hours`; the duration increase must equal the request-start time
increase within five seconds. These rules validate parsed values, not just
JSON types, and cannot exempt complete time-derived signatures or URLs.


A target or response-policy change invalidates comparison evidence. The
coordinator must rerun focused E2E before requesting a fresh comparison.

## Repair Routing

Route the proven cause to exactly one action:

- process-output generation defect: repair normal target component loading,
  configuration, startup, write/flush, or shutdown behavior, run focused local
  tests, and return the tested handoff plus unchanged acceptance to the
  orchestrator;
- target implementation or cache defect: change target code under
  [target-implementation-requirements.md](target-implementation-requirements.md),
  run focused target tests, and return the tested handoff plus unchanged
  `action.commands.acceptance` to the orchestrator;
- startup/configuration defect: repair source-compatible loading or the fixed
  start/stop boundary, test it, and return the handoff plus unchanged acceptance
  to the orchestrator;
- supported nondeterminism/order/counter: return source proof and proposed rule
  inputs; the orchestrator owns `backend-rewrite rule plan|apply` and rerun;
- source-proven omitted dependency: return the evidence ID,
  `hostname[:port]`, and source proof; the orchestrator reports
  `--cause missing-recorded-resource`, then owns the returned capture apply and
  coordinator-owned recording refresh;
- true Recorder/Replay capability gap, where the supported planners and engine
  cannot express the required mechanism: return exact route evidence and the
  required system change; the orchestrator owns `backend-rewrite route` and the
  returned `repair verify <repair-id>` action;
- source change or external-data issue: return exact route evidence and the
  required transition without patching the target; the orchestrator owns
  `backend-rewrite route` and its returned acceptance;
- unresolved: gather the named missing source/runtime proof before changing
  code or policy.

Use `blocked` only when source construction, target implementation, wiring, and
available runtime evidence prove that one required external response-driving
value is unavailable and completion would require invention. Repeated failed
attempts, dirty evidence, an empty dependency stream, or a tool failure do not
prove a blocker.

After one API repair, let the orchestrator rerun the entire immutable API group;
after one process-output repair, let it run the returned process-output
acceptance. If two repairs do not improve the active issue, stop adding local
patches and produce a bounded structural replan from the current issue and
attempt delta.
