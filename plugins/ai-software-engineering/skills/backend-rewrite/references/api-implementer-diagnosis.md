# API Implementer Diagnosis

Audience: API implementers assigned an `implementation_required` work item. Read before work-item diagnosis
or code changes. Before edits, read
[target-code-rules.md](target-code-rules.md).
For a proven environment override, mount, or writable-directory requirement,
read [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md).
Use the engine's current
work-item facts to identify one repair before the engine-issued acceptance.
Select the diagnosis path from the assigned work scope and confirm it against
the evidence overview.

## Diagnosis Routing

Query the assigned API scope, then select the diagnosis path from the current
issue and evidence. Read only the relevant specialty document when its signal appears:

| Current issue or evidence | Specialty diagnosis |
| --- | --- |
| Missing recorded dependency, dirty dependency, MySQL or Redis compatibility | [Dependency diagnosis](api-implementer-dependency-diagnosis.md) |
| Rejected egress, local cache, target runtime or incomplete Replay | [Runtime and Replay diagnosis](api-implementer-runtime-diagnosis.md) |
| Source-generated time/random values, non-contractual order, a rule hint, or a possible rule capability gap | [Rule diagnosis](api-implementer-rule-diagnosis.md) |
| Unused dependencies may come from a source-detached API task | [API-triggered asynchronous process traffic](api-implementer-dependency-diagnosis.md#api-triggered-asynchronous-process-traffic) |

An issue may require more than one specialty document to distinguish causes. Follow
the response, Replay, and dependency gate order below when choosing a repair.

## Work-Scope Contract

Start diagnosis with one query for the exact assigned scope against the canonical
Target root. Use that root while editing in a separate worktree.

```text
backend-rewrite --target-root <canonical-root> evidence --api '<assigned path-or-pattern>'
```

The coordinator supplies your role, exact scope, canonical Target root,
absolute worktree and Source repository locations. Report an unresolvable
identity or API gap to the coordinator.

If the engine reports an unconfirmed dispatch, wait for the coordinator's
confirmation and retry this same read-only entrypoint; a worker can start before
the coordinator has completed confirmation. Do not confirm or report yourself.
An unknown scope or a scope with no current issue is an explicit error; report it
to the coordinator instead of implementing from a previous issue.

Read the `attempts` and `failures` for the assigned API. A grouped HTTP route
can include several methods. Keep each observation tied to its method, attempt
and Case. The failure representative provides the compared values and original
evidence references when available. Use `representative.case_dir` for the
recorded Case and the specific artifact paths for other evidence. Investigate a
reported `hints` entry only when its comparison location and Source behavior
make it relevant.

Use the worktree and frozen base in `assignment`. Address any supplied repair
findings and retain their locations and provenance. Keep the original
workflow, recording, scope, issue, binding, dispatch and lease identities for the
return handoff. Check the same scoped entrypoint if the assignment may have
changed. A changed issue or dispatch requires coordinator reconciliation. A
workflow revision change alone does not replace the assignment.

Prove one cause from Source and Target code, then follow
[Return The Proven Cause](#return-the-proven-cause). Use
[API Implementer Delivery](api-implementer-delivery.md) to return the committed
fix. A post-input resume with no further code repair retains the existing
commit.

## Interpret the failure

For an API work item, evaluate responses, Replay completeness and dependency
cleanliness. If an observed dependency rejection interrupted the request,
investigate it first for that Case. Its missing stream events and later unused
dependencies may follow from that interruption. Other Cases retain their
independent causes. Unused inventory alone leaves the ordinary gate order in
place.

Use the representative's recorded request, dependency or response and its
artifact reference. Use the group count and any omission markers to judge the
coverage. Review a referenced runtime log only for the selected attempt. Read
immutable artifacts and runtime diagnostics without editing workflow state or
inferring the active run from directory recency.

Preserve the distinction between a present JSON `null`, a missing Pointer,
unavailable evidence and a non-JSON body. Map key order and JSON formatting
are ignored by the response comparison. Array order, type, presence, empty
string and scalar value remain real differences until Source evidence proves
otherwise.

When a report identifies a Replay interruption, use the failing phase and
referenced runtime evidence before interpreting earlier Case failures.
Return the observed fault to the coordinator with its original attempt and
artifact reference. The coordinator obtains the route-specific evidence and
follows the engine's repair and verification actions.

When a difference traces to iteration over a Set, HashSet, or another collection
with non-contractual order, do not make target code reproduce the order seen in
one recording. Prove from source construction and downstream use that only order
differs, with element values and duplicate counts preserved. Check the current
verification policy and the relevant response or dependency `unordered` rule
before proposing target changes; return exact selectors and source proof to the
coordinator to reuse or plan a supported rule. If order is contractual or the
contents differ, repair the target behavior instead.

## Rule Discovery From Source Diagnosis

Return the Source proof to the coordinator when a typed rule may apply. The
coordinator checks the evidence identity and policy freshness for that proposal.

After tracing source and target behavior, read
[Rule diagnosis](api-implementer-rule-diagnosis.md) for generated identities,
JWT expiry, DOCX/header dates, Redis locks or time values, MySQL result time
shifts, cross-case HTTP initialization, unordered collections, and protocol
value rules. Source proof determines applicability; engine hints are additional
evidence, and their absence does not mean a documented capability is unavailable.

In particular, Redis `time-shift` has no automatic hint. When an earlier matched
Redis timestamp may cause expiry, extra reads, or an error branch, read its
[proof contract](api-implementer-rule-diagnosis.md#rule-discovery-from-source-diagnosis)
and inspect the shared `dependency.response` time contract and explicit delivery
permission. Check `backend-rewrite rule plan --help` and the typed capabilities
before declaring a gap. Only the
coordinator plans/applies rules and runs fresh verification.

## Additional evidence

Use a targeted read when the grouped representative is insufficient. Use the
original artifact reference for the Case or dependency. Ownership-specific
investigations use `dependency-attribution show --api <route>`. Follow the
coordinator's current specialist instructions when they supply a bound
follow-up query.

For a protected dependency witness with an authenticated ID, use
`evidence-detail --api <route> --witness <id> --pointer <json-pointer>`. The result
retains bounded Source and Target values from the current attempt.
`--value-index` selects among carried documents. MySQL pointers address its
native witness envelope. Use `independent_target_observation` to establish
Target generation. Protected interaction recordings can expose an empty public
header map. Use the authenticated recorded header names to check actual
presence.

For an unmatched Redis request with a Target event index, use
`evidence-detail --api <route> --redis-target-event <case-id>:<event-index> --argument-index <index>`.
The zero-based argument index excludes the command. Add `--pointer` to read a
JSON member. The protected result authenticates Target bytes by request
fingerprint. Keep repeated identical observations separate and use their clocks
with the actual interaction close when investigating delayed work.

### Dependency Topology

Start with the relevant Source and Target dependency evidence in the failure.
Inspect the referenced original traffic only when the omission or preview
boundary affects the diagnosis.

Preserve each MySQL exchange's SQL/parameter/session context, Redis
key/argument/response association, and Memcached key/outcome association.
Respect omitted payloads and marked preview encodings/truncation; a preview is
not a complete response. Memcached flags are neither interpreted nor returned.

Only a dependency event attributed to an active case participates in that
case's cleanliness gate. Treat source pre-readiness traffic as reference for
startup jobs, warmup, and local-cache hypotheses. Do not repair, suppress, or
re-record traffic merely because the same endpoint appears during startup.

## Response Issues

Start with the representative response difference and its original Case.
Use additional Cases when the first representative leaves more than one
plausible cause. A shared Pointer identifies a comparison location.

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
- `missing_external_evidence`: one exact required external value or exchange is
  absent and cannot be derived without invention.

Environment handling is not limited to this failure classification. If source
analysis proves during implementation that target logic requires an
application-owned environment variable, follow [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md)
immediately and return the startup input without waiting for a runtime failure.

For a status mismatch, inspect authentication/preconditions, source error
mapping, boot/request context, and dependency-driven branches before inspecting
body-field policy. For array order, prove both equal contents and a source
ordering contract; map/set iteration is a hypothesis, not proof.

## Return The Proven Cause

Return one supported result with its evidence reference, original dispatch,
Source proof, shared impact, necessary coordinator inputs and unresolved risks.

- Target API, cache, or startup defect: make one
  coherent repair, run focused tests, and complete [api-implementer-delivery.md](api-implementer-delivery.md).
- Supported nondeterminism/order: return source proof and exact typed
  rule inputs. Do not apply the rule.
- Source-proven omitted dependency. Return the Case or occurrence reference,
  `hostname[:port]`, Source citation and missing resource proof.
- Recorder/Replay capability gap: after checking supported mechanisms, return
  the exact unsupported behavior, evidence, source reference, and required
  system change. Do not compensate in target code.
- Source change or external-data issue: return exact evidence and the required
  external change without inventing a target replacement.
- Unresolved: return the named missing source/runtime proof and completed
  investigation; do not add speculative code or policy.

Use `blocked` only when source construction, target implementation, wiring, and
available runtime evidence prove that a required external response-driving value
is unavailable and completion would require invention. Repeated failures, empty
dependency streams, or tool errors do not prove that blocker.

Do not return or execute an acceptance command or wait for acceptance. Return
the completed subset with original API/dispatch/lease identities and remaining
assigned tasks; ending a turn does not make the whole slot idle. If two repairs do not
improve the active issue, stop adding local patches and return a bounded
structural replan from the current issue and observed changes across attempts.

## API-triggered asynchronous process traffic

When unused dependencies may come from a source-detached API task, read
[the dependency diagnosis](api-implementer-dependency-diagnosis.md#api-triggered-asynchronous-process-traffic)
for source ownership proof, supported protocol selectors, and strict boundaries.
