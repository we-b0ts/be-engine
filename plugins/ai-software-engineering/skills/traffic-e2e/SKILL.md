---
name: traffic-e2e
description: "Operate and maintain the traffic-e2e engine directly for standalone Source recording, case grouping, genuine dependency replay, response assertion, evidence-backed recorder/replay policy, and engine capability diagnosis. Use for independent traffic operations or a routed traffic-e2e system repair; do not use for ordinary backend rewrites coordinated by backend-rewrite. This skill owns execution contracts and traffic facts, not migration diagnosis, target implementation, sequencing, completion, or delivery."
---

# Traffic E2E

Own direct traffic operations and return bounded engine facts. Do not load this
skill for an ordinary backend rewrite. The `backend-rewrite` skill is
self-contained and consumes the coordinator interface without this operational
context.

Use the `traffic-e2e` binary for the operations in this skill. It intentionally
has no `rewrite` subcommand. Backend migration orchestration belongs only to
the companion `backend-rewrite` binary, which uses the same `traffic_e2e` crate;
do not emulate that coordinator by composing low-level engine commands.

## Boundary

- Recordings are immutable sensitive evidence. Never edit, synthesize, trim, or
  expose them to make a run pass.
- Expected responses are assertion oracles. Target code and configuration must
  never consume expected responses or recorded dependency outputs.
- Replay must exercise genuine target clients and normal target behavior.
- traffic-e2e owns Recorder/Replay, target process orchestration, HTTP request
  execution, assertions, aggregation, and generated local state.
- Standard Source recording uses only `traffic-e2e record`. The project supplies
  `.traffic-e2e/Dockerfile.recording`; its deployment caller builds and starts the container.
  Inside it, record owns Source/Recorder readiness, interception and finalization.
  Redis coordination is optional; without it the service waits for direct traffic.
- The target repository supplies `.traffic-e2e/Dockerfile.target`; traffic-e2e
  owns its build, immutable image selection, lifecycle, namespace, readiness,
  signals, and cleanup. See
  [target-integration.md](references/target-integration.md).
- The engine reports observable cache-related facts but does not diagnose or
  repair target cache semantics.

## Normal Operation

Read only the reference for the active operation:

- Standalone Source recording and evidence handoff: [recording.md](references/recording.md)
- Case grouping: [case-grouping.md](references/case-grouping.md)
- Prepare, run, and recover replay E2E: [e2e-run.md](references/e2e-run.md)
- Discover and authorize unified Source/input/value/native rules:
  [replay-policy.md](references/replay-policy.md)
- Configure source-proven process-owned dependency rules:
  [process-owned-dependencies.md](references/process-owned-dependencies.md)
- Diagnose Replay or protocol engine capability:
  [replay-lifecycle.md](references/replay-lifecycle.md) and
  [dependency-replay.md](references/dependency-replay.md)

Load dependency protocol references only when bounded evidence proves that
protocol is on the causal path. Low-level replay lifecycle and aggregate-report
references are for traffic-e2e product debugging, not normal migration work.

## Operation Boundary

Normal commands print the evidence the operating AI needs. For `run-api` and
`run`, consume only:

```text
status, passed, gates, diagnosis, progress
```

`diagnosis` contains bounded counts, clustered field/kind failures, and one
representative expected/actual observation with explicit presence:
`present`, `missing`, `unavailable`, or `not_applicable`. JSON `null` is a
present value; never report it as missing or infer a dynamic field because two
displayed values look null.

Do not open generated `state.yaml`, `assertions.json`, aggregate reports,
per-case assertion details, replay logs, or raw case bodies during normal
operation. Do not traverse `.active` or `latest`. Those are runner-owned
internal/published storage. Use low-level artifacts only for a proven
traffic-e2e system capability investigation, and then read the smallest file
selected by the relevant diagnostic command.

Treat the result as facts, not migration attribution. For an independent
operation, report the exact command, scope, status, gates, bounded diagnosis,
and whether an engine capability investigation is required. Do not choose a
target repair, migration route, blocker status, or completion state.

## Unified Policy Boundary

`project.policy` names one `traffic-policy/v2` document, normally
`.traffic-e2e/policy.yaml`. Declare one global JSON field-format map under
`json.fields`, independent of APIs, SSE events, database columns and cache keys.
JSON-valued columns are recognized automatically; native MySQL time types use
protocol metadata. Declare otherwise explicit scalar formats under
`mysql.tables.<name>.fields` with a physical `pattern`. Identity correspondence
is maintained internally from complete typed Source values; rules describe
formats only. Retain additional contextual/stateful effects in `rules` and
existing typed resource declarations. See
[resource-field contracts](../../../../docs/resource-field-contracts.md) for
schema, supported carriers, conditions and clock relationships. Current bounded
evidence supplies discovery and capability metadata; it does not supply Source proof. During managed rewrites, the backend-rewrite skill owns the single
`rule plan --file ... --evidence ...` / `rule apply <plan-id>` transaction.
Plans expand the complete rule, protect unselected evidence and expose remaining
Replay, reclassification or recording obligations. Source self-validation does
not create independent Target evidence. Protocol framing, sessions and finite
consumption remain with the protocol owner.

API route-pattern bootstrap retains `traffic-e2e config recorder ...
case-path-patterns`. It updates capture effects in the same policy and preserves
unrelated rules and proofs. Old verification/Source document formats and
codec-specific rule planners are retired.

## Engine Capability Diagnosis

Enter low-level diagnosis only when bounded output identifies Recorder,
Replay, interception, protocol matching, lifecycle, or publication as the
suspected owner. Inspect the smallest relevant engine artifact and protocol
reference. Return the exact engine defect, proposed system change, and
acceptance command. Do not compensate in target code or weaken evidence.
