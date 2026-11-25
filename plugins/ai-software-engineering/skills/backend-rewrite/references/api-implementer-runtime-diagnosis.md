# API Implementer Runtime And Replay Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when
the current issue or evidence concerns rejected egress, local cache,
target runtime, or Replay completeness. Use only the relevant sections
below. For `session run` assignments, start with the failed Source sequence
and the attempt linked by the coordinator.

## Source Session Progress

For `inspect_session_setup`, start with the reported setup error. Check the
sealed recording, runtime inputs, Replay readiness and Target image build at
the failure boundary. For `analyze_session_failure`, read the reported expected
event and the bounded `session events` query. Use the matching protected
dependency or Target query when available. For primary HTTP, follow the
exchange ID back to the request and forward through the recorded response or
cancellation. The optional `session events --payload` query exposes protected
Source primary HTTP data. Follow the
[Source session evidence contract](session-regression.md).

Use `source_start`, `ready`, `stop`, and `source_exit` to distinguish launch,
readiness, and shutdown failures from business traffic. Startup, background
work and concurrent HTTP exchanges can interleave. An open response or
dependency can wait across other events. Trace the expected event back to the
Target condition that enables it, and report the earlier input, dependency
delivery, or lifecycle sequences that establish that relationship.

Session Replay advances when the recorded admission, delivery, or timer gate
allows it, with zero artificial delay between recorded events. A Target-owned
periodic flush, retry or poll still waits on the application clock. When a
Source-proven wait controls the failing sequence, identify the call site, stream
identity, occurrence and last processed application input. A managed
[Replay timer](../../../../../docs/replay-timers.md) uses `cases.session` with
`before_request` at the first recorded dependency request the wait enables.
A graceful shutdown wait can use `before_event` with the recorded `source_exit`
sequence. The coordinator supplies the plan through
`TRAFFIC_E2E_REPLAY_TIMER_PLAN` for the verified rerun. Keep normal deadlines
when the application runs without a matching timer plan.

## Rejected Egress

When response or dependency verification fails, the referenced runtime evidence
may report REJECT packet-count deltas and sampled time windows. Treat these as
investigation leads. Counts include retries and background traffic. A null
count marks an unavailable counter observation.

Trace the Source call and missing dependency before submitting a system defect.
Return the evidence reference, relevant Source sequences or Case ID, literal
IP:port, and Source citation to the coordinator. Trace the endpoint from
its origin in Source configuration or a prior dependency response to the
call that consumes it. Check equivalent recorded endpoints and report any
missing capture evidence.

## Local Cache And Runtime State

When a response or dependency failure suggests missing startup state, inspect
the startup, readiness, and relevant dependency sequences in a Source session.
For the Case workflow, use the startup and readiness evidence referenced by
`backend-rewrite evidence --api /route`. If the explanation needs recorded
bootstrap or background traffic, identify the specific missing observation
for the coordinator. Trace the full cache path before drawing a conclusion.

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

Use available process traffic to locate Source startup schedulers, background
refreshers, and cache loaders. Trace the recorded interactions to the cache
population and read paths in Source code.

When a generated time drives a different cache branch, identify its Source
generator, recorded value, delivery and comparison clock. Check the
[current typed rule capabilities](api-implementer-rule-diagnosis.md)
for that protocol and value position. Preserve the application expiry
threshold and refresh behavior.

Repair cache initialization, keying, refresh, or its genuine dependency path
in Target. Verify the repair against the same immutable session or Case group.

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
   `EACCES`, follow [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md#writable-directories)
   for source proof and the affected image's directory contract.

Repair product startup, composition, configuration loading, or
`.traffic-e2e/Dockerfile.target`. Do not add case execution, report parsing,
Replay control, or expected-response access to the target repository.

## Replay Issues

For incomplete Replay, use the reported phase and its sequence, Case, or
artifact reference to distinguish these causes.

- target never emitted the expected genuine dependency call;
- semantic dependency evidence exists but Replay cannot match or reproduce it;
- interception, process lifecycle, verification or finalization failed;
- the recording lacks required semantic evidence.

For the last case, follow
[Missing Recorded Dependency Evidence](api-implementer-dependency-diagnosis.md#missing-recorded-dependency-evidence)
before classifying a capability gap or external-data blocker.

If target topology differs, repair target behavior. If semantic evidence exists
but the engine lacks support, return the evidence reference, Source
reference, and exact required system change to the workflow coordinator. Never implement a target workaround for
a Replay capability gap or supply an arbitrary acceptance command.
