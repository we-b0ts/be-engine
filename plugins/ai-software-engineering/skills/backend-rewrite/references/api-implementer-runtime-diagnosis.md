# API Implementer Runtime And Replay Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when
the current issue or evidence concerns rejected egress, local cache,
target runtime, or Replay completeness. Use only the relevant sections
below; the common evidence and handoff contracts still apply.

## Rejected Egress And IP Capture Preflight

When response or dependency verification fails, the referenced runtime evidence
may report REJECT packet-count deltas and sampled time windows. Treat these as
investigation leads. Counts include retries and background traffic. A null
count marks an unavailable read or rule generation. A clean passing run needs
no investigation based only on these counters.

Trace the Source call and missing dependency before submitting a system defect.
Return the evidence reference, Case ID, literal IP:port and Source citation to
the coordinator. If feedback requests more origin proof, supply it. A source-proven
`http-response` origin may support a response URL capture rule; return matching
JSON selectors and source proof. Reassess any remaining engine defect against
the next assigned recording evidence. Static/hardcoded addresses require source
configuration or a source mock. Unknown origins require investigation; do not
invent a response pointer. A matching IP in recorded JSON alone does not prove
source consumption or the absence of an equivalent recorded endpoint.

## Local Cache And Runtime State

When an observed response or Case dependency failure suggests missing startup
state, read the startup and readiness evidence referenced by
`backend-rewrite evidence --api /route`. If the explanation needs recorded
bootstrap or background traffic, identify the specific missing observation for
the coordinator's runtime investigation. Use these observations to guide
Source tracing and check the full cache path before drawing a conclusion.

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

Use any available process traffic to prioritize Source startup schedulers,
background refreshers, and cache loaders for the returned endpoints. An absent
endpoint is not proof that no process-local cache exists, and a high interaction
count or configured process-owned match is not proof that the traffic populates
a response-driving cache.

When source and target implement the same cache semantics, but recorded absolute
time has aged between capture and Replay, inspect
[Redis `time-shift`](api-implementer-diagnosis.md#rule-discovery-from-source-diagnosis).
It preserves the original relative age in the engine's dependency-response copy and
lets the target build its normal cache. Preserve the original expiry threshold;
do not reset timestamps to now or suppress refresh to fit Replay.

Do not apply a generated-scalar assertion rule for a cold, missing, stale, differently keyed,
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
   `EACCES`, follow [api-implementer-startup-inputs.md](api-implementer-startup-inputs.md#writable-directories)
   for source proof and the affected image's directory contract.

Repair product startup, composition, configuration loading, or
`.traffic-e2e/Dockerfile.target`. Do not add case execution, report parsing,
Replay control, or expected-response access to the target repository.

## Replay Issues

For incomplete Replay, use the reported failure phase and its case or artifact
reference to distinguish these causes.

- target never emitted the expected genuine dependency call;
- semantic dependency evidence exists but Replay cannot match or reproduce it;
- interception, readiness, begin/end, finalize, or cleanup failed;
- the recording lacks required semantic evidence.

For the last case, follow
[Missing Recorded Dependency Evidence](api-implementer-dependency-diagnosis.md#missing-recorded-dependency-evidence)
before classifying a capability gap or external-data blocker.

If target topology differs, repair target behavior. If semantic evidence exists
but the engine lacks support, return the evidence reference, Source
reference, and exact required system change to the workflow coordinator. Never implement a target workaround for
a Replay capability gap or supply an arbitrary acceptance command.
