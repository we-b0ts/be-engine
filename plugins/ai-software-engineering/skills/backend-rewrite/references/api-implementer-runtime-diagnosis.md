# API Implementer Runtime And Replay Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) when
the current issue or evidence concerns rejected egress, local cache,
target runtime, or Replay completeness. Use only the relevant sections
below; the common evidence and handoff contracts still apply.

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
coordinator. If feedback requests more origin proof, supply it. A source-proven
`http-response` origin may support a response URL capture rule; return matching
JSON selectors and source proof. Reassess any remaining engine defect against
the next assigned recording evidence. Static/hardcoded addresses require source
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

`replay=incomplete` means the engine did not publish complete lifecycle
evidence. Use the returned issue and dirty-cluster query to distinguish:

- target never emitted the expected genuine dependency call;
- semantic dependency evidence exists but Replay cannot match or reproduce it;
- interception, readiness, begin/end, finalize, or cleanup failed;
- the recording lacks required semantic evidence.

For the last case, follow
[Missing Recorded Dependency Evidence](api-implementer-dependency-diagnosis.md#missing-recorded-dependency-evidence)
before classifying a capability gap or external-data blocker.

If target topology differs, repair target behavior. If semantic evidence exists
but the engine lacks support, return the current evidence ID, source
reference, and exact required system change to the workflow coordinator. Never implement a target workaround for
a Replay capability gap or supply an arbitrary acceptance command.
