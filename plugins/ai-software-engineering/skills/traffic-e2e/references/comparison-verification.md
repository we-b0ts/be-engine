# Comparison Verification

Comparison is allowed only after current replay E2E passes for the affected
scope.

## Record

```bash
traffic-e2e record-comparison --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --api '<METHOD path>'
```

The workflow derives API selectors from the standard recording inventory and
passes their exact canonical values back to the engine. Callers and AI agents
must not infer or assemble selectors from protocol metadata. HTTP and Motan
use the same repeatable `--api` input; protocol adapters own discovery,
transport, and comparison behavior. Motan inventory entries use an opaque
engine-generated `MOTAN /rpc/<api-id>` canonical value.

traffic-e2e builds `.traffic-e2e/Dockerfile.e2e` and owns source and target
containers, their managed network namespaces, readiness, comparison recorder,
finalization, signals, and cleanup. The source keeps the host recording
namespace, while the target uses a run-owned bridge namespace. A run-scoped
egress guard owns target forwarding and masquerade for the lifetime of the
cache snapshot. The target receives its declared startup mounts and environment.
Do not generate or invoke repository comparison wrappers.

Managed comparison runs source through the reviewed
`.traffic-e2e/Dockerfile.recording` adaptor, also used by diagnostic preflight. The
adaptor owns the source command and fixed `998:998` identity required by
cache-only interception; callers do not adapt or configure the source UID.
Comparison reads runtime inputs from the local source snapshot and starts the
adapted, run-private source container. The initialization Pod is not required.
This managed adaptor is separate from the project-owned `Docker.recording`
used to deploy standalone `traffic-e2e record`.

When the recorder config contains Redis process-owned rules, managed comparison
also owns one cache-only run-local snapshot across both managed namespaces.
Fixed-UID `OUTPUT` interception captures source traffic, while source-IP-scoped
`PREROUTING` interception captures target traffic before target
egress masquerade. Source and candidate share the first successful response for
each matching logical Redis read. This comparison snapshot starts empty and
never loads the standard recording's Replay snapshot.
Managed comparison waits for that snapshot recorder's sliding Redis quiet
window before admitting input, then admits one complete source/candidate case
at a time.

HTTP and Motan comparison listeners share that same single process-wide case
slot. A case retains it through source and candidate dispatches, an optional
source recheck, and publication; an overlapping request on either protocol
reaches neither upstream and receives the protocol adapter's fixed response.
Each run chooses a fresh random, pair-balanced source/candidate dispatch
schedule. The schedule is fixed for the lifetime of that run, but different
runs can send the same workload to source or candidate first. Dispatch order
is intentionally not published in comparison evidence or reports.

Comparison sends every admitted request symmetrically to
source and candidate, using the methods declared by the selected HTTP gateway
rule or the matching Motan gateway rule without a separate read-only-method
restriction. Use repeatable `--api`, optional positive `--per-api-case-limit`,
and `--baseline-recheck` only when diagnosis needs source-after evidence.
Source-after never serves as an alternate acceptance oracle.
With explicit API selectors, comparison recording finalizes normally when
every selected API reaches its case limit; `--duration-seconds` remains the
upper bound. The project-level `verification.max_failed_cases_per_api` limit
also stops admitting cases for an API after that many online comparison cases
do not pass under the current verification policy. When the managed runtime
supplies a finite standard-recording case source, it sends one complete case at
a time. After the final case is
published, the source, candidate, and cache snapshot remain running for a
three-second final quiet period, then the run finalizes with
`completion_reason = input_exhausted`. The delivered input count must equal
the published comparison case count; a mismatch finalizes with errors instead
of silently accepting missing evidence. Without finite input or a completed
explicit case limit, comparison keeps the full recording window.

Backend rewrite consumes completed comparison batches placed under
`.traffic-e2e/local/artifacts/comparison-recordings/<run-id>/`, selected with
`comparison_run_id` in local `regression.yaml`. It never invokes this capture;
the caller supplies evidence after the current Replay gate passes.

Finite input selects matching cases across all standard-recording member
directories, including concrete paths covered by a wildcard API. Overlapping
selectors send each case once; other methods and paths are excluded. An input
process failure ends managed comparison and triggers cleanup immediately,
without waiting for the recording duration.

For each enabled `project.process_outputs` metrics profile, the final quiet
period is extended to
`comparison_recording.process_output_flush_after_last_case_ms` (15 seconds by
default). Source and candidate files are copied after that wait and before
their containers stop. The capture is scoped to this single-API comparison
run; standard Replay does not collect these outputs. Source-after remains
explicitly controlled by `baseline_recheck` or `--baseline-recheck`.
Because source-after sends a second request only to the source process,
cumulative process-output contents are not workload-symmetric when it is
enabled; do not add raw-content equality without an explicit segmentation or
normalization contract.

## Verify

Run the file-only comparator against the exact finalized manifest:

```bash
traffic-e2e compare <exact-comparison-run> \
  --policy <target>/.traffic-e2e/verification.yaml
```

Use its bounded terminal totals, source-before/source-after observations, and
representative difference. Do not open the large comparison report during
normal operation. Map/object key order and JSON formatting are already
structural; array order, presence, type, and value differences remain explicit
engine facts. Policy changes use evidence-validating `config ... plan|apply`;
the engine does not infer source causality or authorize a migration repair.
For profile `exact_total_count` comparisons, a `(type, name)` group absent from
one side has numeric count zero: a one-sided zero-count group is equal to
absence, while a one-sided positive-count group remains a difference.
The engine-owned profile policies compare exact `RPC_SERVICE_WHOLE` counts and
require source-positive `HTTP` plus the logical `RPC_SERVICE_CLIENT` Motan
group on target. Redis, Memcached, and service-internal metrics are not product
comparison policies.

For a source-only HTTP or Motan client metric, the issue overview's
`facts.issue.comparison_observation.rule_candidate` describes
`allow_target_missing`. It is a diagnosis candidate, not authorization. The
target AI must inspect the returned metric's source startup/configuration and
indirect-emitter paths. Return exactly the canonical metric, dependency path,
and structured emitter evidence only after proving that source code does not
start the interaction and that the interaction does not affect source behavior;
otherwise implement it in the target. `emitter_evidence.inspected_paths` names
the source and dependency source paths actually inspected, and `description`
states why the indirect dependency emits independently without affecting source
behavior. These two eligibility conclusions are not rule fields. The
coordinator supplies the process output, source revision, and comparison run to
the plan/apply workflow. Plan validates the exact finalized comparison capture,
and apply remains bound to unchanged project, policy, and capture evidence.

When one repaired immutable case passes replay but the first otherwise-valid
fresh comparison does not observe it, retain a non-blocking
`repaired_case_not_observed` attention and do not record again solely for
observation coverage.
