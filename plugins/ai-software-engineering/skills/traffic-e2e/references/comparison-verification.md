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

traffic-e2e builds `.traffic-e2e/Dockerfile.e2e` and owns source, one shared
Breeze, target container, their managed network namespaces, readiness,
comparison recorder, finalization, signals, and cleanup. The source keeps the
host recording namespace, while Breeze and target share the run-owned target
namespace so Breeze loopback endpoints remain valid. The adapted source uses
the target bridge IP to reach that same Breeze through a namespace-scoped
loopback ingress mapping. A run-scoped egress guard owns target forwarding and
masquerade for the lifetime of the cache snapshot. The target receives the
fixed config mount and port environment contract. Do not generate or invoke
repository comparison wrappers.

Managed comparison runs source through the same reviewed
`.traffic-e2e/Dockerfile.recording` adaptor used by standard recording. The
adaptor owns the source command and fixed `998:998` identity required by
cache-only interception; callers do not adapt or configure the source UID.
Comparison reads runtime inputs from the configured source container, which
must remain present and stopped. traffic-e2e only inspects that container and
starts the adapted, run-private source container.

When the recorder config contains Redis process-owned rules, managed comparison
also owns one cache-only run-local snapshot across both managed namespaces.
Fixed-UID `OUTPUT` interception captures source traffic, while source-IP-scoped
`PREROUTING` interception captures target and Breeze traffic before target
egress masquerade. Source and candidate share the first successful response for
each matching logical Redis read. This comparison snapshot starts empty and
never loads the standard recording's Replay snapshot.
Managed comparison waits for that snapshot recorder's sliding Redis quiet
window before admitting input, then admits one complete source/candidate case
at a time.

HTTP and Motan comparison listeners share that same single process-wide case
slot. A case retains it through source, candidate, optional source recheck, and
publication; an overlapping request on either protocol reaches neither
upstream and receives the protocol adapter's fixed response.

When Breeze is absent, the same command selects the configured runtime without
starting Breeze. Comparison sends every admitted request symmetrically to
source and candidate, using the methods declared by the selected HTTP gateway
rule or the matching Motan gateway rule without a separate read-only-method
restriction. Use repeatable `--api`, optional positive `--per-api-case-limit`,
and `--baseline-recheck` only when the verification policy or diagnosis needs
source-after evidence.
With explicit API selectors, comparison recording finalizes normally when
every selected API reaches its case limit; `--duration-seconds` remains the
upper bound. When the managed coordinator supplies a finite standard-recording
case source, it sends one complete case at a time. After the final case is
published, the source, candidate, and cache snapshot remain running for a
three-second final quiet period, then the run finalizes with
`completion_reason = input_exhausted`. The delivered input count must equal
the published comparison case count; a mismatch finalizes with errors instead
of silently accepting missing evidence. Without finite input or a completed
explicit case limit, comparison keeps the full recording window.

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

When one repaired immutable case passes replay but the first otherwise-valid
fresh comparison does not observe it, retain a non-blocking
`repaired_case_not_observed` attention and do not record again solely for
observation coverage.
