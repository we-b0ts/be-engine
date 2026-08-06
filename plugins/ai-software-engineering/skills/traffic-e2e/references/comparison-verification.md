# Comparison Verification

Comparison is allowed only after current replay E2E passes for the affected
scope.

## Record

```bash
traffic-e2e record-comparison --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --brz-no-fallback true --api '<METHOD path>'
```

traffic-e2e owns source, one shared Breeze, target start with `--e2e --boot-dir
.traffic-e2e/local/boot --port <configured-port>`,
readiness, comparison recorder, finalization, signals, and cleanup. Do not
generate or invoke repository comparison wrappers.

When Breeze is absent, the same command selects the configured runtime without
starting Breeze. Comparison sends every admitted request symmetrically to
source and candidate, using the methods declared by the selected HTTP gateway
rule without a separate read-only-method restriction. Use repeatable `--api`,
optional positive `--per-api-case-limit`,
and `--baseline-recheck` only when the verification policy or diagnosis needs
source-after evidence.
With explicit API selectors, comparison recording finalizes normally when
every selected API reaches its case limit; `--duration-seconds` remains the
upper bound. Without selectors, it keeps the full recording window.

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
