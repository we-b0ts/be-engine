# Comparison Verification

Comparison is allowed only after current replay E2E passes for the affected
scope.

## Record

```bash
traffic-e2e record-comparison --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --brz-no-fallback true --api '<METHOD path>'
```

traffic-e2e builds `.traffic-e2e/Dockerfile.e2e` and owns source, one shared
Breeze, target container, their shared network namespace, readiness,
comparison recorder, finalization, signals, and cleanup. The target receives
the fixed config mount and port environment contract. Do not generate or
invoke repository comparison wrappers.

Managed comparison runs source through the same reviewed
`.traffic-e2e/Dockerfile.recording` adaptor used by standard recording. The
adaptor owns the source command and fixed `998:998` identity required by
cache-only interception; callers do not adapt or configure the source UID.
It also reuses the adaptor's platform-owned runtime template, so comparison
does not inspect or require the original source container after the adaptor
has been built.

When the recorder config contains Redis background rules, managed comparison
also owns a cache-only run-local snapshot in the shared network namespace.
Source and candidate share the first successful response for each matching
logical Redis read. This comparison snapshot starts empty and never loads the
standard recording's Replay snapshot.

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
