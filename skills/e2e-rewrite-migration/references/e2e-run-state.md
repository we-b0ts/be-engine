# E2E Run State

Use one state file per recording run so current evidence cannot be confused
with historical batches.

## Layout

```text
.migration/
├── e2e.yaml
├── runs/
│   └── <run-key>.yaml
└── run-reports/
    └── <run-key>.json
```

Derive `<run-key>` from the recording run id plus collection name. For example,
`recordings/20260714041519/pluto` becomes `20260714041519-pluto`. Replaying the
same recording source updates the same run state; do not create a new history
entry merely because the command ran again.

## Current Index

Keep `.migration/e2e.yaml` small. Store stable project metadata plus only the
current run pointers and current status:

```yaml
version: 1
source_repo: ../source
target_language: rust
current_run: 20260714041519-pluto
current_run_state: runs/20260714041519-pluto.yaml
current_aggregate_report: run-reports/20260714041519-pluto.json
status: partial_evidence
```

Git branch/PR pointers, the command facade, recorder config, and documentation
paths may remain here when they are project-wide. Do not append old commands,
case counts, report paths, blockers, or replay results to this file.

## Per-Run State

Store recording-specific evidence under `.migration/runs/<run-key>.yaml`:

- exact `case_source` and source revision when available
- selected scope and method/path-to-case matrix
- rewrite input and PR E2E case sources
- exact E2E command
- replay/assertion policy path when one is configured
- aggregate report path and published/reported/unreported counts
- target test result, startup result, and quality commands
- missing evidence and blocker classifications
- recorder and route-pattern feedback
- schema, metrics, dynamic-value, architecture, and semantics review statuses

Keep raw replay reports in the recording tree. If the case source contains
multiple standard replay reports, call `traffic-replay-aggregate` with the case
source root and write the output under `.migration/run-reports/`. The target
repository owns E2E orchestration and business assertion results; it must not
reimplement recorder report parsing or counting.

## Consistency

Require the current index, per-run state, E2E command, aggregate `case_source`,
and raw report roots to describe the same recording source. Treat a mismatch as
an incomplete migration report. Historical run state is immutable except when
the same recording source is deliberately replayed again.
