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
- selected scope plus ordered API groups with method, source route, grouping
  status/report/manifest, member directories, exact case ids, and terminal state
- rewrite input and PR E2E case sources
- exact E2E command
- replay/assertion policy path when one is configured
- final replay session ids, report paths, and results
- aggregate status, report path, and published/reported/unreported counts
- case-path-pattern status and persisted plan, apply, and final verification
  JSON report paths when applicable
- target test result, startup result, and quality commands
- work branch, focused commit SHA, PR target, and PR URL
- missing evidence and blocker classifications
- recorder and route-pattern feedback
- schema, metrics, dynamic-value, architecture, and semantics review statuses

Keep raw replay reports in the recording tree. If the case source contains
a collection/run, multiple selected cases, or multiple standard replay reports
or sessions, call `traffic-replay-aggregate` with the exact completion case
source root, repeated exact `--case-id` and `--session-id` values, and both
`--fail-on-incomplete` and `--fail-on-dirty`; write the output under
`.migration/run-reports/`. Only a single published case replayed in one
finalized session/report may use
`not_applicable_single_case_single_session`. The target repository owns E2E
orchestration and business assertion results; it must not reimplement recorder
report parsing or counting.

Use only these route-pattern terminal states: `applied`,
`confirmed_no_change`, `not_applicable_missing_source_repo`,
`not_applicable_missing_managed_config`, or `blocked`. Use delivery state
`pr_created` only after the pushed branch and PR target are independently
verified. The run state records canonical evidence paths and identifiers; it
is never proof by itself.

## Consistency

Require the current index, per-run state, E2E command, aggregate `case_source`,
group inventory, and raw report roots to describe the same recording source and
exact case-id set. Require each selected case to occur in exactly one group and
the published recording tree to remain unchanged. Treat a mismatch as an
incomplete migration report. Historical run state is immutable except when the
same recording source is deliberately replayed again.
