# E2E Run State

Separate stable project configuration from local migration execution state. Use
one local state directory per recording run so current evidence cannot be
confused with historical batches or accidentally committed.

## Layout

```text
.migration/
├── e2e.yaml
└── local/
    ├── current.yaml
    └── <run-key>/
        ├── state.yaml
        ├── reports/
        │   ├── <run-key>.json
        │   ├── <run-key>-assertions.json
        │   └── <run-key>-verified-exclude.json
        ├── logs/
        └── tmp/
```

Derive `<run-key>` from the recording run id plus collection name. For example,
`recordings/20260714041519/pluto` becomes `20260714041519-pluto`. Replaying the
same recording source updates the same run state; do not create a new history
entry merely because the command ran again.

## Git Boundary

Keep only stable project configuration in `.migration/e2e.yaml`. Put every
mutable or generated migration artifact under `.migration/local/`, including
current-run pointers, per-run state, aggregate and assertion reports, grouping
and route-pattern reports, verified-exclude reports, blocker diagnostics, logs,
PIDs, addresses, sessions, and temporary files.

Before writing local state, require the target repository's root `.gitignore`
to contain this exact directory rule:

```gitignore
.migration/local/
```

Verify a representative path with `git check-ignore`. MUST NOT stage, commit,
or force-add anything under `.migration/local/`. Ignoring local artifacts does
not waive any evidence or completion gate: required files must still exist and
remain internally consistent for verification. When repository or CI artifact
storage is available, publish required evidence there and record its stable URI
and fingerprint in the local state; do not copy generated reports into source
control merely to retain them.

## Stable Project Configuration

Keep `.migration/e2e.yaml` small and source-control eligible. Store only stable
project metadata and paths that apply across runs:

```yaml
version: 2
source_repo: ../source
target_language: rust
project_cli: scripts/<project>-cli
recorder_config: config/recorder.toml
replay_policy: config/replay.yaml
local_root: local
```

Git base conventions, the exact command facade, recorder config, replay policy,
and documentation paths may remain here when they are project-wide. Do not put
the current run id, current status, case counts, session ids, report results,
blockers, absolute recording paths, logs, PIDs, or temporary paths in this file.

## Current Pointer

Store current execution pointers under `.migration/local/current.yaml`:

```yaml
version: 2
current_run: 20260714041519-pluto
current_run_state: 20260714041519-pluto/state.yaml
current_aggregate_report: 20260714041519-pluto/reports/20260714041519-pluto.json
status: partial_evidence
```

Resolve these paths relative to `.migration/local/`. This file is local working
state and MUST NOT be treated as canonical proof.

## Per-Run State

Store recording-specific evidence under
`.migration/local/<run-key>/state.yaml`:

- exact `case_source` and source revision when available
- selected scope plus ordered API groups with method, source route, grouping
  status/report/manifest, member directories, exact case ids, and terminal state
- rewrite input and PR E2E case sources
- exact E2E command
- canonical `config/replay.yaml` path, content fingerprint, validation result,
  applicable-rule usage, and unused applicable rules
- direct audit result proving `expected-response.json` is read only by final
  assertion comparison and never constructs actual behavior
- final replay session ids, report paths, and results
- aggregate status, report path, and published/reported/unreported counts
- case-path-pattern status and persisted plan, apply, and final verification
  JSON report paths when applicable
- verified-exclude threshold, trailing success count, assertion report,
  recorder-owned ensure-report path, and terminal status
- target test result, startup result, and quality commands
- work branch, focused commit SHA, PR target, and PR URL
- missing evidence and blocker classifications
- recorder and route-pattern feedback
- schema, metrics, dynamic-value, architecture, and semantics review statuses
- external artifact URIs and fingerprints when artifact storage is available

Keep raw replay reports in the recording tree. If the case source contains a
collection/run, multiple selected cases, or multiple standard replay reports or
sessions, call `traffic-replay-aggregate` with the exact completion case source
root, repeated exact `--case-id` and `--session-id` values, and both
`--fail-on-incomplete` and `--fail-on-dirty`; write the output under
`.migration/local/<run-key>/reports/`. Only a single published case replayed in
one finalized session/report may use
`not_applicable_single_case_single_session`. Write target-owned assertion,
grouping, route-pattern, verified-exclude, and blocker reports under the same
run-specific `reports/` directory. The target repository owns E2E orchestration
and business assertion results; it must not reimplement recorder report parsing
or counting.

Use only these route-pattern terminal states: `applied`,
`confirmed_no_change`, `not_applicable_missing_source_repo`,
`not_applicable_missing_managed_config`, or `blocked`. Use only these
verified-exclude terminal states: `applied`, `already_present`,
`below_threshold`, `not_applicable_missing_verified_excludes_config`, or
`blocked`. Use delivery state `pr_created` only after the pushed branch and PR
target are independently verified. Local state records canonical evidence paths
and identifiers; it is never proof by itself.

## Consistency

Require `.migration/local/current.yaml`, the per-run state, E2E command,
aggregate `case_source`, group inventory, and raw report roots to describe the
same recording source and exact case-id set. Require each selected case to occur
in exactly one group and the published recording tree to remain unchanged.
Treat a mismatch as an incomplete migration report. Historical local run state
is immutable except when the same recording source is deliberately replayed
again.
