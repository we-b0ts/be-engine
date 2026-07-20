# E2E Run State

Keep stable project configuration, Git-eligible human progress, local focused
attempts, and full-round canonical evidence separate.

## Layout

```text
.traffic-e2e/
├── e2e.yaml
├── replay.yaml
├── recorder.toml
├── e2e-progress.yaml
└── local/
    ├── current.yaml
    └── <run-key>/
        ├── state.yaml
        ├── case-groups.json
        ├── focused/
        │   └── <api-key-hash>/
        │       ├── .active/
        │       └── latest/
        ├── .active/
        └── latest/
            ├── state.yaml
            ├── reports/
            ├── apis/
            └── tmp/
```

Derive `<run-key>` from the recording run id plus collection name when
available. Replaying the same case source updates the same run key. Focused API
attempts and full rounds are attempts within that run key, not new historical
run keys.

## Git Boundary

The target root `.gitignore` MUST contain:

```gitignore
.traffic-e2e/local/
```

Verify it with `git check-ignore` before runner state is created. Never stage or
force-add `local/`. The runner writes all JSON/YAML evidence under `local/`;
AI MUST NOT create, edit, merge, repair, or copy these files by hand.

`e2e-progress.yaml` is different: it is a concise runner-generated report for
humans and is expected to be committed. It contains only execution, success,
trailing-success, verification, and latest-round counts. It intentionally
excludes failed/incomplete categories, protocol evidence, connections,
policies, sessions, aggregates, root causes, and repair suggestions. AI reads
local evidence when diagnosis is needed. The runner loads and incrementally
updates project history, preserving APIs absent from the current inventory; AI
does not edit, merge, reconstruct, or validate these counters.

Details for unresolved or unfixable problems remain in runner-generated reports
and evidence under `.traffic-e2e/local/`.

The generated shape is:

```yaml
version: 2
updated_at: "2026-07-17T08:00:00Z"
status: complete
run:
  key: 20260717080000-record-api
progress:
  runs:
    executed: 4
    successful: 3
    consecutive_successful: 2
  cases:
    executed: 136
    successful: 132
    consecutive_successful: 68
  apis:
    total: 5
    verified: 5
latest_run:
  number: 4
  successful: true
  cases:
    executed: 34
    successful: 34
  apis:
    executed: 5
    successful: 5
apis:
  GET /api/widgets/*:
    verified: true
    runs:
      executed: 3
      successful: 3
      consecutive_successful: 3
    cases:
      executed: 24
      successful: 24
      consecutive_successful: 24
  POST /api/widgets:
    verified: true
    runs:
      executed: 3
      successful: 3
      consecutive_successful: 3
    cases:
      executed: 12
      successful: 12
      consecutive_successful: 12
```

`progress.runs` and `progress.cases` are cumulative across distinct published
run keys. Focused and full attempts within the current run replace that run's
terminal contribution instead of adding counts. `consecutive_successful` under
`cases` is the number of canonical cases covered by the same trailing fully
successful distinct runs, not a sequence assembled from attempts or individual
case outcomes. A non-successful run resets both global streaks. Per-API streaks
reset only when that API's run is not successful. An inventory or
source-revision change starts new streaks. Detailed failure categories remain
in runner-local evidence, not this human report.

## Stable Configuration

Keep the source-controlled replay and recorder migration inputs at
`.traffic-e2e/replay.yaml` and `.traffic-e2e/recorder.toml`.

Generate the source-controlled `.traffic-e2e/e2e.yaml` with
`traffic-e2e init`:

```bash
traffic-e2e init \
  --target-root <target> \
  --project-cli scripts/<project>-cli \
  --replay-policy .traffic-e2e/replay.yaml \
  --api-verification-consecutive-successful-runs 3 \
  --api-verification-successful-cases 3 \
  --api-verification-override 'GET /api/widgets/*=5,200' \
  --pr-base <confirmed-base-branch> \
  --recorder-config .traffic-e2e/recorder.toml \
  --recording-rule record-api
```

The resulting file is:

```yaml
version: 4
project_cli: scripts/<project>-cli
replay_policy: .traffic-e2e/replay.yaml
replay_startup_timeout_seconds: 60
api_verification:
  consecutive_successful_runs: 3
  successful_cases: 3
  overrides:
    GET /api/widgets/*:
      consecutive_successful_runs: 5
      successful_cases: 200
pr_base: <confirmed-base-branch>
recorder_config: .traffic-e2e/recorder.toml
recording_rule: record-api
local_root: local
```

`replay_startup_timeout_seconds` is the replay readiness deadline and defaults
to 60 when absent from an older config. The runner prints dependency-loading
progress by loaded case count, beginning with `loaded_cases=0` and then about
every 5%, while retaining the complete replay log.

`api_verification` is the sole verification policy. Top-level values are
defaults; a canonical `METHOD path_pattern` override replaces both values for
that exact API. Repeat `--api-verification-override` with
`METHOD path_pattern=successful-runs,successful-cases` when generating
overrides. An API becomes verified only when its trailing successful distinct
published runs meet its effective thresholds. The runner then synchronizes that
API into `.traffic-e2e/recorder.toml`; the recorder config stores the result,
not another threshold.

`project_cli`, `replay_policy`, and `pr_base` are required. `init`
validates that the PR base exists locally or as an `origin`
remote-tracking branch. `recorder_config` and `recording_rule` are optional only
as a pair. Every runner command rejects a missing, incomplete, obsolete, or
unresolvable project config before using traffic E2E state. `prepare`, `run-api`,
and `run` require a named feature branch different from `pr_base`. Do not put a current
run id, case count, API list, status, session, report result, blocker, PID,
address, or temporary path in this file. If required project facts cannot be
confirmed, ask the user; do not hand-edit the file.

## Focused API State

`traffic-e2e run-api` creates the selected API's `.active`, runs its entire
canonical case group, then atomically replaces that API's `latest`. A rerun
keeps only the latest complete focused snapshot.

Terminal focused attempts replace the selected API's final contribution to the
current logical run and update `e2e-progress.yaml` and any eligible verified
exclude. Repeating the same run does not add another run or another copy of its
cases. Focused attempts never replace full-round `.active`, global `latest`, or
`.traffic-e2e/local/current.yaml`.

When every published case is grouped and every API's current group passes, the
grouped focused result is completion proof unless a later shared change can
invalidate an earlier group. Verification thresholds do not gate the current
migration or delivery. Such a change requires rerunning affected groups or one
full regression round.

## Full-Round State

`traffic-e2e run` requires complete, non-overlapping grouping for every
published case. It creates the run-key `.active`, executes one full round, and
only after terminal evidence atomically replaces the previous global `latest`.
Readers see either the old complete snapshot or the new complete snapshot,
never a mix of API results from different rounds.

The run-key `state.yaml` stores the project history baseline plus the current
logical run's idempotent terminal contribution.
Global `latest/state.yaml` stores only the most recent full round and its exact
case/API evidence. `.traffic-e2e/local/current.yaml` points to that terminal
state.

If the full round fails, use focused `run-api` for diagnosis and repair. Run a
new full round only when the regression gate remains required. Never patch a
failed `.active` snapshot into success.

## Completion

Only terminal runner evidence can advance progress:

- every API and every case must pass;
- canonical replay evidence must be finalized, complete, and clean;
- a non-successful current logical run leaves human progress
  `status: in_progress`;
- a successful API is `verified` only after distinct published runs with
  complete, clean evidence meet both configured streak thresholds;
- verified APIs are synchronized add-only into the managed recorder exclusion
  list before progress is published;
- the same terminal sequence and repeated attempts within one run are applied
  idempotently.

## Recovery

Use runner commands, never filesystem surgery:

```bash
traffic-e2e status  --target-root <target> --case-source <source>
traffic-e2e abort   --target-root <target> --case-source <source>
traffic-e2e recover --target-root <target> --case-source <source>
```

`abort` publishes an interrupted full round so the failure is explicit.
`recover` restores an interrupted atomic publication or aborts a surviving
global `.active`. Focused `.active` evidence remains isolated and cannot become
the global `latest`.
