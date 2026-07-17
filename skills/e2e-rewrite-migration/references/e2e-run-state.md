# E2E Run State

Keep stable project configuration, Git-eligible human progress, local focused
attempts, and full-round canonical evidence separate.

## Layout

```text
.migration/
├── e2e.yaml
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
.migration/local/
```

Verify it with `git check-ignore` before runner state is created. Never stage or
force-add `local/`. The runner writes all JSON/YAML evidence under `local/`;
AI MUST NOT create, edit, merge, repair, or copy these files by hand.

`e2e-progress.yaml` is different: it is a concise runner-generated report for
humans and is expected to be committed. It contains counts, status, latest
full-round summaries, failure highlights, and per-API progress. It intentionally
excludes protocol evidence, connections, policies, sessions, aggregates, root
causes, and repair suggestions. AI reads local evidence when diagnosis is
needed.

Details for unresolved or unfixable problems remain in runner-generated reports
and evidence under `.migration/local/`.

The generated shape is:

```yaml
version: 1
updated_at: "2026-07-17T08:00:00Z"
status: complete
run:
  key: 20260717080000-record-api
progress:
  runs:
    total: 4
    successful: 3
    failed: 1
    interrupted: 0
  cases:
    total: 34
    replayed: 136
    passed: 132
    failed: 4
    incomplete: 0
  apis:
    total: 5
    verified: 5
    pending: 0
latest_run:
  number: 4
  status: successful
  cases:
    total: 34
    passed: 34
    failed: 0
    incomplete: 0
  apis:
    total: 5
    passed: 5
    failed: 0
    incomplete: 0
  highlights: {}
apis:
  GET /api/widgets/*:
    cases: 8
    status: verified
  POST /api/widgets:
    cases: 4
    status: verified
```

`progress.cases` is cumulative across full rounds except `total`, which is the
current published inventory. `latest_run` never expands every API; on a failed
round its `highlights` contains only `most_failed_cases` and
`highest_failure_rate`.

## Stable Configuration

Generate the source-controlled `.migration/e2e.yaml` with
`traffic-e2e-run init`:

```bash
traffic-e2e-run init \
  --target-root <target> \
  --project-cli scripts/<project>-cli \
  --replay-policy config/replay.yaml \
  --pr-base <confirmed-base-branch> \
  --recorder-config config/recorder.toml \
  --recording-rule record-api
```

The resulting file is:

```yaml
version: 4
project_cli: scripts/<project>-cli
replay_policy: config/replay.yaml
pr_base: <confirmed-base-branch>
recorder_config: config/recorder.toml
recording_rule: record-api
local_root: local
```

`project_cli`, `replay_policy`, and `pr_base` are required. `init`
validates that the PR base exists locally or as an `origin`
remote-tracking branch. `recorder_config` and `recording_rule` are optional only
as a pair. Every runner command rejects a missing, incomplete, obsolete, or
unresolvable project config before using migration state. `prepare`, `run-api`,
and `run` require a named feature branch different from `pr_base`. Do not put a current
run id, case count, API list, status, session, report result, blocker, PID,
address, or temporary path in this file. If required project facts cannot be
confirmed, ask the user; do not hand-edit the file.

## Focused API State

`traffic-e2e-run run-api` creates the selected API's `.active`, runs its entire
canonical case group, then atomically replaces that API's `latest`. A rerun
keeps only the latest complete focused snapshot.

Focused attempts support migration diagnosis and repair. They never update:

- the run-key `state.yaml` cumulative full-round counters;
- `.migration/e2e-progress.yaml`;
- full-round `.active` or `latest`;
- verified API excludes.

A focused pass is not completion proof because later shared changes may
invalidate it.

## Full-Round State

`traffic-e2e-run run` requires complete, non-overlapping grouping for every
published case. It creates the run-key `.active`, executes one full round, and
only after terminal evidence atomically replaces the previous global `latest`.
Readers see either the old complete snapshot or the new complete snapshot,
never a mix of API results from different rounds.

The run-key `state.yaml` stores cumulative full-round counts.
Global `latest/state.yaml` stores only the most recent full round and its exact
case/API evidence. `.migration/local/current.yaml` points to that terminal
state.

If the full round fails, use focused `run-api` for diagnosis and repair, then
start a new full round from the beginning. Never patch a failed `.active`
snapshot into success. One successful full round with every API and case
passing and finalized, complete, clean evidence sets progress to `complete`.

## Completion

Only a terminal full round can complete progress:

- every API and every case must pass;
- canonical replay evidence must be finalized, complete, and clean;
- a failed, incomplete, or interrupted full round reports
  `status: needs_attention`;
- a successful API is `verified` only with complete, clean global evidence;
- the same terminal sequence is applied idempotently during recovery.

## Recovery

Use runner commands, never filesystem surgery:

```bash
traffic-e2e-run status  --target-root <target> --case-source <source>
traffic-e2e-run abort   --target-root <target> --case-source <source>
traffic-e2e-run recover --target-root <target> --case-source <source>
```

`abort` publishes an interrupted full round so the failure is explicit.
`recover` restores an interrupted atomic publication or aborts a surviving
global `.active`. Focused `.active` evidence remains isolated and cannot become
the global `latest`.
