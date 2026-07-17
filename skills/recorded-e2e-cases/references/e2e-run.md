# Standard E2E Migration Runner

Use `traffic-e2e-run` as the only normal AI-facing replay command. Low-level
grouping, replay-control, aggregate, and verified-exclude commands remain
recorder-owned implementation details and human diagnostic surfaces.

## Stable Target Configuration

Keep source-controlled project settings in `.migration/e2e.yaml`:

```yaml
version: 2
project_cli: scripts/<project>-cli
replay_policy: config/replay.yaml
recorder_config: config/recorder.toml
recording_rule: record-api
local_root: local
required_consecutive_successful_runs: 3
```

`recorder_config` and `recording_rule` MUST appear together. The target
repository MUST ignore `.migration/local/`.

## Prepare An API

Before inspecting or running an API, read the first published case only for
route discovery and confirm the route against source registrations. Then call:

```bash
traffic-e2e-run prepare \
  --target-root <target> \
  --case-source <case-source> \
  --case-dir <canonical-input-directory> \
  --method <METHOD> \
  --source-route '<confirmed-source-route>' \
  --source-revision '<source-revision>'
```

For a dynamic route, also pass `--pattern '<whole-segment-pattern>'`. Prepare
delegates to canonical grouping and managed pattern feedback. It rejects stale
inventories, overlaps, mixed routes, and unsafe patterns. Never infer the API
key from directory names; use the returned `group.group_id`.

## Focused Migration Loop

Run one complete API group while implementing and repairing behavior:

```bash
traffic-e2e-run run-api \
  --target-root <target> \
  --case-source <case-source> \
  --api '<group.group_id>'
```

One focused attempt starts replay once for that API's cases, loads applicable
bootstrap once, starts the target once, executes every case sequentially, and
finalizes once. It publishes only the API's focused `latest` snapshot.

Focused attempts are diagnostic migration work. They MUST NOT:

- update `e2e-progress.yaml`;
- increment or reset full-round or API consecutive-success counts;
- run verified-excludes ensure;
- replace the full-round `latest`.

Fix an evidenced defect and rerun the same API. Preparing and migrating another
API does not make an earlier focused pass current after shared behavior changes;
the final full round is the regression gate.

## Full Round

After all published cases belong to exactly one prepared group, run:

```bash
traffic-e2e-run run \
  --target-root <target> \
  --case-source <case-source>
```

The command owns the entire round: one replay server, one bootstrap/full-case
load, one target start, sequential case begin/request/assert/end, one target
stop, one replay finalize, a global aggregate, per-API evidence views,
per-API verified-excludes ensure, progress update, and atomic publication.

Do not repair code inside a full round. If it fails, use focused `run-api` to
diagnose and fix, then start a new full round from the beginning.
After a successful round, repeat the unchanged full round until
`e2e-progress.yaml` reaches `status: complete`.

## Consecutive Success

Only a terminal full round changes consecutive-success state.

- Global consecutive success increments only when every API and every case
  passes and canonical evidence is finalized, complete, and clean.
- One failed, incomplete, or interrupted full round resets global consecutive
  success to zero.
- An API increments only when every case in that API passes in the completed
  full round. For 30 cases, 29 passes reset that API to zero; the 29 passing
  cases cannot contribute.
- An interrupted round resets every API streak to zero.
- Re-publishing the same terminal sequence is idempotent.
- Completion requires the configured global and every API streak; one clean
  round updates progress but does not bypass a larger configured requirement.

## Generated State

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
```

All files under `local/` and every JSON/YAML evidence file inside active,
focused, and latest directories are runner-generated. AI MUST NOT hand-edit
them. `e2e-progress.yaml` is the concise, Git-eligible human report; it omits
protocol, connection, policy, session, aggregate, root-cause, and repair detail.

Use `status`, `abort`, or `recover` for an interrupted full round. Never copy
partial focused evidence into the global `latest`.
