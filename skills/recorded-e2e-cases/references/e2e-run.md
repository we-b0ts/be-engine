# Standard Traffic E2E Runner

Use `traffic-e2e-run` as the only normal AI-facing replay command. Low-level
grouping, replay-control, aggregate, and verified-exclude commands remain
recorder-owned implementation details and human diagnostic surfaces.

## Initialize Target Configuration

Generate and validate the source-controlled `.traffic-e2e/e2e.yaml` once:

```bash
traffic-e2e-run init \
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

`project_cli`, `replay_policy`, and `pr_base` are required project
facts. If they cannot be confirmed from the target repository, ask the user;
do not guess or hand-write the YAML. The PR base must resolve as a
local branch or an `origin` remote-tracking branch. The recorder flags are
optional only as a pair. The command generates:

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
to 60 when absent from an older config. The runner prints an initial
`loaded_cases=0` dependency-loading event, then relays progress about every 5%
by loaded case count while retaining the complete replay log.

`api_verification` is the sole verification policy. Top-level values are
defaults; `overrides` keys use the exact canonical `METHOD path_pattern` API id
and replace both values for that API. Repeat `--api-verification-override` with
`METHOD path_pattern=successful-runs,successful-cases` when generating them.
`successful_cases` counts case executions covered by the same trailing
successful API rounds. The runner synchronizes an API into
`.traffic-e2e/recorder.toml` only after its effective thresholds are met.

The target repository MUST ignore `.traffic-e2e/local/` before initialization.
Existing configuration is preserved unless `--force` is explicit.
Every other runner command validates that the generated config exists, has all
required fields, and still names an existing PR base before reading
or changing traffic E2E state.
`pr_base` is only the pull-request target. `prepare`, `run-api`, and `run`
require a named feature branch different from `pr_base`.
When `recorder_config` and `recording_rule` are configured, every focused and
full replay automatically passes both to replay. Replay loads the named rule's
`allowed_unused_http_hosts` once at startup; AI does not reimplement runtime
filtering.

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

For a dynamic route, also pass `--pattern '<safe-recorder-path-pattern>'`. Prepare
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

With replay-policy version two, the runner invokes the target facade as:

```bash
scripts/<project>-cli e2e \
  --case-dir <case-dir> \
  --actual-response <runner-owned-output>
```

The command reads only the recorded request, sends it through normal target
startup, and writes:

```json
{
  "version": 1,
  "status": 200,
  "body": {
    "encoding": "utf8",
    "data": "{\"content\":\"actual-value\"}",
    "truncated": false
  }
}
```

Command success means the actual response was captured, not that it matched.
The runner reads expected and actual artifacts, applies the response policy,
and persists field-level differences, diagnostic candidates, applied rules,
unused applicable rules, and policy fingerprints. Version-one policies retain
the legacy target-owned assertion contract for existing repositories.

Terminal focused attempts update cumulative progress and the selected API's
streaks. Once that API's effective thresholds are met, they run
verified-excludes ensure. They MUST NOT replace the full-round `latest`.

Fix an evidenced defect and rerun the same API. If later shared behavior changes
may invalidate an earlier focused pass, rerun the affected groups or use one
full regression round.

When the only remaining dirty evidence is a recorded HTTP exchange that the
target did not emit, inspect source before changing configuration. If the
entire dependency host is owned by an API-independent process-level task and
the focused API's response assertions and all other dependency evidence pass,
run:

```bash
traffic-recorder-config allowed-unused-http-hosts plan \
  --config <recorder-config> \
  --rule <recording-rule> \
  --host <dependency-host> \
  --format json

traffic-recorder-config allowed-unused-http-hosts apply \
  --config <recorder-config> \
  --rule <recording-rule> \
  --host <dependency-host> \
  --format json
```

The host applies to every case in the named recording rule; do not attribute it
to, enumerate, or merge active APIs. The AI supplies the source-verified host,
while plan/apply owns add-only config mutation. Restart the affected focused
run because replay reads the rule once at startup. Do not apply new recorder
feedback during a full round; return to focused diagnosis and restart the full
round afterward.

## Full Round

When behavior changes after earlier groups passed and a full regression is
therefore required, run:

```bash
traffic-e2e-run run \
  --target-root <target> \
  --case-source <case-source>
```

The command owns the entire round: one replay server, one bootstrap/full-case
load, one target start, sequential case begin/request/assert/end, one target
stop, one replay finalize, a global aggregate, per-API evidence views,
eligible verified-excludes ensure, progress update, and atomic publication.

Do not repair code inside a full round. If it fails, use focused `run-api` to
diagnose and fix, then restart the full regression when it remains required.
Progress reaches `status: complete` only after every API meets both verification
thresholds configured in `.traffic-e2e/e2e.yaml`.

## Completion

- Terminal focused and full rounds advance API streaks only from finalized,
  complete, clean evidence.
- Human progress uses `status: in_progress` until every API is verified.
- An API is `verified` only when its trailing successful rounds meet both its
  effective configured round count and case-execution count.
- Re-publishing the same terminal sequence is idempotent.

## Generated State

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
```

`.traffic-e2e/replay.yaml` and `.traffic-e2e/recorder.toml` are source-controlled
migration inputs.
`e2e.yaml` is generated by `init`; all files under `local/` and every JSON/YAML
evidence file inside active, focused, and latest directories are generated by
the runner. AI MUST NOT hand-edit generated files. `e2e-progress.yaml` is the
concise, Git-eligible human report; it omits protocol, connection, policy,
session, aggregate, root-cause, and repair detail. It reports only executed,
successful, and trailing-success counts for runs and cases, globally and for
every API. The case streak is the number of executions covered by trailing
successful rounds; a non-successful round resets it. Changed source or case
inventory starts new streaks. Detailed failure categories remain in local
evidence.

Use `status`, `abort`, or `recover` for an interrupted full round. Never copy
partial focused evidence into the global `latest`.
