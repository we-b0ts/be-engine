# Standard Traffic E2E Runner

This reference is owned by the `traffic-e2e` skill.

Use `traffic-e2e` as the only normal AI-facing replay command. Low-level
grouping, replay-control, and aggregate commands remain implementation details
and human diagnostic surfaces.

## Contents

- Initialize target configuration
- Prepare an API
- Focused verification loop
- Full round
- Completion
- Generated state

## Initialize Target Configuration

Generate and validate the source-controlled `.traffic-e2e/project.yaml` once:

```bash
traffic-e2e config project init --target-root <target>
```

Do not hand-write the YAML. The initializer requires the standard executable
`scripts/<project>-cli`, initialized recorder and replay documents, an ignored
`.traffic-e2e/local/`, and a local or `origin/dev-migration` branch. It
generates:

```yaml
version: 5
project_cli: scripts/<project>-cli
replay_policy: .traffic-e2e/verification.yaml
replay_startup_timeout_seconds: 60
pr_base: dev-migration
recorder_config: .traffic-e2e/recorder.toml
recording_rule: record-api
local_root: local
```

`replay_startup_timeout_seconds` is the replay readiness deadline and defaults
to 60 when absent from an older config. The runner prints an initial
`loaded_cases=0` dependency-loading event, then relays progress about every 5%
by loaded case count while retaining the complete replay log. After readiness,
the runner prints `completed_cases=0` and case-execution progress about every
5% by completed case count, including the final 100% event. Small focused
groups report each completed case.

The E2E runner reports replay execution as `passed`. It does not mark an API
permanently verified and never edits recorder scope after a pass. Current
validation success comes from the later comparison report, which reports both
case-level and API-level passed counts.

The target repository MUST ignore `.traffic-e2e/local/` before initialization.
The initializer refuses to replace existing configuration unless an obsolete
generated version is explicitly regenerated with
`traffic-e2e config --target-root <target> project init --force`.
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
traffic-e2e prepare \
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

## Focused Verification Loop

Run one complete API group while implementing and repairing behavior:

```bash
traffic-e2e run-api \
  --target-root <target> \
  --case-source <case-source> \
  --api '<group.group_id>'
```

One focused attempt starts replay once for that API's cases, loads applicable
startup Global dependencies once, starts the target once, executes every case
sequentially, and finalizes once. It publishes only the API's focused `latest`
snapshot.

With replay-policy version two, the runner invokes the target facade as:

```bash
scripts/<project>-cli e2e \
  --case-dir <case-dir> \
  --actual-response <runner-owned-output>
```

When the recorded `request.json` contains encrypted request-header values, the
runner authenticates and decrypts them with
`TRAFFIC_E2E_ENCRYPTION_KEY_B64`, creates a private `0600` short-lived case
view under runner-owned local state, and passes that view as `--case-dir`.
Other case artifacts remain links to the immutable source. The view is removed
after the case command returns and before runner state is published. The
project CLI reads ordinary header values and must not load the key or implement
decryption. Missing, invalid, or wrong key material fails replay startup.

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
unused applicable rules, and policy fingerprints. A response rule whose
Pointer is absent from both sides does not participate in that case and does
not require coverage elsewhere in the API group. Version-one policies retain
the legacy target-owned assertion contract for existing repositories.

Run `run-api` only until the current complete API group passes. Once it passes,
stop.
Terminal focused attempts replace that API's final contribution to the current
logical run, while every finalized attempt is counted once in
`.traffic-e2e/replay-progress.yaml`. Reprocessing the same published attempt is
idempotent. Focused attempts MUST NOT replace the full-round `latest`.

After the calling orchestrator fixes an evidenced target defect, rerun the same
API. If later shared behavior changes may invalidate an earlier focused pass,
rerun the affected groups or use one full regression round.

After response assertions pass, when a recorded case HTTP exchange remains
unused, use [failure-diagnosis.md](failure-diagnosis.md) to establish its source
owner and independence. When that proof succeeds, follow the evidence-gated
selector and `plan|apply` contract in
[background-dependencies.md](background-dependencies.md). That reference is
the authority for rule shape, command arguments, evidence validation, and
matched-case review.

Applying a background rule changes future recording attribution only. Create a
new recording and replay that new case source; restarting replay against the
old immutable recording cannot make it clean. Do not apply recorder feedback
during a full round; return to focused diagnosis and restart the full round
with the new recording afterward.

For an immutable older recording that cannot be replaced, use
`allowed-unused-http-hosts plan/apply` only when source proves every request to
the entire host is unrelated to every selected API. This is a replay
compatibility exception, not the normal background-classification workflow.

## Full Round

When behavior changes after earlier groups passed and a full regression is
therefore required, run:

```bash
traffic-e2e run \
  --target-root <target> \
  --case-source <case-source>
```

The command owns the entire round: one replay server, one Global/full-case
dependency load, one target start, sequential case begin/request/assert/end,
one target stop, one replay finalize, a global aggregate, per-API evidence
views, progress update, and atomic publication.

Do not repair code inside a full round. If it fails, use focused `run-api` to
diagnose and return `target_behavior`; after the calling orchestrator repairs
it, restart the full regression when it remains required. Progress reaches
`status: complete` after every API in the current logical run
passes. Comparison verification remains a separate, repeatable phase.

## Completion

- Terminal focused and full attempts update the current logical run only from
  finalized, complete, clean evidence.
- Human progress uses `status: in_progress` until every API in the current
  logical run passes.
- An E2E pass proves replay compatibility only. A subsequent comparison report
  is the authority for current API validation success.
- Re-publishing or replaying the same run is idempotent for run and case counts.

## Generated State

```text
.traffic-e2e/
├── project.yaml
├── verification.yaml
├── recorder.toml
├── replay-progress.yaml
├── comparison-progress.yaml
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

`.traffic-e2e/verification.yaml` and `.traffic-e2e/recorder.toml` are
source-controlled verification inputs.
`project.yaml` is generated by `init`; all files under `local/` and every JSON/YAML
evidence file inside active, focused, and latest directories are generated by
the runner. AI MUST NOT hand-edit generated files. `replay-progress.yaml` and
`comparison-progress.yaml` are concise, Git-eligible reports with the same
schema: lifetime `totals`, the current `success_streak`, `latest_run`, and
per-API totals and streaks. `run-api` and `run` update only replay progress;
`compare` updates only comparison progress. A run passes globally only when
every selected API passes, and changing the selected API scope starts a new
global streak. The runner migrates legacy `e2e-progress.yaml` into replay
progress on the next finalized replay attempt. Detailed failure categories
remain in local evidence.

Run `status` first for an interrupted full round. Use `recover` to restore an
interrupted atomic publication or abort a surviving global `.active`; use
`abort` to publish an explicit interrupted full-round failure. Never repair
runner state through filesystem operations or copy partial focused evidence
into the global `latest`.
