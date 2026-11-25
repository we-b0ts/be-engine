# Source Session Regression

Use this workflow for the sealed event recording produced by `traffic-e2e
record`. The coordinator owns Replay, evidence routing, and publication of
integrated code. The Issue Analyst traces Source behavior and observed Target
behavior read-only.
Implementers repair reviewed findings in assigned worktrees. The integrator
combines their committed changes for the next full Replay.

## Run the selected recording

The external recording owner stops the recorder normally, letting it stop
Source and seal the run, then hands over the full recording directory.
Preserve the manifest, `events.tsv`, dependency data, and payload segments
together. Follow the
[recording handoff](coordinator-recording.md) for missing or incomplete evidence.

From the canonical Target, use `status` to locate the round or start one from
the configured `project.delivery.pr_base`. Select the sealed recording by its
14-digit directory name under `.traffic-e2e/local/artifacts/recordings/`. Obtain
explicit caller approval before supplying `--user-confirm`.

```sh
be-replay --target-root /absolute/target status
be-replay --target-root /absolute/target run --user-confirm --recording-run-id 20261123161021
```

The confirmed command creates a `codex/replay/YYYYMMDD-N` work branch, selects
the recording, and starts Replay. On a named work branch, use
`be-replay switch-recording-id ID` to change the active recording in the
current checkout. Use `be-replay run --recording-run-id ID` to select and
replay in one command. Plain `status` and `run` use the active recording.
Switching back restores that recording's run key, attempts and reviewed
workflow for the branch. Every new attempt launches an isolated Target on
the current committed code and replays from Source launch.
One Source timeline interleaves startup, readiness, concurrent ingress,
dependency admissions and deliveries, notifications, and shutdown. Replay
advances by sequence when the matching Target request or delivery receipt is
ready. Sequence numbers can have gaps. Use the primary request's
`exchange` reference to join its response events. Source offsets measure
recorded time for investigation. Replay adds zero delay for those intervals.
Real application waits and I/O still take time.

HTTP gateway rules select ingress at capture time. The API catalog in
`.traffic-e2e/apis.yaml` labels counts by method and route, using the literal
path for requests without a catalog match. Startup and background traffic
are verified on the same timeline.

## Inspect a Replay attempt

```sh
be-replay --target-root /absolute/target status
be-replay --target-root /absolute/target status --recording-run-id ID --run-key KEY --attempt-id UUID
```

`status` reports the current round and attempt. `status --recording-run-id ID`
previews a different recording and provides its selection command. For an
earlier attempt in the selected round, pass its exact `--attempt-id`.
Supply the recording ID and run key when reading a different round.
Status includes `recording_id`, `state`, `phase`, `progress`, `session`, and
`action`, with `failure` when available. Read the top-level `phase` to
distinguish Replay preparation, Target build, Target startup, event matching,
and finalization.
Before the first attempt, `phase` and `progress` are `null`.

`progress.events` shows the last reached Source sequence over the sealed
recording's final Source sequence, such as `17893/942000`. Source sequence
numbers can have gaps. Both values show the final sequence after Replay
completes. `progress.apis` shows verified API labels over the
total, such as `0/17`. A label is verified once every recorded primary
exchange under it has completed or been cancelled. An unavailable total
appears as `?`.

| State | Meaning and action |
| --- | --- |
| `not_started` | This recording and run key have no registered attempt. Start with `run`. |
| `running` | Replay is active. Check the running process and use the returned status query to inspect progress. |
| `interrupted` | The attempt ended without a terminal result. Start a fresh full attempt using `action.commands.run`. |
| `failed` | Read `failure` for the first divergence and follow `action` for the current workflow step. |
| `passed` | The selected attempt completed full Replay verification. |
| `candidate_changed` | The latest result covers earlier Target code or inputs. Follow the current action to verify again. |

`action.kind` drives the coordinator's workflow. `action.summary` describes
the step, `action.details` carries any scheduling information, and
`action.commands` provides argument lists for the applicable `be-replay`
workflow commands. Historical attempts have `action: null`.

| `action.kind` | Coordinator responsibility |
| --- | --- |
| `checkout_target_branch` | Check out a named branch. |
| `select_recording` | Select the exact sealed recording. |
| `confirm_regression` | Obtain caller approval and use the confirmed `run` command from the pull-request base. |
| `switch_recording` | Use `action.commands.switch` to select a different recording on the current branch. |
| `setup_required` | Resolve the setup error or route a confirmed engine issue to its owner. |
| `analysis_required` | Assign read-only investigation of the first divergence. |
| `implementation_required` | Assign currently eligible work and register each ready delivery. |
| `integration_required` | Integrate the selected deliveries, publish the candidate, and register its receipt. |
| `advance_required` | Start a full Replay with `action.commands.run`. |
| `wait_required` | Follow the active Replay or outstanding assignments and refresh `status`. |
| `complete` | Report the passing attempt and its verified revision. |

## Diagnose the first failure

Retain `recording_id`, `session.attempt_id`, `failure`, and `action`. The
compact `failure` can give `seq`, an `expected` event summary, a `reason`, and
a `target_observation_id`. `expected.kind` identifies the expected event.
`expected.dependency_sequence` identifies the corresponding dependency
admission when available.
A failed `run` with a Replay result prints JSON before exiting unsuccessfully.
For `setup_required`, the coordinator uses the reported error to resolve the
recording, configuration, or launch inputs. `failure.seq` identifies the
failed Source read or preparation position when available.

When `action.kind` is `analysis_required`, check the task runtime and reuse an
active `issue-analyst` for the same attempt. Otherwise dispatch one read-only
analyst with `recording_id`, `session.attempt_id`, `failure.seq`, and the Source
and Target repository locations and revisions. Include the expected event
summary and any Target observation ID. The analyst groups related problems by
likely shared repair and returns concise findings. The first failed Source
sequence belongs in `first_unmatched.sequences`.

Run the evidence queries from the canonical Target or provide
`--target-root /absolute/target`.

- `events --recording-run-id ID --seq SEQ` reads the exact Source event.
  Repeat `--seq` to read multiple exact positions. Explicitly selected server
  push deliveries appear even without `--with-push-event`.
- `events --recording-run-id ID --from-seq SEQ --window-seconds 60` reads
  the surrounding Source window. Start before the expected event. Continue
  with `--after-seq` set to `next_after_sequence`, keeping the start, window,
  and push visibility options. Default pages hide server push delivery events.
  Add `--with-push-event` to show them. Client
  requests such as `PUBLISH` and `SUBSCRIBE` are always visible. This display
  option applies to the event query. Use `--payload` only when protected
  primary HTTP payloads are necessary.
- `dependency --recording-run-id ID SEQ` reads the protected semantic request
  and result for a dependency's **admission** sequence. The exact Source event
  may identify it in `dependency_sequence`.
- `target --attempt UUID OBSERVATION_ID` reads an authenticated Target
  observation for the active recording using the exact attempt and observation
  ID. Use `--report /absolute/report.json` to read a specific report file.

Follow the earliest divergence to the relevant Source behavior and actual
Target call or response. Later Source events can support analysis of a shared
cause. They receive verification credit only after a fresh Replay reaches them.
Share sequence references and bounded facts, keeping protected contents private.
See [dependency diagnosis](api-implementer-dependency-diagnosis.md),
[runtime diagnosis](api-implementer-runtime-diagnosis.md), and
[rule diagnosis](api-implementer-rule-diagnosis.md) for protocol-specific decisions.

## Plan, implement, and verify

The coordinator reviews the analyst's findings and runs `action.commands.plan`
with a JSON object. The command uses the active recording and `--attempt-id`
binds the submission to the failed attempt. The first submission requires
`first_unmatched`, a finding with `failure.seq` in `sequences`. Use optional
`others` for further findings from the same attempt. Include relevant
earlier Source sequences in the corresponding finding. Submit an object
containing only `others` to add findings before registering the candidate.

Each finding has these fields.

| Field | Contract |
| --- | --- |
| `root_cause` | Free-form, nonempty string used as a stable group ID for symptoms that appear to share one repair |
| `summary` | Short description of the problem |
| `sequences` | Nonempty list of positive Source sequence numbers |
| `scope` | Optional string for ownership or lifecycle, such as `startup`, `api:GET /users/{id}`, `job:sync_users`, `shutdown`, or `shared` across scopes |

An example `findings.json` for a failure at sequence `42` follows.

```json
{
  "first_unmatched": {
    "root_cause": "startup_cache_lookup",
    "summary": "Replay stops at the startup cache lookup required for readiness.",
    "sequences": [42],
    "scope": "startup"
  }
}
```

Use one `root_cause` for symptoms that appear to share one repair. The planner
prioritizes `first_unmatched` and fills available slots with distinct groups.
`--max-implementers` accepts 1 to 16 and defaults to 16. The coordinator
dispatches each group in a separate worktree and handles overlapping edits
when integrating fixes. Use `plan` to revise findings whose work has yet to
be assigned.

Give each implementer its reviewed finding, evidence query context, frozen
base, and absolute worktree. The implementer confirms the cause and repairs
Target behavior or a Source-proven time, ID, or token policy. The implementer
returns the exact commit and focused check results, with any required
startup inputs. See the
[rule contract](rule-policy.md) and [startup input interface](coordinator-startup-inputs.md).

Keep findings and receipt files under the ignored Target runtime directory or
outside the Target checkout. Submit each ready set of fixes with
`be-replay report --file /absolute/fixes.json`. The receipt uses the originating
attempt's UUID. For each fix, use the reviewed `root_cause`, full commit SHA,
and the checks from the delivery. The engine combines accepted deliveries
for the attempt. Independent unfinished work can continue while Replay
advances. Submit deliveries after the running Replay releases the round lock.

```json
{
  "kind": "fixes",
  "attempt_id": "11111111-1111-4111-8111-111111111111",
  "fixes": [
    {
      "root_cause": "startup_cache_lookup",
      "commit": "1111111111111111111111111111111111111111",
      "checks": ["startup cache regression passed"]
    }
  ]
}
```

If the implementer confirms an engine gap, the coordinator verifies the
observation and registers it with `be-replay report --file /absolute/engine-gap.json`.
Use the assignment's attempt and group ID. Include the exact observation and
the missing engine behavior in `evidence`.

```json
{
  "kind": "engine_gap",
  "attempt_id": "11111111-1111-4111-8111-111111111111",
  "root_cause": "startup_cache_lookup",
  "evidence": "Source seq 42 and the Target observation show the same Redis request on the expected connection. Replay rejects that request as unsupported before comparison."
}
```

Route the reported gap to the engine owner.

When `action.kind` is `integration_required`, give the integrator the first
unmatched group's fix and frozen base. After validation, publish the exact
candidate to the canonical work branch. Submit it with
`be-replay report --file /absolute/candidate.json`.
`commit` must be the canonical branch's current `HEAD`. Put the delivered
fix's SHA in `included_fixes`. Use the current failed attempt UUID.

```json
{
  "kind": "candidate",
  "attempt_id": "11111111-1111-4111-8111-111111111111",
  "commit": "2222222222222222222222222222222222222222",
  "included_fixes": ["1111111111111111111111111111111111111111"],
  "checks": ["repository validation passed"]
}
```

Follow `advance_required` to run the same complete recording against the
published candidate. For `setup_required`, use the offered retry command
after resolving the execution error or confirmed engine issue.

`status` reports `action.kind` as `complete` after verification. The `run`
result reports `session.passed` and requires the complete event sequence and
strict finalization. Its `apis` field shows recorded and
verified primary exchanges. A response end or recorded cancellation completes
an exchange. Readiness probes contribute only to event verification. A passing
session with recorded API exchanges contributes once per sealed run ID to
`.traffic-e2e/progress.yaml`, preserving existing history. A repeat pass or
a session with no API traffic can have `progress_published: false`. Handle
any reported progress publication error from `run`.

[Engine session reference](../../../../../docs/session-regression.md)
