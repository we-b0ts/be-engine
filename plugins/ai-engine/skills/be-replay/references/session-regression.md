# Source Session Regression

Use this workflow for the sealed event recording produced by `traffic-e2e
record`. The coordinator owns Replay, evidence routing, and publication of
integrated code. The Issue Analyst groups uncatalogued API paths and
identifies the owner of the failed event when the engine asks. Implementers
diagnose and repair their assigned groups in dedicated worktrees. The
integrator combines selected changes for the next full Replay.

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

The confirmed command creates a `codex/replay/YYYYMMDD-N` work branch and
selects the recording. Follow `api_grouping_required` for new API paths and
commit the catalog produced by `plan`. Launch and register implementers at
`dispatch_required`. At `worker_status_required`, query the agent runtime
and report its status. Start Replay when the engine returns `advance_required`.
On a named work branch, use
`be-replay switch-recording-id ID` to change the active recording in the
current checkout. Plain `status` and `run` use the active recording.
Switching back restores that recording's run key, attempts and assignments.
API implementation work follows the branch across recordings.
Every new attempt launches an isolated Target on
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
be-replay --target-root /absolute/target status --with-assignments
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
numbers can have gaps. The numerator reaches the final sequence when Replay
completes the timeline. `progress.previous_events` uses the same format for
the preceding attempt when its snapshot is available. Older rounds can
populate this field when the next attempt starts.

`progress.cases` counts completed ingress requests over recorded ingress
requests, excluding readiness checks. Matching a recorded cancellation counts
as completing the exchange. `progress.apis` counts verified API labels over
recorded labels, such as `0/17`. A label is verified once every recorded primary
exchange under it has completed or matched its recorded cancellation.
An unavailable total appears as `?`.

| State | Meaning and action |
| --- | --- |
| `not_started` | This recording and run key have no registered attempt. Follow the returned action to prepare or start Replay. |
| `running` | Replay is active. Check the running process and use the returned status query to inspect progress. |
| `interrupted` | The attempt ended without a terminal result. Start a fresh full attempt using `action.command`. |
| `failed` | Read `failure` for the first divergence and follow `action` for the current workflow step. |
| `passed` | The selected attempt completed full Replay verification. |
| `candidate_changed` | The latest result covers earlier Target code or inputs. Follow the current action to verify again. |

`action.kind` drives the coordinator's workflow. `action.summary` describes
the step, and `action.details` carries any scheduling information. When
present, `action.command` is the argument array for the next `be-replay`
command, such as `["status"]`. Historical attempts have `action: null`.

Default `status` shows counts and the current action. Use `action.query`
when present to obtain supporting detail. `apis --ungrouped` lists the paths
that need grouping. `status --with-assignments` gives the worktrees, worker
states, full handoffs, and the ready fixes for an integration action.

| `action.kind` | Coordinator responsibility |
| --- | --- |
| `checkout_target_branch` | Check out a named branch. |
| `select_recording` | Select the exact sealed recording. |
| `confirm_regression` | Obtain caller approval and use the confirmed `run` command from the pull-request base. |
| `switch_recording` | Run `action.command` to select a different recording on the current branch. |
| `configuration_commit_required` | Review the paths in `action.details.files`, commit the intended configuration, and check `status` again. |
| `setup_required` | Resolve the setup error or route a confirmed engine issue to its owner. |
| `api_grouping_required` | Have the Issue Analyst group the uncatalogued API paths and submit the plan. |
| `ownership_required` | Identify the owner of `failure.seq` and submit its scope and group. Dispatch any available API assignments in parallel. |
| `dispatch_required` | Launch every assignment without an `agent_handle` in parallel and register the handles. |
| `worker_status_required` | Query the agent runtime for the registered handles and report their actual state. |
| `implementation_required` | Follow the registered implementers and register ready deliveries. |
| `integration_required` | Integrate the selected deliveries, publish the candidate, and register its receipt. |
| `advance_required` | Start a full Replay with `action.command`. |
| `wait_required` | Follow the active Replay or outstanding assignments and refresh `status`. |
| `complete` | Report the passing attempt and its verified revision after any required API work. |

The engine checks that `.traffic-e2e/project.yaml`, `.traffic-e2e/apis.yaml`,
and the effective policy are committed before `run`, `plan`, and candidate
publication. Paths in `action.details.files` are relative to the Target root.

When an updated engine qualifies for a retry after a mismatch, `status`
returns `advance_required` with `action.details.reason` set to `engine_changed`.
Run a fresh attempt against the same Target code. Commits limited to managed
configuration are eligible. The retry is keyed by committed engine revision.
Rebuilding at the same revision or returning to an already tried revision
uses the existing identity.

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

On a mismatch, the engine looks ahead 60 seconds of Source time from the
failed sequence and dispatches the API groups in the previously uncovered
part of the window. Another failure at the same sequence reuses that window.
A recorded request link or lifecycle event can establish the owner of the
failed sequence for direct assignment. Other work can proceed while the owner
is being determined.

For `ownership_required`, dispatch one read-only `issue-analyst` for
`failure.seq`. Include `recording_id`, `session.attempt_id`, the expected
event, any Target observation ID, and the Source and Target repositories
and revisions. The analyst identifies just the failed sequence's scope and
group. Assignments can still appear under `action.details.assignments`.

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

Use the exact event link or relevant Source call path when confirming
ownership. For diagnosis, implementers trace assigned events to the observed
Target call or response. Later Source events receive verification credit when
a fresh Replay reaches them. Share sequence references and bounded facts,
keeping protected contents private.
See [dependency diagnosis](api-implementer-dependency-diagnosis.md),
[runtime diagnosis](api-implementer-runtime-diagnosis.md), and
[rule diagnosis](api-implementer-rule-diagnosis.md) for protocol-specific decisions.

## Plan, implement, and verify

Use `be-replay apis --ungrouped` for the recorded paths that need grouping.
Use Source routes to supply `case_pattern` and `group` for each label and
submit them with `be-replay plan --findings FILE`. The proposed pattern
must match the recorded paths. Use the literal path for a static route.
Several literal paths for a dynamic route can share the same pattern and
group.

```json
{
  "apis": [
    {"api":"POST /reports/42","case_pattern":"/reports/*","group":"reports"}
  ]
}
```

The engine writes `.traffic-e2e/apis.yaml` and records implementation work
by method and pattern. Commit the updated catalog as requested by
`configuration_commit_required`. Previously catalogued paths reuse their
group. An HTTP method first seen in a later recording for a tracked route
becomes an implementation task in its existing group.

If `status` asks for the owner of a failed event, submit one record for that
sequence.

```json
{
  "ownership": {
    "seq": 42,
    "scope": "job:cache-refresh",
    "group": "cache-refresh"
  }
}
```

Use `api:METHOD /path` with the catalog group, `job:NAME` with its
implementation group, or `startup` or `shutdown` with the corresponding
group. Group names use 1–128 ASCII letters, digits, periods, underscores,
or hyphens.

Each active group gets one reservation. Different jobs and APIs can share a
group. `--max-implementers` accepts 1 to 16 and defaults to 16. Use
`status --with-assignments` for each group's `assignment_id`, `base_commit`,
and items, including their scopes, sequences, and applicable API work.
Resolve the reserved `worktree` against the canonical Target root. It uses
`.traffic-e2e/local/rewrite-worktrees/api-implementer-<n>`. Reuse the worker
and worktree when the engine adds items to the same group. Different recordings
can use the same slot. A recording switch restores that recording's own
assignment IDs and paths.

Use `status --with-assignments` to get the full handoffs. The engine counts
reservations without a registered handle in `action.details.pending_dispatch`.
Launch one worker for each of them. Use the actual ID returned by the agent
runtime in `agent_handle`. Submit registrations in one batch or as the launches
complete with `be-replay report --file /absolute/implementers.json`.

```json
{
  "kind": "implementers",
  "workers": [
    {
      "group": "cache-refresh",
      "assignment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "agent_handle": "agent-a1b2c3",
      "state": "started"
    }
  ]
}
```

At `worker_status_required`, actually query the runtime for each registered
handle with `worker_status: check_required` in the handoff. Submit the same
receipt with `state: running` for each active implementer. Running reports
expire after one hour. Report `state: exited` when a query confirms the worker
stopped before delivering, then register the replacement or resumed worker
on the same assignment. After a recording switch, check the agent runtime
before reusing the slot and registering its handle for the selected recording.
If API groups are still queued because all slots are in use, follow
`implementation_required` and register completed deliveries to open slots.
The first Replay starts after every selected API task has an accepted delivery
or a worker confirmed running. Run when `status` returns `advance_required`.

Give each implementer its items, evidence query context, frozen base, and
absolute worktree. The implementer diagnoses assigned events and delivers
tested Target changes or Source-proven time, ID, or token rules. Keep plan
and receipt files in the ignored Target runtime directory or outside the
checkout. Submit ready commits and exact sequences using
`be-replay report --file /absolute/fixes.json`. Copy `assignment_id` from the
full handoff into each fix and into each review or engine-gap receipt. This
binds the receipt to the assignment issued for that recording, including
after a recording switch. Submit it with that recording selected. Replay can
keep running while you register deliveries.
[Rule contract](rule-policy.md) · [Startup inputs](coordinator-startup-inputs.md)

```json
{
  "kind": "fixes",
  "fixes": [
    {
      "group": "cache-refresh",
      "assignment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "commit": "1111111111111111111111111111111111111111",
      "sequences": [42, 47],
      "checks": ["cache refresh regression passed"]
    }
  ]
}
```

For assigned lookahead sequences whose behavior already meets the Source
contract, submit a review with the checks performed. The current failed
sequence requires a repair or a confirmed engine gap.
If an implementer verifies an assigned API is already implemented, use the
same receipt with `"confirms_apis": true`, its exact assigned sequences, and
the checks that verified the active route and handler. The catalog must
already be committed for that API.

```json
{
  "kind": "review",
  "group": "reports",
  "assignment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "sequences": [88],
  "checks": ["report route and handler verified against Source"]
}
```

For a confirmed engine gap, include the evidence and required engine
behavior and route the report to the engine owner.

```json
{
  "kind": "engine_gap",
  "group": "cache-refresh",
  "assignment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "sequences": [42],
  "evidence": "Source seq 42 and the Target observation establish that an unsupported engine operation rejected the request before comparison."
}
```

When a new delivery covers the failed sequence, follow
`integration_required` and query the ready fixes with `status --with-assignments`.
Give the integrator the selected fixes and
canonical base. A candidate can include other ready, compatible deliveries.
Independent groups continue working. Publish the exact validated candidate
to the canonical branch and submit it with
`be-replay report --file /absolute/candidate.json`. Use the current
finished attempt's ID. The candidate's `commit` is the canonical branch's
current `HEAD`, and `included_fixes` contains the delivered commit SHAs.

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

Full Replay closes outstanding lookahead work. Required API implementation
tasks remain open until integrated or confirmed by a review of an existing
implementation. `status` reports `complete`
once the resulting revision passes and required API work is complete. The `run`
result reports `session.passed` and requires the complete event sequence and
strict finalization. Its `apis` field shows recorded and
verified primary exchanges. A response end or recorded cancellation completes
an exchange. Readiness probes contribute only to event verification. A passing
session with recorded API exchanges contributes once per sealed run ID to
`.traffic-e2e/progress.yaml`, preserving existing history. A repeat pass or
a session with no API traffic can have `progress_published: false`. Handle
any reported progress publication error from `run`.

[Engine session reference](../../../../../docs/session-regression.md)
