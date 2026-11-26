# Source session regression

`traffic-e2e record` captures a globally ordered Source session. Set HTTP
gateway rules before recording to select the ingress workload. The session
includes startup and background traffic at the configured capture points.
Recorder opens ingress at application readiness while already admitted I/O
continues on the same sequence.

Stop the recorder normally to seal the recording. Keep its
`dependency-manifest.json` and the full recording tree together. One
`events.tsv` lists startup, primary HTTP, dependency exchanges, notifications
and shutdown in increasing Source sequence. The first three columns are
`seq`, `offset_us` and the event kind. Sequences can have gaps. An HTTP
response refers to the sequence of its primary request.

Body references name a segment, byte offset and length under `payload/`.
Structured dependency requests and responses each have one `fields-path:`
reference. Embedded binary values remain raw segment slices. Exact protocol
responses such as MySQL zero OK, Redis RESP2 `+OK` and Redis RESP2 null bulk use
`const:` references to a shared response in the sealed dependency term table.
Session dependency rows encode capture phase and default ownership, effect
index and empty Case links in the existing `d=` metadata field.
The `t=` tuple gives the capture clock as a nanosecond offset from the term
table's UTC anchor, followed by request-start and protocol timestamp offsets
relative to that capture clock. A dash leaves the corresponding field outside
the tuple. The monotonic `offset_us` column still drives event ordering.
Recorder publishes `session-summary.live.json` periodically and seals the
final route counts, first request sequences, and capture totals in
`session-summary.json`. Successful TCP connects with no exchange contribute to
connection counts. Observations used for protocol diagnosis remain available
in `observations.tsv`. The Recorder also seals the MySQL driver and transaction
decisions derived from the facts collected as exchanges were recorded.

Replay authenticates timeline chunks as it reads and fills a rolling window in
Source sequence order. Notifications carry their payload reference before the
wire output begins. Ordinary exchanges put their semantic record on the same
timeline when capture completes. A forward reader can look ahead to that row
when Replay reaches its admission, using a temporary file for displaced records
that exceed the in-memory window. Redis notifications and primary HTTP chunks
can use raw bytes through the segment reader. Treat sealed files as read-only
throughout Replay.
During shutdown, the recorder closes admission and gives active ingress up to
15 seconds to finish. It records `primary_cancel` with reason `engine_shutdown`
for each remaining request and disconnects it before stopping Source. Replay
disconnects the corresponding Target request at that event's sequence.
If Recorder initiates a normal stop and the Source outlasts its SIGTERM
deadline, Recorder can finish cleanup with SIGKILL. It records the raw exit
status and the verified Recorder-forced disposition. Recording completeness
still depends on the live capture ledger and the normal seal checks. Replay
matches the recorded shutdown events through Source exit and accepts a Target
that completes its requested stop with status 0 or 143.
Protocol adapters handle canonical transport maintenance locally. Replay
validates the evidence for driver setup or cleanup before omitting the
corresponding recorded exchanges from the required sequence.

Place the complete recording under
`.traffic-e2e/local/artifacts/recordings/<run-id>/` in the Target repository.
Initialize the Target once with `be-replay init`. Start with `status` on
`project.delivery.pr_base`, usually `dev-migration`. After the caller approves
a new round, pass the exact 14-digit recording ID to the confirmed command.

```sh
be-replay --target-root /absolute/target status --recording-run-id 20261123161021
be-replay --target-root /absolute/target run --user-confirm --recording-run-id 20261123161021
be-replay --target-root /absolute/target status
```

The confirmed `run` creates a `codex/replay/YYYYMMDD-N` work branch and
selects the recording. Follow `api_review_required` to confirm every API
before the first Replay. Replay can start while implementers work on the
missing APIs. On a named work branch, `switch-recording-id` changes the active
recording in the current checkout.

```sh
be-replay --target-root /absolute/target switch-recording-id 20261125113932
be-replay --target-root /absolute/target apis
be-replay --target-root /absolute/target plan --findings /absolute/apis.json
be-replay --target-root /absolute/target run
```

Plain `run` and `status` use the active recording. Switching back restores
that branch's run key, attempts and reviewed workflow for the selected
recording. Each new attempt replays from Source launch.

`status --recording-run-id ID` previews a different recording and provides
the command to select it. To inspect a specific earlier attempt, supply
`status --attempt-id UUID` with its recording ID and run key when needed to
select the history.
The response includes `recording_id`, `state`, `phase`, `progress`, `session`,
`failure` when available, and `action`. Attempt states are `not_started`,
`running`, `interrupted`, `failed` and `passed`.
Current-round status uses `candidate_changed` when a pass covers older Target
code or inputs or when a different commit supersedes a failure without a
reviewed repair. `session.attempt_id` identifies the attempt. `session` can
also include the Target commit for that attempt. `failure` can give `seq`,
an `expected` event summary, a `reason`, and a `target_observation_id`.
`action` contains a `kind` and a short `summary`, with optional `details` and
`command`. When present, `action.command` is an argument array for
`be-replay`, such as `["status"]`. Historical attempts have `action: null`.

When the action has assignments, `status` lists each `group`, its `pending`
item count, and the reserved worker `name` and `worktree` under
`action.details.assignments`. Use `status --with-assignments` for the
`assignment_id`, frozen base, and each item's scope, sequences, and applicable
API work.

The top-level `phase` advances through `preparing_replay`, `building`,
`starting_target`, `replaying`, and `finalizing`, then reaches `complete` after a
pass. Before the first attempt, `phase` and `progress` are `null`.

```json
{"phase":"replaying","progress":{"apis":"0/17","cases":"3/150","events":"17893/942000","previous_events":"4337/942000"}}
```

`progress.events` shows the last reached Source sequence over the sealed
recording's final Source sequence. Source sequence numbers can have gaps.
The numerator reaches the final sequence when Replay completes the timeline.
`progress.previous_events` shows the preceding attempt's endpoint in the same
format when its progress snapshot is available. Older rounds can populate
this field when the next attempt starts.
`progress.cases` counts completed ingress requests over recorded ingress
requests, excluding readiness checks. Matching a recorded cancellation counts
as completing the exchange.
`progress.apis` shows verified API labels over the total from the sealed route
inventory after applying `.traffic-e2e/apis.yaml`. An API label is verified
once all its recorded primary exchanges have completed or matched their
recorded cancellation. An unavailable total appears as `?`.

| `action.kind` | Coordinator action |
| --- | --- |
| `checkout_target_branch` | Check out a named branch. |
| `select_recording` | Obtain the exact ID of a sealed recording. |
| `switch_recording` | Run `action.command` to select the recording on the current work branch. |
| `confirm_regression` | Obtain caller approval and use the confirmed `run` command. |
| `configuration_commit_required` | Review the paths in `action.details.files`, commit the intended configuration, and check `status` again. |
| `setup_required` | Resolve the setup error or route a confirmed engine issue to its owner. |
| `api_review_required` | Submit a confirmation for every recorded API before the first Replay. |
| `ownership_required` | Have an Issue Analyst identify the scope and group of `failure.seq`. Dispatch any available API assignments in parallel. |
| `implementation_required` | Dispatch the engine's groups using their assigned worktree paths and accept tested fixes as they arrive. |
| `integration_required` | Integrate the selected fixes, validate and publish the candidate, and submit its receipt. |
| `advance_required` | Run `action.command` to start a full Replay on the selected revision. |
| `wait_required` | Check active Replay or outstanding assignments and use `status` to follow progress. |
| `complete` | The selected revision has passed Replay and required API work is complete. |

The engine checks that `.traffic-e2e/project.yaml`, `.traffic-e2e/apis.yaml`,
and the effective policy are committed before `run`, `plan`, and candidate
publication. Paths in `action.details.files` are relative to the Target root.

After a mismatch, an eligible new committed engine revision can trigger
`advance_required` with `action.details.reason` set to `engine_changed`. This
runs the same Target code again, including any configuration-only commits.
The round grants one such retry for the new engine revision. Rebuilding the
same revision or returning to an already tried revision uses the existing
retry identity.

```mermaid
flowchart LR
    select[Select recording] --> review[Confirm all recorded APIs]
    review --> replay[Full Replay]
    review -->|missing implementations| work[Implementer groups]
    replay -->|first failed Source seq| window[Find APIs in next 60 seconds of Source time]
    window -->|API groups and known owner| work
    window -->|failed event owner unknown| analysis[Issue Analyst]
    analysis -->|scope and group of failed seq| work
    replay -->|execution error| setup[Coordinator resolves setup]
    setup --> replay
    work -->|engine gap covering failed seq| setup
    work -->|tested fix covering failed seq| integration[Integrator]
    integration -->|registered candidate commit| replay
    replay -->|full pass with API work complete| complete[Complete]
```

## Inspect evidence

The coordinator handles `setup_required`, including unreadable Source
artifacts. `failure.seq` identifies the Source position when available. An
event failure stops delivery at the first divergence. The engine looks ahead
60 seconds of Source time from each distinct failed sequence and assigns API
work from the previously uncovered part of the window. Repeated failures at
the same sequence reuse its window. The engine assigns the
failed sequence directly when a recorded request link or lifecycle event
establishes its owner. At `ownership_required`, give one analyst the recording and
attempt IDs, `failure.seq`, and the Source and Target revisions. The analyst
returns the scope and group of that sequence while other assignments proceed.

Read the exact Source event and page the surrounding timeline using the
recording ID and sequence from status. Use `--from-seq` before the failure to
see preceding requests.

```sh
be-replay --target-root /absolute/target events --recording-run-id ID --seq SEQ
be-replay --target-root /absolute/target events --recording-run-id ID --from-seq 182 --window-seconds 60
```

Use `--after-seq` with the same `--from-seq` and window to continue a page series.
Lower `--from-seq` when the related request precedes the failure. The default
page hides server push notification lifecycle rows and includes client
commands such as Redis `PUBLISH` and `SUBSCRIBE`. Add `--with-push-event` to
show the push rows in a page. Repeat `--seq` to select exact events, including
push rows. Replay still verifies the full recorded sequence. Use
`events --payload` when analysis needs the protected primary HTTP payload.
Use `be-replay dependency <seq>` for the protected request and result
associated with a dependency admission. Use `be-replay target --attempt ID
OBSERVATION_ID` for the authenticated Target observation named by `failure`.
Explicit `--report` remains available for reading a specific report file.

## Plan, implement, and verify

Before the first Replay, `be-replay apis` lists each API label and its
recorded literal paths, request count, first sequence, case pattern, and
group. Check each handler and the effective Target routes for all of its
paths. Submit the complete `apis` review with `be-replay plan --findings FILE`.
Include `implemented` for every API and propose a case pattern and group
for uncatalogued APIs. The coordinator can start Replay while the
assigned groups implement missing APIs and catalog entries.

For a requested owner, submit `ownership` with the current `failure.seq`,
`scope`, and `group`. Use `api:METHOD /path` and the catalog group for
an API, or `job:NAME`, `startup`, or `shutdown` with the group responsible
for the work. The engine assigns work from the API window and adds the
failed sequence to its owner's group. Each active group uses one worker
and a fixed path under `.traffic-e2e/local/rewrite-worktrees/api-implementer-<n>`.
Use `--max-implementers N` to set the number of available slots from 1 to 16.

Implementers diagnose the assigned events and deliver tested Target
changes or Source-proven time, ID, or token rules. Use
`be-replay report --file FILE` to register the group, `assignment_id`, exact
sequences, full commit ID, and checks. Register ready deliveries while Replay
is running. The assignment ID binds fixes, reviews, and engine-gap reports to
the recording that issued the assignment. A review can close assigned
lookahead sequences whose behavior already meets the Source contract. When an
implementer confirms an engine gap, register the evidence and route the gap
to the engine owner.

A delivery covering the failed sequence enables integration. The
coordinator may include other ready, compatible repairs while the rest
continue. Publish the validated candidate and register its exact commit,
included delivery commits, and checks against the current finished attempt.
Follow `advance_required` to start a full Replay. The engine verifies the
sequences when Replay reaches them. A full pass closes remaining lookahead
work. API implementation and catalog tasks required by the initial review
remain open until delivered and integrated. [Plan and report formats](../plugins/ai-engine/skills/be-replay/references/session-regression.md#plan-implement-and-verify)

Session Replay advances recorded I/O on the shared timeline as soon as its
matching request, delivery receipt, or timer gate allows it. Recorded intervals
add zero delay. Target execution and actual I/O still take real time.
Replay timer anchors refer to Source sequences. The engine can wake a graceful
shutdown wait at `source_exit`, after earlier events and final background
notifications have completed. [Replay timer mechanics](replay-timers.md)

Replay keeps identity mappings for the full session so later events can
refer to the same translated values. The sealed mandatory dependency count sets the
identity count budget, and retained values share a fixed memory limit.

Each recorded ingress request contributes one case to its HTTP method and
route in `.traffic-e2e/apis.yaml`. For requests absent from the catalog, the
label uses the literal path. A case is verified when its response or recorded
cancellation completes. Readiness probes and dependency traffic contribute
to event verification only.
The catalog labels the report. The replay workload is determined by the
recording, including all selected ingress, startup, and background events.
Each Session attempt starts at Source launch and matches the entire timeline.

`be-replay run` reports matched event counts and recorded and verified counts
per API. After all events pass in a session with API cases, it adds one
regression to `.traffic-e2e/progress.yaml` and retains existing API history. A sealed recording
contributes once across retries. The route labels used by the first successful
publication remain in the history if the catalog changes later. Failed attempts
and sessions without API cases retain their event reports. Check
`session.passed` for the Replay verdict and `progress_published` for publication.
The run result reports any progress-publication error separately.
