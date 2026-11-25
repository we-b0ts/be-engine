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

The confirmed `run` creates a `codex/replay/YYYYMMDD-N` work branch, binds
the recording to it, and verifies the isolated Target from process launch.
Further `run` and `status` commands on that branch use the same round and
recording. An existing named work branch with no round can start by passing
`--recording-run-id ID` to `run`.

`status` reads the current round and latest attempt. To inspect an earlier
attempt, supply `status --attempt-id UUID` with its recording ID and run key
when needed to select the history.
The response includes `recording_id`, `state`, `progress`, `session` and `next`. Attempt
states are `not_started`, `running`, `interrupted`, `failed` and `passed`.
Current-round status uses `candidate_changed` when a pass covers older Target
code or inputs or when a different commit supersedes a failure without a
reviewed repair. A managed attempt records the Target commit and input
fingerprint and adds the image ID when a build succeeds. `session` also
provides the attempt identity, event progress, report path and any error.
`next` gives the coordinator the current action.

An active attempt publishes a compact `progress` snapshot. The phase advances
through `preparing_replay`, `building`, `starting_target`, `replaying`, and
`finalizing`, then reaches `complete` after a pass. `events.matched` counts the
matched prefix. `events.total` is `null` until Replay knows the complete plan
size. `apis.total` is the number of API labels in the sealed route inventory
after applying `.traffic-e2e/apis.yaml`. `apis.verified` counts labels whose
recorded primary exchanges have all ended or been cancelled in the matched
prefix. Readiness probes contribute to event counts only.

| `next.action` | Coordinator action |
| --- | --- |
| `checkout_target_branch` | Use a named Target branch to enter the workflow. |
| `select_recording` | Obtain the exact ID of a sealed recording. |
| `confirm_regression` | Obtain caller approval and use the confirmed `run` command. |
| `run_regression` | Start or rerun Replay on the round's work branch. |
| `wait_for_session` | Follow the returned status command while Replay is active. |
| `rerun_interrupted_session` | Start a fresh full attempt with the bound recording. |
| `inspect_session_setup` | Investigate the attempt's setup error and available report. |
| `analyze_session_failure` | Inspect the first divergence and submit reviewed findings. |
| `review_findings` | Resolve findings that stay with the coordinator. |
| `implement_fixes` | Dispatch the plan, collect tested commits, and submit a fixes report. |
| `integrate_candidate` | Integrate the reported fix commits, validate and publish the candidate, and submit its report. |
| `verify_candidate` | Replay the bound recording on the published candidate. |
| `restore_candidate` | Restore the registered candidate or register a newly reviewed candidate covering the same accepted deliveries. |

Unreadable Source artifacts lead to `inspect_session_setup`. When the failing
position is available, `next.source_sequence` gives its Source sequence.

An event failure stops delivery and returns the expected Source sequence.
`next.event` selects that exact event. `next.events` queries Source context
starting there. For example, page through the original Source minute starting
at sequence 182:

```sh
be-replay --target-root /absolute/target events --from-seq 182 --window-seconds 60
```

Use `--after-seq` with the same `--from-seq` and window to continue a page series.
Lower `--from-seq` when the related request precedes the failure. The default
page hides server push notification lifecycle rows and includes client
commands such as Redis `PUBLISH` and `SUBSCRIBE`. Add `--with-push-event` to
show the push rows in a page. Repeat `--seq` to select exact events, including
push rows. Replay still verifies the full recorded sequence. Use
`events --payload` when analysis needs the protected primary HTTP payload.
Use `be-replay dependency <seq>` for the protected request and result
associated with a dependency admission. Use
`be-replay target --report <absolute-report> <id>` for the authenticated
Target observation identified by that attempt.
Use `be-replay plan --findings FILE` to register reviewed findings against the
latest eligible failure. Supply `--attempt-id` to require its exact identity.
The planner deduplicates findings by cause and selects independent work with
`--max-implementers N` (1 to 16, default 16). Findings include the shared cause,
summary, disposition, evidence basis, Source sequences, and proposed code
paths. Findings that require additional analysis or an engine change return to
the coordinator. Events after the failure provide context for investigation
and receive no verification credit until a later Replay reaches them.

Submit ready fixes with `be-replay report --file FILE`. A report of kind
`fixes` binds the failed attempt ID to each reviewed cause, exact fix commit,
and checks. Have the integrator validate the combined candidate and publish
its exact commit to the canonical work branch. A report of kind `candidate`
binds the same failed attempt ID to the published commit, the included fix
commits, and the candidate checks. The candidate commit must be the work
branch's current `HEAD`. Follow `status` to verify it against the full
recording. [Finding and report formats](../plugins/ai-engine/skills/be-replay/references/session-regression.md#plan-implement-and-verify)

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

`be-replay run` reports recorded and verified counts per API. After all
events pass in a session with API cases, it adds one regression to
`.traffic-e2e/progress.yaml` and retains existing API history. A sealed recording
contributes once across retries. The route labels used by the first successful
publication remain in the history if the catalog changes later. Failed attempts
and sessions without API cases retain their event reports. Check
`session.passed` for the Replay verdict and `progress_published` for publication.
The run result reports any progress-publication error separately.
