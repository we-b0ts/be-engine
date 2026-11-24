# Source session regression

Enable session capture with `traffic-e2e record --session-events` or
`recorder.recording.session_events: true` in the recording project. Set HTTP
gateway rules before recording to select the ingress workload. The session
includes startup and background traffic at the configured capture points.
Recorder opens ingress at application readiness while already admitted I/O
continues on the same sequence.

Stop the recorder normally to seal the recording. Keep its
`dependency-manifest.json` and the full recording tree together. Primary
events in `request-response.tsv`, dependency events in `dependencies.tsv`,
and notifications in `dependencies-push.tsv` share one recording sequence.
Session recording stores each dependency by its event kind and uses a single
scope index to locate dependency records.
Protocol adapters handle canonical transport maintenance locally. Replay
validates the evidence for driver setup or cleanup before omitting the
corresponding recorded exchanges from the required sequence.

Set `recording_run_id` in `.traffic-e2e/regression.yaml` to the new recording
directory name and run:

```sh
backend-rewrite --target-root /absolute/target session run
```

The session starts the isolated Target and verifies from process launch. The
runner reports matched and total events. A failure stops event delivery and
publishes the failed sequence and an evidence query. The following query pages
through the original Source minute starting at sequence 182:

```sh
backend-rewrite --target-root /absolute/target session events --from-seq 182 --window-seconds 60
```

Use `--after-seq` with the same `--from-seq` and window to continue a page series.
Repeat `--seq` to inspect the events referenced by one finding.
Use `session dependency <seq>` for the protected request and result associated
with a dependency admission. Use `session target --report <absolute-report> <id>`
for the authenticated Target observation identified by that attempt.
Use `session plan --findings <absolute-json-file>`
to deduplicate reviewed findings and select independent implementations with
`max_implementers`. Findings include the shared cause, summary, disposition,
evidence basis, Source sequences, and proposed code paths. Findings that
require additional analysis or an engine change return to the coordinator.
The coordinator can give an analyzer the evidence query from the failed run,
adjust the window, and assign each implementer the sequences for one reviewed
finding. Implementers can also query the full Source timeline. Events after
the failure provide context for investigation and receive no verification
credit until the next replay reaches them.

With fast replay, the engine advances recorded I/O on the shared timeline.
For a Target-owned periodic wait, use a [Replay timer](replay-timers.md) with
the scope `cases.session` and a recorded dependency request as its wake
anchor. Use `TRAFFIC_E2E_REPLAY_TIMER_PLAN` to select the plan for the run.
A graceful shutdown wait can use `before_event` with the `source_exit`
sequence. The wait wakes after earlier events have completed, so background
connections can receive their final recorded notifications before Target exits.
Client-enforced deadlines still require instrumentation at their own wait
sites to preserve whether completion or timeout occurred first.

Replay keeps identity mappings for the full session so later events can
refer to the same translated values. The authenticated plan sets the
identity count budget, and retained values share a fixed memory limit.

Each recorded ingress request contributes one case to its HTTP method and
route in `.traffic-e2e/apis.yaml`. For requests absent from the catalog, the
label uses the literal path. A case is verified when its response or recorded
cancellation completes. Readiness probes and dependency traffic contribute
to event verification only.
The catalog labels the report. The replay workload is determined by the
recording, including all selected ingress, startup, and background events.
Each Session attempt starts at Source launch and matches the entire timeline.

The session command reports recorded and verified counts per API. After all
events pass in a session with API cases, it adds one regression to
`.traffic-e2e/progress.yaml` and retains existing API history. A sealed recording
contributes once across retries. The route labels used by the first successful
publication remain in the history if the catalog changes later. Failed attempts
and sessions without API cases retain their event reports.
