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

The confirmed command creates a `codex/replay/YYYYMMDD-N` work branch, binds
the recording to that branch, and starts Replay. To start on an existing
named work branch with no round, pass `--recording-run-id ID` to `run`.
Subsequent `status` and `run` reuse the bound recording. Every attempt
launches an isolated Target against the current committed code and exercises
the entire recording.
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

`status` reports the current round and attempt. For an earlier attempt, pass
its exact `--attempt-id`, recording ID and run key. Status includes
`recording_id`, `state`, `progress`, `session`, and `next` when available.
Read `progress.phase` to distinguish Replay preparation, Target build,
Target startup, event matching, and finalization. `progress.events` shows the
matched count and the plan total when known. `progress.apis` shows how many
recorded API labels have completed every primary exchange in the matched prefix.

| State | Meaning and action |
| --- | --- |
| `not_started` | This recording and run key have no registered attempt. Start with `run`. |
| `running` | Replay is active. Check the running process and use the returned status query to inspect progress. |
| `interrupted` | The attempt ended without a terminal result. Use the returned `run` command to start a fresh full attempt. |
| `failed` | Inspect the terminal error and available evidence queries. |
| `passed` | The selected attempt completed full Replay verification. |
| `candidate_changed` | The latest result covers earlier Target code or inputs. Follow the current action to verify again. |

`next` identifies the workflow step. On the pull-request base, use
`select_recording` and `confirm_regression` to select the input and obtain
approval. A round ready for its initial attempt uses `run_regression`. After a
failed attempt, follow the evidence query and `review_findings` for work the
coordinator must resolve. Use `implement_fixes`, `integrate_candidate` and
`verify_candidate` as their evidence is registered. If the canonical `HEAD`
has moved since candidate registration, `restore_candidate` gives the exact
published commit. Restore that commit or register a newly reviewed candidate
covering the same accepted deliveries.

## Diagnose the first failure

Retain `recording_id`, `session.attempt_id`, `session.report`,
`session.events`, and `next` from the run or status. A failed `run` with a
Replay result prints JSON before exiting unsuccessfully. For
`next.action: inspect_session_setup`,
inspect the returned setup error and report. `next.source_sequence` identifies
the failed Source read or preparation position when available. If the CLI fails
before printing a result, use its error to resolve recording, configuration, or
launch inputs.

For `next.action: analyze_session_failure`, start with `expected_sequence`
and the exact `next.event` query when supplied. Use `next.events` for the
surrounding timeline. Dispatch the read-only Issue Analyst with
the recording identity, expected sequence, Source and Target revisions and
locations, and any returned protected queries. Place the returned arguments
after `be-replay --target-root /absolute/target`:

- `events --seq SEQ` reads the exact Source event used by `next.event`.
  Repeat `--seq` to read multiple exact positions. An explicitly requested
  server push delivery appears even without `--with-push-event`.
- `events --from-seq SEQ --window-seconds 60` reads the Source window used
  by `next.events`. Continue with `--after-seq` set to `next_after_sequence`,
  keeping the start, window, and push visibility options. Default pages hide
  server push delivery events. Add `--with-push-event` to show them. Client
  requests such as `PUBLISH` and `SUBSCRIBE` are always visible. This display
  option leaves Replay verification unchanged. Use `--payload` only when
  protected primary HTTP payloads are necessary.
- `dependency SEQ` reads the protected semantic request and result
  for a dependency's **admission** sequence. An expected delivery event can
  name that sequence separately as `dependency_sequence`.
- `target --report /absolute/report.json OBSERVATION_ID` reads the
  authenticated Target observation when the attempt supplies one. Use the
  exact report, observation ID, and recording for the attempt.

Follow the earliest divergence to the relevant Source behavior and actual
Target call or response. Later Source events can support analysis of a shared
cause. They receive verification credit only after a fresh Replay reaches them.
Share sequence references and bounded facts, keeping protected contents private.
See [dependency diagnosis](api-implementer-dependency-diagnosis.md),
[runtime diagnosis](api-implementer-runtime-diagnosis.md), and
[rule diagnosis](api-implementer-rule-diagnosis.md) for protocol-specific decisions.

## Plan, implement, and verify

Collect reviewed findings from analysis and pass a JSON array to
`plan --findings /absolute/findings.json` for the failed attempt. The current
eligible failure is selected by default. Use `--attempt-id` to require its
exact identity. Use the returned `next.plan` template when available. Each
finding has these fields.

| Field | Contract |
| --- | --- |
| `root_cause`, `summary` | Nonempty shared cause identity and concise explanation |
| `kind` | `target`, `rule`, or `engine_gap` |
| `basis` | `reproduced`, `source_proven`, or `hypothesis` |
| `sequences` | Nonempty list of positive Source sequence numbers |
| `code_paths` | Optional list of Target-root-relative paths affected by the repair |
| `blocked_by` | Optional list of unresolved prerequisite findings |

The planner merges matching causes and rejects conflicting dispositions.
It prioritizes reproduced and Source-proven findings by sequence within each
basis. Results in `implementers` fit the `--max-implementers` limit of 1 to 16,
which defaults to 16, and have independent paths. `waiting` covers
prerequisites, path overlap, or capacity. Findings in `coordinator` need further
analysis, an engine change, or specific repair paths. The coordinator reviews
remaining work as its prerequisites resolve and owns dispatch and runtime
reconciliation.

Give each implementer its reviewed finding, sequence-based evidence, frozen
base, and absolute worktree. Require a Source citation, focused checks, the
exact committed fix, and any outstanding inputs in the handoff. Preserve
normal Target behavior and keep recording data, expected outputs, and Replay
internals out of product code. For a `rule` finding, use the
[Session rule contract](rule-policy.md) for time, id, and token changes.
For proven environment or mount requirements, use the
[startup input interface](coordinator-startup-inputs.md).

Keep findings and receipt files under the ignored Target runtime directory or
outside the Target checkout. Submit a ready integration batch with
`be-replay report --file /absolute/fixes.json`.
The report uses the failed attempt's UUID. For each fix, use the reviewed
`root_cause`, full commit SHA, and the checks from the delivery.

```json
{
  "kind": "fixes",
  "attempt_id": "11111111-1111-4111-8111-111111111111",
  "fixes": [
    {
      "root_cause": "route decoding loses a trailing slash",
      "commit": "1111111111111111111111111111111111111111",
      "checks": ["route decoding regression passed"]
    }
  ]
}
```

Register the fix batch while the canonical branch remains at the failed
revision. Use `integrate_candidate` to hand the batch to the integrator. After
validation, publish the exact candidate to the canonical work branch. Submit
it with `be-replay report --file /absolute/candidate.json`. `commit` must be the
canonical branch's current `HEAD`. `included_fixes` names the full SHAs from
the batch. Use the same failed attempt UUID.

```json
{
  "kind": "candidate",
  "attempt_id": "11111111-1111-4111-8111-111111111111",
  "commit": "2222222222222222222222222222222222222222",
  "included_fixes": ["1111111111111111111111111111111111111111"],
  "checks": ["repository validation passed"]
}
```

Follow `verify_candidate` to run the same complete recording against the
published candidate.
For coordinator-owned work with an empty `implementers` list, register the
candidate with `included_fixes: []` after reviewing any code or startup inputs.

Complete verification when `session.passed` is true. The engine requires the
complete event sequence and strict finalization. `apis` shows recorded and
verified primary exchanges. A response end or recorded cancellation completes
an exchange. Readiness probes contribute only to event verification. A passing
session with recorded API exchanges contributes once per sealed run ID to
`.traffic-e2e/progress.yaml`, preserving existing history. A repeat pass or
a session with no API traffic can have `progress_published: false`. Handle
any reported progress publication error from `run`.

[Engine session reference](../../../../../docs/session-regression.md)
