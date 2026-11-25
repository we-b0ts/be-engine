# Source Session Regression

Use this workflow for the sealed event recording produced by `traffic-e2e
record`. The coordinator owns Replay, evidence routing, and publication of
integrated code. The repository analyst traces Source behavior read-only.
Implementers repair reviewed findings in assigned worktrees. The integrator
combines their committed changes for the next full Replay.

## Run the selected recording

The external recording owner stops the recorder normally, letting it stop
Source and seal the run, then hands over the full recording directory.
Preserve the manifest, `events.tsv`, dependency data, and payload segments
together. Follow the
[recording handoff](coordinator-recording.md) for missing or incomplete evidence.

Set `recording_run_id` and optionally `max_implementers` in the canonical
Target's local `.traffic-e2e/regression.yaml`. The run ID is the existing
14-digit directory name under `.traffic-e2e/local/artifacts/recordings/`.
The implementer limit is 1 to 16 and defaults to 16. These are the two
accepted Session settings. The command-line `--recording-run-id` can select
the recording explicitly.

```sh
backend-rewrite --target-root /absolute/target session run
```

Every attempt launches an isolated Target and exercises the entire recording.
One Source timeline interleaves startup, readiness, concurrent ingress,
dependency admissions and deliveries, notifications, and shutdown. Replay
advances by sequence when the matching Target request, delivery receipt, or
timer gate is ready. Sequence numbers can have gaps. Use the primary request's
`exchange` reference to join its response events. Source offsets measure
recorded time for investigation. Replay adds zero delay for those intervals.
Real application waits and I/O still take time.

HTTP gateway rules select ingress at capture time. The API catalog in
`.traffic-e2e/apis.yaml` labels counts by method and route, using the literal
path for requests without a catalog match. Case selection settings such as
`only` and `skip` are rejected by Session configuration. Startup and background
traffic are verified on the session timeline.

## Diagnose the first failure

Retain `recording_id`, `session.attempt_id`, `session.report`,
`session.events`, and `next` from the run. A reported failed Replay prints its
JSON before exiting unsuccessfully. For `next.action: inspect_session_setup`
inspect the returned setup error and report. If the CLI fails before printing
a result, use its error to resolve recording, configuration, or launch inputs.

For `next.action: analyze_session_failure`, start with `expected_sequence`
and the returned `events` query. Dispatch a read-only analysis with the
recording identity, expected sequence, Source and Target revisions and
locations, and any returned protected queries. Place the returned arguments
after `backend-rewrite --target-root /absolute/target`:

- `session events --from-seq SEQ --window-seconds 60` reads the Source
  timeline from that position. Continue with `--after-seq` set to
  `next_after_sequence`, keeping the original start and window. Read earlier
  events when needed to trace the cause. Repeat `--seq` for exact positions.
  Use `--payload` only when primary HTTP payloads are necessary.
- `session dependency SEQ` reads the protected semantic request and result
  for a dependency's **admission** sequence. An expected delivery event can
  name that sequence separately as `dependency_sequence`.
- `session target --report /absolute/report.json OBSERVATION_ID` reads the
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
`session plan --findings /absolute/findings.json` for the same recording.
Use the returned `next.plan` argument template when available. Each finding
contains:

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
basis. Results in `implementers` fit the configured cap and have independent
paths. `waiting` covers prerequisites, path overlap, or capacity. Findings in
`coordinator` need further analysis, an engine change, or specific repair
paths. The coordinator reviews and redispatches remaining work as its
prerequisites resolve. `session plan` emits a work plan. Actual dispatch,
runtime reconciliation, and integration remain coordinator responsibilities.

Give each implementer its reviewed finding, sequence-based evidence, frozen
base, and absolute worktree. Require a Source citation, focused checks, the
exact committed fix, and any outstanding inputs in the handoff. Preserve
normal Target behavior and keep recording data, expected outputs, and Replay
internals out of product code. Integrate the exact commits into one canonical
candidate, then rerun the same full session. For a `rule` finding, use the
[Session rule contract](rule-policy.md) for time, id, and token changes.
For proven environment or mount requirements, use the
[startup input interface](coordinator-startup-inputs.md).
Case worker bindings, per-API acceptance, and final Case review receipts
belong to the separate Case coordinator.

Complete verification when `session.passed` is true. The engine requires the
complete event sequence and strict finalization. `apis` shows recorded and
verified primary exchanges. A response end or recorded cancellation completes
an exchange. Readiness probes contribute only to event verification. A passing
session with API cases contributes once per sealed run ID to
`.traffic-e2e/progress.yaml`, preserving existing history. A repeat pass or
a session with no API cases can have `progress_published: false`.

[Engine session reference](../../../../../docs/session-regression.md)
