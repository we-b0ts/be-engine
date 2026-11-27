# Source Session Regression

The commands and receipts below apply to a managed round for a sealed
`traffic-e2e record` session. Read the [coordinator workflow](coordinator.md)
for role dispatch and handoffs.

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
selects the recording. Follow the returned `action`. For uncatalogued API
paths, the engine requests a delegated grouping and a commit of the resulting
catalog before dispatching implementers. Start Replay at `advance_required`.
On a named work branch, use
`be-replay switch-recording-id ID` to change the active recording in the
current checkout. Plain `status` and `run` use the active recording.
Switching back restores that recording's run key, attempts, and assignments.
Switching recordings clears delegated-role and implementer registrations.
Check the runtime before registering any previously launched agent again.
The catalog and API implementation backlog follow the branch across recordings.
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
when present to obtain supporting detail. `status --with-assignments` gives
the worktrees, worker states, window bounds, and ready fixes and rule plans
for integration. Each item gives a scope and sequence count. Use `sequences`
to read the full list when the handoff contains only the count.

| `action.kind` | Coordinator responsibility |
| --- | --- |
| `checkout_target_branch` | Check out a named branch. |
| `select_recording` | Select the exact sealed recording. |
| `confirm_regression` | Obtain caller approval and use the confirmed `run` command from the pull-request base. |
| `switch_recording` | Run `action.command` to select a different recording on the current branch. |
| `configuration_commit_required` | Review the paths in `action.details.files`, commit the intended configuration, and check `status` again. |
| `setup_required` | Resolve the setup error or route a confirmed engine issue to its owner. |
| `dispatch_task` | Launch the role named in `action.details.task` and register the returned runtime handle. |
| `await_delivery` | Follow the registered agent and submit its completed artifact or report its exit. |
| `dispatch_required` | Launch every assignment without an `agent_handle` in parallel and register the handles. |
| `worker_status_required` | Query the agent runtime for the registered handles and report their actual state. |
| `implementation_required` | Follow the registered implementers and submit sequence confirmations, fixes, and rule plans as they arrive. |
| `advance_required` | Start a full Replay with `action.command`. |
| `wait_required` | Follow the active Replay or outstanding assignments and refresh `status`. |
| `complete` | The candidate passed full Replay and required API work is complete. [Pre-final validation and Replay](coordinator.md#pre-final-validation-and-replay) |

The engine checks that `.traffic-e2e/project.yaml`, `.traffic-e2e/apis.yaml`,
and the effective policy are committed before `run`, `plan`, and candidate
publication. Paths in `action.details.files` are relative to the Target root.

An eligible committed engine revision can qualify for a retry on the same
Target code, including configuration-only commits. Follow the current
`status` action for API dispatch and window confirmation. When it returns
`advance_required` with `action.details.reason: engine_changed`, run the
fresh attempt. The retry identity follows the committed engine revision.

## Dispatch and monitor delegated tasks

`dispatch_task` and `await_delivery` use `action.details.task` for the
`task_id`, `role`, `requirement`, and task-specific context. The requirement
is `api_grouping_required` for new API groupings, `ownership_required` for
an unowned failed sequence, `lookahead_ownership_required` for outstanding
window ownership, or `integration_required` for a candidate.

At `dispatch_task`, launch the named role through the agent runtime and pass
its task context. Ask the agent to load `be-replay` for its assigned role.
When the runtime returns the handle, register it with
`be-replay report --file FILE`.

```json
{
  "kind": "task_dispatch",
  "task_id": "task-id-from-status",
  "agent_handle": "agent-a1b2c3",
  "state": "started"
}
```

The engine then returns `await_delivery` with the registered `agent_handle`.
Follow that handle through the runtime. Submit the agent's returned artifact
with the current task and handle. Grouping and ownership use
`be-replay plan --findings FILE`. Candidates use `be-replay report --file FILE`.
When the runtime confirms an agent exited without delivering, submit
the same `task_dispatch` receipt with `state: exited` to make dispatch
available again.
[Delivery formats](#plan-implement-and-verify)

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

On a mismatch, the engine opens a fixed 60-second window of Source time
starting at the failed sequence. Every non-push sequence in the window with
a matching Source exchange requires confirmation. Recorded request links and
lifecycle events establish ownership where available. A dependency can refer
to an earlier request outside the window. The actual failed event always
receives a diagnosis. The engine considers overlapping sequences on subsequent
failed attempts. Unresolved ownership and open engine gaps keep the window
open until resolved.

The analyst and implementers run evidence queries from the canonical Target
or provide `--target-root /absolute/target`.

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
- `apis --case-pattern '/reports/*' --from-seq FROM --through-seq THROUGH`
  locates the first primary request for that catalog pattern across methods.
  The bounds include both endpoints. The `request` gives `request_seq`, actual
  `method`, `path`, `offset_micros`, and `exchange` for related Source events.
  Repeat with `--after-seq` set to `next_after_sequence`, keeping the original
  bounds, until `request` is `null`.
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

For the `api_grouping_required` task, the Issue Analyst supplies a complete
list of groupings for the recorded uncatalogued APIs. The coordinator submits
those rows with `be-replay plan --findings FILE` and the registered task and
agent identities.
The proposed pattern must match the recorded path. Static routes use literal
paths. Several literal paths for a dynamic route can share a pattern and
group.

```json
{
  "task_id": "grouping-task-id-from-status",
  "agent_handle": "agent-a1b2c3",
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

For the `ownership_required` task, submit the analyst's ownership for the
failed sequence, together with that task and its registered handle.

```json
{
  "task_id": "ownership-task-id-from-status",
  "agent_handle": "agent-d4e5f6",
  "ownership": {
    "seq": 42,
    "scope": "job:cache-refresh",
    "group": "cache-refresh"
  }
}
```

Use `api:/case/pattern` with the catalog group, `job:NAME` with its
implementation group, or `startup` or `shutdown` with the corresponding
group. Group names use 1–128 ASCII letters, digits, periods, underscores,
or hyphens.

### Lookahead ownership

The Issue Analyst reads one representative sequence per outstanding exchange
and delivers evidence-backed findings with `be-replay plan --findings FILE`.
Sequences that share an owner can be batched in one file. Omit both `scope`
and `group` and give an unresolved reason when the evidence is insufficient.
Accepting ownership assigns the linked sequences for implementer confirmation.

```sh
be-replay sequences --task-id TASK --limit 100
be-replay sequences --task-id TASK --after-seq LAST_SEQ --limit 100
```

```json
{
  "task_id": "lookahead-task-id-from-status",
  "agent_handle": "agent-a1b2c3",
  "lookahead": [
    {
      "sequences_file": "report-dependencies.txt",
      "scope": "api:/reports/*",
      "group": "reports",
      "evidence": "The recorded request and Source handler call path identify the report store reads."
    },
    {
      "sequences_file": "unresolved.txt",
      "evidence": "The dependency has no recorded owner and the Source has two possible callers."
    }
  ]
}
```

### Implementer handoffs

Each active group gets one reservation. Different jobs and APIs can share a
group. When the runtime has fewer than 16 implementer slots, add
`--max-implementers N` to the plan submission for the slots it can run.
The flag accepts 1 to 16 and defaults to 16. Use
`status --with-assignments` for each group's `assignment_id`, `base_commit`,
and items, including their scopes, sequence counts, and applicable API work.
Resolve the reserved `worktree` against the canonical Target root. It uses
`.traffic-e2e/local/rewrite-worktrees/api-implementer-<n>`. Reuse the worker
and worktree when the engine adds items to the same group. Different recordings
can use the same slot. A recording switch restores that recording's own
assignment IDs and paths.

`sequences --assignment-id UUID` prints assigned sequences in increasing order,
one per line. Add `--scope 'api:/reports/*'` for just that scope. Assignment
and task queries both support an exclusive `--after-seq` and optional `--limit`.
Redirect output to a file when handling a large assignment. Lookahead uses
one `api:/case/pattern` scope across methods. First-run `apis` work retains
its actual method and pattern.

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

### Claim window dependencies

Register a `kind: claim` receipt with `be-replay report --file FILE` when an
active API implementer can use Source evidence to connect unassigned window
dependencies to an assigned API. Use an in-window primary request as the
anchor and provide the subsequent dependency admission sequences in the file.
Accepted claims assign those sequences to the implementer. Submit the
confirmation, repair, or rule plan for those sequences in the same assignment.

```json
{
  "kind": "claim",
  "group": "reports",
  "assignment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "scope": "api:/reports/*",
  "request_seq": 88,
  "sequences_file": "claimed-dependencies.txt",
  "evidence": "Source report handler at src/reports/handler.rs calls the store query recorded at these admissions."
}
```

### Confirm window sequences

The implementer checks each assigned sequence's linked Source input and output
against its Target implementation and branch. Submit every outcome with
`be-replay report --file FILE` or `be-replay rule plan --file FILE`. Copy the
`group` and `assignment_id` from the handoff, for APIs and jobs alike.
Submit with the original recording selected and its worker handle registered.
A `sequences_file` contains positive Source sequences separated by commas or
newlines. Paths are absolute or relative to the containing JSON. Keep
plan and receipt files in the ignored Target runtime directory or outside the
checkout. [Implementer diagnosis](api-implementer-diagnosis.md#confirm-assigned-events)

When the format matches and the branch is implemented, submit this receipt.
Use `rule: covered` for a rule already in effect and `rule: not_needed` when
the event needs no rule. Each file can cover multiple sequences with the same
result. The fields shown are sufficient for unchanged window sequences.

```json
{
  "kind": "confirmed",
  "group": "reports",
  "assignment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "sequences_file": "reports-confirmed.txt",
  "format": "matches",
  "rule": "not_needed"
}
```

### Submit implementation outcomes

Implement the required changes and submit the commits and exact sequences
using `be-replay report --file /absolute/fixes.json`. Run focused tests for
the changes and include their results in `checks`. Review checks, standalone
builds, and Clippy are prohibited for implementers. Fixes, reviews, and engine
gaps also accept the inline `sequences` array.
[Rule contract](rule-policy.md) · [Startup inputs](coordinator-startup-inputs.md)

```json
{
  "kind": "fixes",
  "fixes": [
    {
      "group": "cache-refresh",
      "assignment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "commit": "1111111111111111111111111111111111111111",
      "sequences_file": "cache-refresh-fix.txt",
      "checks": ["cache refresh regression passed"]
    }
  ]
}
```

For first-run API work, use `kind: review` with `"confirms_apis": true` when
focused tests verify the existing route and handler. Use the exact assigned
API sequences. The catalog must already be committed for that API.

```json
{
  "kind": "review",
  "group": "reports",
  "assignment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "sequences_file": "reports-reviewed.txt",
  "checks": ["assigned report route regression passed"],
  "confirms_apis": true
}
```

For an engine gap, include the evidence and required engine behavior and
route it to the engine owner. The affected window sequence stays open.

```json
{
  "kind": "engine_gap",
  "group": "cache-refresh",
  "assignment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "sequences_file": "cache-refresh-engine-gap.txt",
  "evidence": "Source seq 42 and the Target observation establish that an unsupported engine operation rejected the request before comparison."
}
```

Register Source-proven policy changes with `be-replay rule plan --file FILE`
as part of the same assignment. If a sequence needs both a rule and a code
fix, register the plan before submitting the fix receipt.
[Rule plan format](api-implementer-rule-diagnosis.md#submit-a-rule-plan)

### Integrate the candidate

When every required sequence in the window has a confirmation or accepted
repair and the window has ready changes, the engine requests
`integration_required`. Use
`status --with-assignments` for the ready fixes and rule plans. The code
integrator merges all required window fixes onto the canonical base and
applies all required window rule plans in the integration worktree. Deliver
a clean integration immediately. If the merge conflicts, resolve the
conflicts and run only tests directly related to the resolution. Review
checks, standalone builds, and Clippy are prohibited for integrators. Independent groups can
continue working. On delivery, publish the exact candidate to the canonical
branch and submit it with
`be-replay report --file /absolute/candidate.json` for the registered task,
agent handle, and current finished attempt. The candidate's `commit` is
the canonical branch's current `HEAD`, and `included_fixes` contains the
delivered commit SHAs. `included_rule_plans` contains the applied plan IDs.
Omit `checks` after a clean merge. Include related test results in `checks`
when resolving conflicts. [Rule application](code-integrator.md#apply-selected-rule-plans)

```json
{
  "kind": "candidate",
  "task_id": "integration-task-id-from-status",
  "agent_handle": "agent-g7h8i9",
  "attempt_id": "11111111-1111-4111-8111-111111111111",
  "commit": "2222222222222222222222222222222222222222",
  "included_fixes": ["1111111111111111111111111111111111111111"],
  "included_rule_plans": ["sha256:3333333333333333333333333333333333333333333333333333333333333333"]
}
```

The candidate must include all required window fixes and applied plans.
Follow `advance_required` to run the same complete recording against the
published candidate. For `setup_required`, resolve the execution error or
engine gap and refresh `status`.

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
