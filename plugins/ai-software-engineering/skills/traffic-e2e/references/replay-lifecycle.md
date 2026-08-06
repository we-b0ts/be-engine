# Traffic E2E Managed Replay Lifecycle

Read this reference for every replay execution.

## Contents

- Target isolation
- Recorder commands
- Fixed-user interception
- Required sequence
- Aggregate
- Iteration

## Target Isolation

Inspect the target E2E entrypoint, startup, config, and dependency endpoints.
Reuse its existing framework and add only the smallest missing recorded-E2E
orchestration.

When the target uses the standard managed workflow, invoke recorded E2E through
`traffic-e2e run-api` or `traffic-e2e run`. The runner calls the target's
standard version-two
`scripts/<project>-cli e2e --case-dir <path> --actual-response <path>` once per
active case. That facade executes the request and writes the actual response;
it does not read the expected response or own replay startup, begin/end,
response comparison, aggregate, or progress operations.

Clear inherited HTTP proxy variables only inside the recorded-E2E invocation so
dependency traffic can reach DNS and fake-IP interception. Do not change the
agent's global proxy settings or normal product configuration.

Require the case source through `--case-dir` or an equivalent explicit input.
Never hardcode or silently default to a developer-machine recording path or an
older batch.

## Recorder Commands

The normal AI-facing command is `traffic-e2e`. It orchestrates these recorder
surfaces:

- `traffic-e2e replay` for the replay session;
- `traffic-e2e target exec` for a prebuilt in-process target command;
- `traffic-e2e config replay plan|apply response-rule` for evidence-driven
  replay response-rule maintenance;
- `traffic-e2e config comparison plan|apply response-rule` for
  comparison-only response-rule maintenance;
- `traffic-e2e diagnose replay-control` for readiness, case lifecycle,
  finalization, and cleanup;
- `traffic-e2e diagnose replay-aggregate` for final multi-case or multi-session
  coverage.

Do not call the low-level commands to assemble a parallel lifecycle during the
standard workflow. They remain available for human diagnostics and recorder
development. Do not generate replacements inside the target project or
hardcode the recorder repository or skill path.

If the installed recorder or replay tools are incompatible with the published
cases or required replay configuration, stop and report the exact
incompatibility. Do not rebuild or replace those tools while verifying the
target.

## Fixed-User Interception

Resolve the interception identity with
`traffic-e2e diagnose interception identity` and require it to exist. Build
and orchestration may run as the developer, but the process emitting
dependency traffic MUST run as that recorder-owned fixed user.
Recorder and Replay themselves MUST NOT run as the fixed user; interception
startup rejects that identity so their control traffic cannot enter the target
owner scope.

For a prebuilt in-process E2E, use `traffic-e2e target exec`; do not run the
build tool as the fixed user or widen workspace, build cache, control socket,
report, session, or private CA-key permissions. Keep replay lifecycle control
under the developer account and stage only the required executable, readable
inputs, and target-owned output directories.

Target tests, facades, docs, and state MUST NOT pass or emulate `--owner-uid`,
`--user`, `--all-users`, `OWNER_UID`, or another owner-selection mechanism. If
the fixed identity or target process identity cannot be verified, stop with the
internal diagnostic `blocked_replay_isolation`. Return
`target_environment/action_required` or `replay_capability_gap/action_required`
for the operation; this diagnostic does not satisfy the main skill's
recording-data proof for a `blocked` handoff.

Use `--no-intercept` only when every dependency is explicitly routed to replay
listeners; it is not an isolation bypass.

## Required Sequence

For each focused API attempt or full round, the runner performs:

1. validate canonical grouping and the explicit source-controlled replay policy;
2. start `traffic-e2e replay` with the policy and exact case selection;
3. call `traffic-e2e diagnose replay-control wait-ready` and stop on any
   readiness failure;
4. start the normal target once and confirm its status;
5. call `traffic-e2e diagnose replay-control begin <case-id>`;
6. call the target facade for that exact case, exercising genuine dependencies
   and capturing the actual response;
7. compare the actual response with the assertion-only expected response under
   the validated replay policy;
8. call `traffic-e2e diagnose replay-control end <case-id> --fail-on-dirty`;
9. repeat begin through end for every exact selected case;
10. stop the target once and call
    `traffic-e2e diagnose replay-control finalize --fail-on-dirty --fail-on-incomplete`.

Require the final version-six report to contain the exact selected case ids,
session id, `finalized: true`, and `finalized_at`. Successful finalization
atomically publishes the report and stops replay. A validation or report-write
failure leaves the session incomplete; retain diagnostics and use the canonical
stop command only for cleanup.

One target-facade invocation handles one active case. The target MUST NOT own
the control socket or call lifecycle commands.

## Aggregate

After the selected session finalizes, the full runner applies the aggregate
contract loaded from the main skill and runs `traffic-e2e diagnose
replay-aggregate` for every collection or run source, multi-case selection, or
source replayed through multiple reports or sessions. Pass the exact repeated
case and session ids and both fail-on-incomplete and fail-on-dirty gates.

Focused attempts retain their own aggregate for diagnosis and use it to replace
the selected API's contribution to the current logical run and update any
current E2E pass progress. Every distinct finalized attempt contributes once;
processing an already counted runner-owned identity and evidence does not add
counts, even after newer attempts. Focused attempts never replace the global
full-round `latest`. Only one published case replayed in exactly one finalized
session may record
`not_applicable_single_case_single_session`. Never enumerate report paths,
manually total counters, merge overlapping attempts without exact session
selection, or substitute target test output for recorder evidence.

## Iteration

After an engine failure, isolate lifecycle, interception, publication, or
protocol ownership from bounded output before reading a low-level artifact.
Return the exact engine defect or missing capability and its acceptance
command. Do not infer target business causality, blocker status, or migration
completion from repeated attempts.
