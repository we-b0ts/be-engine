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

Inspect `.traffic-e2e/Dockerfile.target`, the OCI entrypoint, startup
configuration, and dependency endpoints. Reuse the target's existing framework
and add only the smallest missing runtime integration.

Invoke recorded E2E through `traffic-e2e run-api` or `traffic-e2e run`. The
runner builds the target image, starts its entrypoint once, drives every case
over HTTP, and writes the actual-response evidence itself. The target never
receives case directories, expected responses, Replay controls, or report
paths.

## Recorder Commands

The normal AI-facing command is `traffic-e2e`. It orchestrates these recorder
surfaces:

- `traffic-e2e replay` for the replay session;
- `traffic-e2e target exec` for legacy low-level diagnosis of a prebuilt
  in-process target command;
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

Confirm the fixed numeric interception identity with
`traffic-e2e diagnose interception identity`. It is UID/GID `998:998` and does
not depend on a same-named account or its numeric identity on the host. Build
and orchestration may run as the developer, but every containerized process
emitting dependency traffic MUST run as `998:998`. Recorder and Replay
themselves MUST NOT run as UID `998`; interception startup rejects that identity
so their control traffic cannot enter the target owner scope.

The standard managed target image runs as `998:998` in a system-owned network
namespace. Replay keeps interception control under the developer account,
allows intercepted/local traffic, and rejects uncontrolled external egress.
Do not widen workspace, build cache, control socket, report, session, or
private CA-key permissions.

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
4. build the target image, start its OCI entrypoint once in the Replay
   namespace, mount the public Replay CA, and confirm HTTP readiness;
5. call `traffic-e2e diagnose replay-control begin <case-id>`;
6. send the exact recorded request to the target HTTP endpoint, exercising
   genuine dependencies and capturing the actual response;
7. compare the actual response with the assertion-only expected response under
   the validated replay policy;
8. call `traffic-e2e diagnose replay-control end <case-id> --fail-on-dirty`;
   Replay keeps that case active for the configured dependency post-response
   window before closing it (10 ms by default), so dependencies started just
   after the primary response retain the case ownership observed at request
   admission;
9. repeat begin through end for every exact selected case;
10. send `SIGTERM`, require a clean target exit, remove its namespace, and call
    `traffic-e2e diagnose replay-control finalize --fail-on-dirty --fail-on-incomplete`.

Require the final version-six report to contain the exact selected case ids,
session id, `finalized: true`, and `finalized_at`. Successful finalization
atomically publishes the report and stops replay. A validation or report-write
failure leaves the session incomplete; retain diagnostics and use the canonical
stop command only for cleanup.

One system HTTP-driver invocation handles one active case. The target MUST NOT
own the control socket or call lifecycle commands.

## Aggregate

After the selected session finalizes, the full runner applies the aggregate
contract loaded from the main skill and runs `traffic-e2e diagnose
replay-aggregate` for every collection or run source, multi-case selection, or
source replayed through multiple reports or sessions. Pass the exact repeated
case and session ids and both fail-on-incomplete and fail-on-dirty gates.

Focused attempts retain their own aggregate for diagnosis and use it to replace
the selected API's contribution to the current logical run and update any
current E2E pass progress. Public Replay progress counts recording coverage,
not attempt history: one `recording_run_id` contributes at most one run and one
current contribution per selected case. Retries revise that contribution and
cannot increase executed totals or success streaks; only a new recording batch
can do so. Attempt sequence and diagnostic evidence remain runner-owned local
state. Focused attempts never replace the global full-round `latest`. Only one
published case replayed in exactly one finalized session may record
`not_applicable_single_case_single_session`. Never enumerate report paths,
manually total counters, merge overlapping attempts without exact session
selection, or substitute target test output for recorder evidence.

## Auxiliary Rejection Counts

Intercepted Replay reads existing REJECT packet counters at case begin/end.
Response or dependency failures may include `egress_rejections` with the delta
and sampled time window. Counts do not change verification gates and do not
identify IPs, origins, individual calls, or exact event times. Failed reads or
rule replacement are unavailable evidence, never zero. `--no-intercept` omits
this observation. Follow returned rule hints only after tracing the source
call; JSON response URL acquisition can use recorder rule plan/apply followed
by a consolidated fresh recording.

## Iteration

After an engine failure, isolate lifecycle, interception, publication, or
protocol ownership from bounded output before reading a low-level artifact.
Return the exact engine defect or missing capability and its acceptance
command. Do not infer target business causality, blocker status, or migration
completion from repeated attempts.
