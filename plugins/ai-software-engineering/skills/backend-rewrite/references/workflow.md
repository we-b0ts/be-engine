# Rewrite Coordinator Workflow

The coordinator owns the executable phase order:

```text
select API -> standard recording -> prepare -> focused E2E
           -> one active issue -> focused E2E
           -> comparison recording -> compare -> slice complete

explicit new traffic / changed recording contract / changed source baseline
           -> fresh standard recording -> prepare -> focused E2E
```

The target AI repeatedly runs `traffic-e2e rewrite next`. It pauses only for:

- the exact standard or comparison recording command returned by the action;
- one source/target investigation and implementation issue;
- one evidence-backed rule decision;
- one controlled non-target-code route;
- one explicit fresh-standard-recording request when its preconditions hold;
- completion.

## Action Handling

### `recording_required`

Execute the exact argv with the named environment variables, then run `next`.
The coordinator preallocates the run ID and validates that exact finalized
manifest. Never discover a run by recency. Recording duration and case limit
are explicit in the argv; do not adjust them there.

### Fresh standard recording

The ordinary repair loop keeps the finalized standard cases immutable. When a
focused E2E attempt fails, change the target for one proven cause and run
`next`; the coordinator reruns those same cases. After focused E2E passes, the
coordinator allocates fresh comparison evidence without replacing the standard
cases.

Use `rewrite recording request --kind standard` only for an explicit caller
request, a changed Recorder contract, or a changed source baseline. Supply the
corresponding reason plus positive `--duration-seconds` and `--case-limit`
values. The coordinator preserves the prior artifacts, clears state derived
from that baseline, allocates a new run, and returns the exact
`recording_required` action. Execute that action and resume with `next`.

This public transition is also the legal continuation after a system repair
when fresh traffic is required. The AI selects the transition from coordinator
and source-code evidence. Artifact inspection may inform diagnosis, but only the
coordinator identifies the active baseline and authorizes a fresh recording.

### `implementation_required`

The action contains one bounded issue, one representative when available,
possible causes, evidence query IDs, and the acceptance command. Traffic facts
come from those queries and immutable artifacts. `representatives` returns the
exact standard or comparison case directory and structured response difference;
inspect that case first and other artifact cases as needed. Source inspection
supplies the final business attribution. Apply
[problem-diagnosis.md](problem-diagnosis.md), repair one proven cause, run local
target tests, then execute the acceptance command.

The coordinator always evaluates gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Dirty dependencies cannot preempt a response mismatch. A repository change
after a comparison mismatch returns through focused E2E before another fresh
comparison recording.

Dependency cleanliness is evaluated per active case. The coordinator clusters
case-scoped unmatched, unsupported, unsafe, and unused-case events by protocol
and endpoint. It may return source pre-readiness traffic for the same endpoint
as reference context, but startup context, `unused_global`, and target activity
outside a case do not fail the case gate.

### `system_repair_required`

This action exists only after `rewrite route` accepts current evidence and a
source reference, required system change, and acceptance command. It never
turns a traffic limitation into a target workaround and never permits the
target AI to stop silently. After the accepted repair, request a fresh standard
recording when the repaired Recorder contract or source baseline requires new
traffic; do not stop because the prior action had no recording argv.

### `complete`

The active API has current passing focused E2E and comparison evidence.
`terminal_allowed` is true only here. Repository-wide regression, delivery,
and additional API inventory remain under the caller's rewrite objective.

## State And Recovery

Coordinator state is one atomically replaced file under the ignored local
root. Prefer `rewrite status` to reading this noisy internal representation and
never edit it. When an action reports `recovery_required`, execute its exact
`rewrite recover` argv. Recovery rejects a live coordinator, removes a stale
lock, stops an orphaned focused target/Replay attempt, and publishes that
attempt as interrupted before returning the next coordinator command.

Traffic-e2e's internal runner publication may retain its own implementation
layout. Those local paths are not a stable rewrite-interface contract. The
interface may expose immutable artifact paths such as a representative
`case_dir` when direct inspection is useful.

The target repository's `replay-progress.yaml` and
`comparison-progress.yaml` are a separate, versioned coordinator output. Do
not edit or roll them back manually. Preserve coordinator-generated changes,
including consecutive-success evidence, and commit them with the target change
they verify. Continue excluding ignored local runtime state and traffic
artifacts from delivery.
