# Rewrite Coordinator Workflow

The coordinator owns the executable phase order:

```text
select API -> standard recording -> prepare -> focused E2E
           -> one active issue -> focused E2E
           -> comparison recording -> compare -> slice complete
```

The target AI repeatedly runs `traffic-e2e rewrite next`. It pauses only for:

- the exact standard or comparison recording command returned by the action;
- one source/target investigation and implementation issue;
- one evidence-backed rule decision;
- one controlled non-target-code route;
- completion.

## Action Handling

### `recording_required`

Execute the exact argv with the named environment variables, then run `next`.
The coordinator preallocates the run ID and validates that exact finalized
manifest. Never discover a run by recency.

### `implementation_required`

The action contains one bounded issue, one representative when available,
possible causes, evidence query IDs, and the acceptance command. Traffic facts
come only from those queries. Source inspection supplies the final business
attribution. Apply [problem-diagnosis.md](problem-diagnosis.md), repair one
proven cause, run local target tests, then execute the acceptance command.

The coordinator always evaluates gates in this order:

```text
responses -> replay completeness -> dependency cleanliness
```

Dirty dependencies cannot preempt a response mismatch. A repository change
after a comparison mismatch returns through focused E2E before another fresh
comparison recording.

### `system_repair_required`

This action exists only after `rewrite route` accepts current evidence and a
source reference, required system change, and acceptance command. It never
turns a traffic limitation into a target workaround and never permits the
target AI to stop silently.

### `complete`

The active API has current passing focused E2E and comparison evidence.
`terminal_allowed` is true only here. Repository-wide regression, delivery,
and additional API inventory remain under the caller's rewrite objective.

## State And Recovery

Coordinator state is one atomically replaced file under the ignored local
root. The AI never reads or edits it. `rewrite status` returns its bounded
projection. When an action reports `recovery_required`, execute its exact
`rewrite recover` argv. Recovery rejects a live coordinator, removes a stale
lock, stops an orphaned focused target/Replay attempt, and publishes that
attempt as interrupted before returning the next coordinator command.

Traffic-e2e's internal runner publication may retain its own implementation
layout, but no `.active`, `latest`, report path, or raw artifact crosses the
rewrite interface.
