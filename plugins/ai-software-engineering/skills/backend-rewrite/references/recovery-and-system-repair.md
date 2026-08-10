# Recovery And System Repair

Read this guide only for `recovery_required`, `system_repair_required`, or a
coordinator-issued repair verification action. The coordinator owns every
state-mutating command in this guide.

## System Repair

`system_repair_required` exists only after `backend-rewrite route` accepts
current evidence, a source reference, and the required system change. The route
captures a coordinator-defined system/source revision and returns an opaque
repair ID; never supply an invented acceptance command.

Apply the required repair and execute the exact
`action.commands.acceptance`. New repairs use
`repair verify <repair-id>`. A legacy Response `external_data_blocker` now
expressible by bootstrap Replay planning instead receives
`repair resume-replay-planning <repair-id>`; that migration does not require a
runtime-input revision change. Neither `next` nor `recording request` may
bypass the returned command.

Successful verification chooses the next transition. Replay and external-input
repairs reuse the same cases; Recorder or source-baseline repairs allocate
fresh standard traffic. The AI never chooses between those transitions.

Use `recorder_capability_gap` only when the recorder lacks a required mechanism
and the supported recorder-capture planner cannot express it. A configured
Breeze resource bypassed during recording is an API-scoped recorder-capture
refresh, not system repair. Follow
[coordinator-evidence-actions.md](coordinator-evidence-actions.md) when that
planner is available.

## Status And Recovery

Use `backend-rewrite status [--api '<METHOD pattern>']` to reconstruct a lost or
resumed action without advancing state. Depending on current state it returns:

- the original `action.commands.execute` before recording execution;
- exact `action.commands.apply` for a pending plan;
- `action.commands.status` while a detached recording executor is live;
- `action.commands.advance` after a finalized manifest or target change is
  ready; or
- the coordinator-issued system-repair acceptance.

A running manifest whose owner exited returns `recovery_required`. Execute only
its exact `action.commands.recover`. Recovery rejects a live coordinator,
removes the matching stale lock, stops only the orphaned focused target/Replay
attempt or managed recording, publishes interrupted state, and returns the next
coordinator command. It may allocate a replacement recording run; never rebuild
the prior argv or start a second executor manually.

`wait_required` is not recovery. It proves that a live or non-preemptible owner
blocks the requested transition and supplies the status command to poll. Only
`recovery_required` authorizes `recover`.

Internal runner paths are not stable rewrite-interface contracts. Use public
status/actions and immutable artifact paths exposed by the coordinator as the
primary interface. Read-only inspection of `.traffic-e2e/local/runtime/**` is
allowed for diagnosis, but never edit it or reconstruct recovery actions from
its layout.
