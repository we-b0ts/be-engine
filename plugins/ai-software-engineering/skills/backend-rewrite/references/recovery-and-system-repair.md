# Recovery And System Repair

Read this guide only for `recovery_required`, `system_repair_required`, or a
coordinator-issued repair verification action. The coordinator owns every
state-mutating command in this guide.

## System Repair

`system_repair_required` exists only after `backend-rewrite route` accepts a
cause that requires a system/source change, together with current evidence, a
source reference, and the required change. The route captures a
coordinator-defined system/source revision and returns an opaque repair ID;
never supply an invented acceptance command. `missing-recorded-resource` is a
validated route cause but resolves to a recorder-capture plan and never enters
this phase.

Apply the required repair and execute the exact
`action.commands.acceptance`. New repairs use
`repair verify <repair-id>`. A legacy Response `external_data_blocker` now
expressible by bootstrap Replay planning instead receives
`repair resume-replay-planning <repair-id>`; that migration does not require a
runtime-input revision change. Neither `next` nor `recording request` may
bypass the returned command.

System-repair actions retain the route and acceptance command as scheduling
information. Fetch the issue diagnostics through their single
`action.commands.evidence` entrypoint when needed; status does not embed them.

Successful verification chooses the next transition. Replay and external-input
repairs reuse the same cases; Recorder or source-baseline repairs allocate
fresh standard traffic. The AI never chooses between those transitions.

For an accepted `source_change` caused by an upgraded source image, an
administrator replaces the source baseline without rerunning initialization:

```bash
backend-rewrite-admin --target-root <target> source upgrade \
  --source-pod <ready-pod> --namespace <namespace> \
  [--pod-container <regular-container>] \
  [--kubeconfig /path/to/kubeconfig] [--context <context>] \
  --confirm-replace
```

The command captures the new image and Kubernetes runtime inputs and
recaptures the existing startup declaration as one rollback-safe operation. It
does not change tracked project configuration, target code, or `target.env`.
After it succeeds, execute the exact coordinator-issued `repair verify
<repair-id>` acceptance command; do not substitute initialization preflight or
a manually constructed recording. If only runtime inputs changed while the
image stayed the same, the upgrade does not satisfy `source_change` acceptance;
use the coordinator's runtime-input repair (`external_data_blocker`) and its
issued verification command.

If an administrator confirms that a `source_change`,
`recorder_capability_gap`, or `replay_capability_gap` route was accepted by
mistake and the issue is target-owned, use `backend-rewrite-admin repair
cancel` with the exact repair ID, a bounded reason, and
`--confirm-misroute`. The command clears only the current accepted route,
restores `target_code` ownership, and returns the coordinator-owned advance
command. Execute that returned command once. It does not apply to
`external_data_blocker`, delete evidence, or bypass ordinary AI workflow
transitions.

Before reporting an IP capture defect, use `route --cause unrecorded-ip` and
follow its source investigation or recorder rule plan/apply instructions. A
supported JSON response URL rewrite is an acquisition rule; complete its fresh
recording verification before escalating a remaining engine defect. Rejection
counts alone establish neither IP origin nor a missing capture mechanism.

Use `recorder-capability-gap` only when the recorder lacks a required mechanism.
A comparison issue owned by `traffic_e2e_system` uses
`replay-capability-gap`: response decoding, semantic assertion, and comparison
verification are part of the same traffic-e2e verification revision. Do not
route an ordinary complete comparison difference this way.
A configured Breeze resource bypassed during recording is reported as
`missing-recorded-resource` and becomes an API-scoped recorder-capture refresh,
not system repair. Follow
[coordinator-evidence-actions.md](coordinator-evidence-actions.md) after source
inspection proves the explicit route inputs.

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

If an administrator confirms that `traffic-e2e run-api` was mistakenly run
outside an active rewrite workflow, use `backend-rewrite-admin repair
retry-replay` with the exact failed coordinator attempt, newer passing
out-of-band attempt, API, reason, and confirmation flag. The command accepts
only unchanged target content and matching case source/inventory, discards the
external result as workflow authority, and returns the coordinator-owned
Replay advance command. Execute that returned command once. Never edit rewrite
state or treat the out-of-band result as API completion.
