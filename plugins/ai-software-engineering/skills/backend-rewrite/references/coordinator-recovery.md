# Coordinator Recovery And System Repair

For a Source Session setup or execution failure, follow the returned result
and [Session diagnosis](session-regression.md#diagnose-the-first-failure).
The action kinds and repair receipts below belong to the Case workflow.

Read this guide for `recovery_required`, `system_repair_required`, `blocked`, or an
engine-issued repair verification action. The coordinator owns every
state-mutating command in this guide.

## System Repair

`system_repair_required` exists only after `backend-rewrite route` accepts a
cause that requires a system/source change, together with current evidence, a
source reference, and the required change. The route captures an
engine-defined system/source revision and returns an opaque repair ID;
never supply an invented acceptance command.

The responsible implementation/system worker or external owner applies the
required repair. The coordinator does not repair code while idle. Read global
status again after installing the repair.
Record the repair route and its acceptance identity before installing the new
engine. If the engine was already upgraded and the current issue is outside the
automatic changed-engine retry categories, use the current worker dispatch's
ordinary review/handoff/integration path. An unchanged candidate is valid after
real review; when candidate equals the current assignment base, verify its
identity and retain canonical HEAD as described in the integration guide. Do
not manufacture a code commit or reuse an already consumed repair identity.
Until the relevant revision changes, it is counted in `waiting.system_repair`
and `action.details.acceptance_ready` is false. Other ready worker work continues. The engine can park this API with its exact
issue, evidence, route, and repair identity while verifying other APIs. After
every implementation is accepted or confirmed as a gap, the engine requires
current final pre-revalidation proof before deferred revalidation starts a
persistent round. Follow `pre_revalidation_review_required` through
[final review](coordinator-review.md#final-review-before-full-revalidation). Drain all its members before acting on
new repair or worker handoffs, even if individual APIs fail. Recovery retains
remaining membership; fingerprint changes do not repeat finished members.
After eligible revalidation drains, a global `blocked` action stops this run
when the remaining incomplete APIs all require system repair. Preserve resume
context and worker bindings; do not claim completion. A later global status
checks both active and parked repair revisions and can resume acceptance.
Once ready and the verification resource is free, it contributes one
`ready.verify_system_repair` and is selected before worker checks or dispatch outside an active revalidation round.
Execute the exact `action.commands.acceptance` returned then. New repairs use
`repair verify <repair-id>`. A legacy Response `external_data_blocker` now
expressible by bootstrap Replay planning instead receives
`repair resume-replay-planning <repair-id>`; that migration does not require a
runtime-input revision change. `next` cannot
bypass the returned command.

System-repair actions retain the route, triggering `work_scope`, readiness, and
available acceptance command as scheduling information. The assigned worker
fetches any needed diagnostics through `evidence --api '<assigned path-or-pattern>'`
against the canonical target root; status does not embed evidence or its command.

Successful verification chooses the next transition. Replay and external-input
repairs authorize Replay for the same owning API and immutable cases without a
new implementation handoff. Target quality gates still apply. For a Recorder
or Source baseline repair, follow the engine's required Case evidence handoff.

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
After it succeeds, execute the exact engine-issued `repair verify
<repair-id>` acceptance command; do not substitute initialization preflight or
a manually constructed recording. If only runtime inputs changed while the
image stayed the same, the upgrade does not satisfy `source_change` acceptance;
use the engine's runtime-input repair (`external_data_blocker`) and its
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

Before reporting an IP capture defect, use `route --cause unrecorded-ip` with
the worker's current evidence and inputs. Route further Source investigation
to that worker. Establish the address origin and the missing capture mechanism
from Source and the exact dependency evidence.

Use `recorder-capability-gap` only when the recorder lacks a required mechanism.
Use `replay-capability-gap` for a proven response decoding or semantic assertion
capability gap.
## Status And Recovery

Use `backend-rewrite status [--api '<assigned path-or-pattern>']` to reconstruct a lost or
resumed action without advancing state. Depending on current state it returns:

- exact `action.commands.apply` for a pending plan;
- `action.commands.wait` while selected external evidence is being published;
- `action.commands.advance` after a finalized manifest or target change is
  ready; or
- the engine-issued system-repair acceptance.

`recovery_required` concerns rewrite-owned workers, locks, and focused Replay
attempts. Execute its exact `action.commands.recover`; a live executor prevents
recovery. External recording processes and containers remain owned by their
deployment caller. An unfinished external manifest stays an input wait and
cannot authorize rewriting evidence or allocating a replacement run.

`wait_required` is not recovery. It proves that a live or non-preemptible owner
blocks the requested transition or a worker handoff is pending, and supplies a
bounded wait command. Before waiting on agents and after each wait, follow the
[mandatory runtime query pass](coordinator-agent-protocol.md#mandatory-runtime-queries),
reconcile results and events, and refresh global status. Only
`recovery_required` authorizes `recover`.

Internal runner paths are not stable rewrite-interface contracts. Use public
status/actions and immutable artifact paths exposed by the engine as the
primary interface. Read-only inspection of `.traffic-e2e/local/runtime/**` is
allowed for diagnosis, but never edit it or reconstruct recovery actions from
its layout.

If an older coordinator left concrete route owners in a recording run after
the canonical inventory adopted case path patterns, Replay may reject the same
case as already owned by another group. For that exact compatibility failure,
an administrator may run:

```bash
backend-rewrite-admin --target-root <target> repair rebuild-case-groups \
  <recording-run-id> --confirm-rebuild
```

The command accepts only the current workflow's recording run while all
coordinator, traffic, full E2E, and focused E2E execution is idle. It backs up
the derived group index, rebuilds complete coverage from the canonical API
inventory, and rolls back automatically on failure. Managed indexes persist
case paths relative to the target root. For a copied legacy absolute-path index,
the command verifies the original index, recording run, source revision, and
location-independent case inventory before migrating both the case-group and
E2E run indexes; the original paths must remain readable during this one-time
migration. It never changes recording artifacts or rewrite progress. On success,
execute only the failed operation's exact retry command from `backend-rewrite
status`.

If an administrator confirms that `traffic-e2e run-api` was mistakenly run
outside an active rewrite workflow, use `backend-rewrite-admin repair
retry-replay` with the exact failed engine attempt, newer passing
out-of-band attempt, API, reason, and confirmation flag. The command accepts
only unchanged target content and matching case source/inventory, discards the
external result as workflow authority, and returns the coordinator-owned
Replay advance command. Execute that returned command once. Never edit rewrite
state or treat the out-of-band result as API completion.
