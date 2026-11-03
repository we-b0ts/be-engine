# Fixed Implementers

Use for `implementer_dispatch_required`, pooled runtime observations and batch
handoffs. The engine allocates slots; the coordinator performs actual runtime
creation, resume and delivery. Runtime handles are separate from slot names.

## Slots And Group Mapping

Local `.traffic-e2e/regression.yaml` accepts a positive `max_implementers`, default
16. The effective value is captured when a workflow starts. Editing it during
the workflow does not resize or renumber that pool; the next new workflow uses
the changed value. `inventory.implementers.effective_max_implementers` is the
active limit. Do not add `max_workers` or invent live resizing.

Slot N has one name and worktree:

```text
api-implementer-N
<canonical-target-root>/.traffic-e2e/local/rewrite-worktrees/api-implementer-N
```

Use the exact `dispatch.worktree` returned by the engine. Do not add workflow IDs,
group names or API slugs. For a nested target, this directory is the outer Git
worktree; edit its corresponding target-project child and permitted managed
paths. Keep the canonical nested root for all engine commands. The integrator
uses a separate `integrator` worktree; the analyst is read-only and needs none.

New group IDs are assigned in stable order to slots round-robin, wrapping at the
effective limit. Persisted assignments survive restarts. One slot may own many
groups; same-group APIs default to the same slot. The engine does not predict
group cost or automatically rebalance. The coordinator may explicitly adjust a
group's future mapping:

```text
backend-rewrite implementer reassign --group <group-id> --slot <N> --reason '<observed reason>'
```

This changes future dispatches and does not interrupt an API. Groups exceeding
the slot count wrap naturally. Independent remaining groups can use their mapped
slots even when only one other implementer is busy; related tasks can remain
serial without creating extra worktrees.

## Confirm The Returned Batch

`implementer_dispatch_required.details` supplies `slot_id`, `name`,
`worktree`, `agent_handle`, `group_id`, a batch `dispatch_id`, `lease_generation`
and `apis`. Each API entry has its own `api`, `group_id`, `dispatch_id` and
`lease_generation`. Preserve both batch and per-API identities.

Reuse the stored handle when available; create a real `api-implementer-N` session
when this slot has none. The engine provides and validates the path; the
coordinator creates the actual Git worktree when absent, for example:

```text
git worktree add -b <slot-branch> <dispatch.worktree> <integrated-target-revision>
```

Confirmation requires a real worktree at that exact root; a plain directory,
symlink or another checkout is rejected. Before synchronizing an existing tree, preserve all
unhanded changes, queued assignments and local commits. Never reset an active
tree. A session may rotate after its assignments are drained; retain the slot and
worktree/cache. An unknown or unrecoverable active session needs recovery, not a
duplicate implementation owner.

Send the same-group batch, canonical root, returned worktree, Source locations,
group summary, and original per-API lease identities. The implementer queries
each API's current scoped evidence before editing it. A slot can receive another
group batch while retaining queued work; it still develops at most one API at a
time. Do not tell two runtime tasks to edit the same slot concurrently.

After runtime acceptance, execute the exact `commands.confirm` with the actual
handle. Its CLI is:

```text
backend-rewrite implementer confirm --slot <N> --group <group-id> --dispatch-id <batch-dispatch-id> --agent-handle <actual-handle>
```

Confirmation binds every member and records it queued. It is not proof that all
members are running. Repeating the same confirmation is idempotent.

## Restore A Missing Runtime

Resume the recorded handle first. When an actual runtime API query establishes
that the exact old handle no longer exists and cannot be resumed, retain the
slot/worktree and create a replacement runtime session. A timeout, incomplete
listing, session restart or ended-but-resumable turn does not prove absence.
Report the actual query and its RFC 3339 timestamp:

```text
backend-rewrite implementer replace-runtime --slot <N> --previous-agent-handle <old-handle> --agent-handle <new-handle> --reason '<proven runtime absence>' --runtime-query-command '<actual query>' --runtime-query-at '<actual RFC3339 time with timezone>'
```

This compare-and-swap preserves the checkout, group mapping and pending APIs.
It replaces pending task dispatch/lease identities and rejects old callbacks;
already accepted handoff history stays unchanged. Reload `inventory` and give
the replacement every pending task's new identity before it resumes. Do not use
the legacy per-API `worker transfer` for a pooled slot, discard unhanded changes,
or run old and replacement sessions concurrently.

## Runtime Activity And Partial Handoff

Query each live slot handle once per mandatory runtime-query pass, then reconcile
its API tasks. Per-API observations must use `implementer report` with the
original lease; never infer an API from the handle alone:

```text
backend-rewrite implementer report --slot <N> --api '/route' --dispatch-id <api-dispatch-id> --lease-generation <generation> --agent-handle <actual-handle> --activity running
```

Supported activity is `queued`, `running` or `idle`. Only one API per slot can be
running. Idle means this API stopped without an accepted handoff; it does not
claim that all other slot tasks ended. Use `inventory` for `current_api`,
`developing_api_count`, `pending_api_count`, assigned `groups`, tasks and handles.
Reject stale API/dispatch/lease callbacks even when the slot name is unchanged.

Each completed API needs its exact committed delivery, without review check. An implementer
may return one or several deliveries, including APIs from different assigned
groups. The coordinator submits the completed subset as one JSON array:

```json
[
  {
    "api": "/api/a",
    "dispatch_id": "<original API dispatch>",
    "lease_generation": 1,
    "handoff_id": "<stable identity unique to this API delivery>",
    "delivery_commit": "<full committed delivery SHA>"
  }
]
```

```text
backend-rewrite implementer handoff --slot <N> --agent-handle <actual-handle> --deliveries <deliveries.json>
```

All members are validated before activity is published. The engine freezes
accepted commits and reports independently of the reused checkout and releases
only those API leases. Duplicate accepted deliveries are harmless. Remaining
tasks stay assigned; a handoff event is not a whole-slot idle event. Recheck the
actual task result and inventory before resuming or appending work.

## Integration And Group Replay

Accepted handoffs enter [integration](coordinator-integration.md). Use the
exported frozen commit/report identities even if the implementer is now editing
another API. Integration reports still use the original handle, unique handoff
ID and original integration report; that delivery identity disambiguates APIs
sharing a handle. Plain handle-only runtime `worker report` is invalid for pools.

The engine grants Replay only after review and integration or another precise
existing rule/system-repair admission. It freezes one group's admitted route
list and target/recording identity, executes routes sequentially with their
admitted method contracts, and saves each result. Ordinary failure continues to
the next route. The group finishes before its next same-group failure batch is
dispatched. Infrastructure failure preserves partial results; recover or retry
the returned operation without repeating finished routes.

Initial pending routes and admitted acceptance routes form separate rounds.
An API pending fresh evidence can retain historical attempts; zero attempts are
not required for a stale-evidence retry. Unhanded failed APIs are not pulled into
acceptance because they share a group. Final
quality review and the final full revalidation retain their existing gates.
