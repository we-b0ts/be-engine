# Dependency attribution and verification

Current recordings use `traffic-recording/v3`, policy documents use
`traffic-policy/v3`, and ownership submissions use `dependency-attribution/v3`.
Old recording, report and workflow ownership semantics are unsupported.

The central Source inventory is immutable. Each physical exchange has a stable
`source_exchange_id`, request-start capture metadata and original owner. Applied
ownership decisions are a separately versioned overlay, bound to Source revision,
sealed inventory identity, positive Source proof and effective rules. Replay
freezes one overlay per actual session. Ownership proof never writes a consumed
occurrence or alters a historical Replay report.

Keep three independent facts: Source capture proves what was observed; a
Source-backed attribution decision proves the owner and permitted scope; actual
Target delivery proves consumption in one session. A request match, a hypothesis
or an ownership proof cannot substitute for successful delivery. A later proof
changes the effective ownership view while retaining the original capture and
actual execution facts.

`dependency-attribution show --api /route` returns one canonical API view with all
method contracts. It includes real attempt/session identity, response gates,
dependency failures, all attempted hypotheses (including rejected probes), original
Source IDs, protected unmatched Target IDs, ownership claims and scoped origin
obligations. Follow returned pagination commands. SQL/Redis arguments and raw
payloads stay in protected evidence queries; summary output contains identities,
coordinates, shapes and digests.

## Implementer claims

An API implementer proves current API behavior and value mechanisms. For concrete
unused occurrences, exclusion from the current API is enough to open an independent
investigation; it is insufficient for acceptance. The coordinator submits:

```json
{
  "schema": "dependency-attribution/v3",
  "api": "/current-api",
  "evidence_id": "<current-method-evidence-id>",
  "source_exchange_ids": ["<actual-unused-source-uuid>"],
  "exclusion": {
    "source_revision": "<current-source-revision>",
    "source_locations": ["src/api.rs:handle"],
    "call_chain": "Complete current API path and relevant branches",
    "exclusive_scope": "Why these concrete requests cannot originate here"
  }
}
```

Use `backend-rewrite dependency-attribution claim --file claim.json`. The engine
checks current implementer confirmation, exact finalized unused-only attempt and
original Source membership. The claim creates independent analyst work, not a
waiver. Implementer work on other issues can continue.

An unmatched request is an independent Target observation, even when it has no
Source candidate. Submit `investigate --file investigation.json` with the same
schema, canonical `api`, current `evidence_id`, a nonempty factual `reason` and
`target_observation_ids` from the actual report. Do not invent a Source UUID.
The engine authenticates protected observation coverage and the actual attempt.
Unmatched does not imply async behavior: possible outcomes include a value rule,
Target implementation defect, cross-scope ownership, missing capture or unresolved.

## Independent analyst proof

The coordinator obtains `dependency-attribution context` and dispatches its exact
assignment to the read-only repository analyst. The context includes Source and
proof revisions, pending claims/investigations, actual declared task groups,
unattributed business occurrences and origin obligations. Protocol control facts
remain in the inventory and follow their native contracts; they are not silently
counted as unattributed business requests.

`dependency-attribution source --exchange-id UUID` inspects an authenticated
original occurrence without exposing payloads. Investigations include offline
resource/operation candidate pages across all Source scopes, with executable
continuations:

```text
backend-rewrite dependency-attribution candidates --investigation ID \
  --target-observation ID --revision N --offset N
```

Pagination rejects a changed proof revision. Resource/operation candidates have
not compared request payloads, authorized scope or established actual consumption.
An empty candidate page proves none of async ownership, missing capture or a
Target bug.

The analyst traces actual entrypoints, indirect calls, branches, retries and
cleanup. An independent process task is grouped by its complete declared
`process_dependencies.tasks.<actual-task-name>.requests` selector set across
protocols and Cases in the process epoch. Naming a task is not proof. For a
foreign async API, bind the actual origin Case and applicable end-only `async_api`
scenario. Intermediate business requests need not be enumerated. The original
request/response scenario must match the lifecycle rule.

`dependency-attribution rules` returns complete active task/lifecycle rule groups
and their fingerprints. The coordinator publishes any new Source-proven rule
through unified rule plan/apply first, then obtains fresh attribution context.
The analyst submission echoes `assignment_id`, `expected_revision`,
`recording_run_id`, `source_revision`, `source_inventory_id` and contains:

- `decisions`: positive ownership proposals;
- `investigation_resolutions`: independent unmatched investigation conclusions;
- `claim_rejections`: independently proved rejections of mistaken foreign-unused claims;
- `unresolved_claim_ids`: claims requiring more evidence.

Each `claim_rejections` entry contains `claim_id`, a current Source-backed `proof`
and a bounded factual `reason`. Rejection cancels that ownership claim only. It
does not prove another owner, remove original unused/dirty facts, grant matching
permission or issue acceptance. The responsible API still needs to resolve its
actual failure unless separate positive proof already establishes a valid owner.

Each decision contains `claim_ids`, `source_exchange_ids`, `source_task`, typed
`owner`, positive `proof`, `impact`, `obligation_scope`, optional
`missing_evidence`, and `rule_binding` with exact `policy_fingerprint` and complete
`rule_ids`. An empty process `source_exchange_ids` lets the engine expand the
complete selector group. A supplied process set must equal that whole group.
Startup sharing similarly binds explicit effective finite initialization rules
and their complete selected request scope. Source revision, selector coverage,
epoch, origin request/response, completeness and assignment CAS are checked before
any state changes. Overlapping decisions in one submission are rejected.

The coordinator runs `dependency-attribution apply --file attribution.json`.
Immutable original facts and decision history remain available. Rule removal,
changed fingerprints or Source revision invalidate active proofs and reopen the
affected assignment and acceptance.

## Acceptance and origin obligations

The engine can issue `ai-verified` for an API's existing actual attempt only when
responses passed, Replay completed, all remaining failures were unused occurrences,
and every occurrence has independent positive proof of a foreign owner under
active rules. Unmatched/unsafe requests, protocol failures, used hypotheses,
incomplete capture and execution failures still block. Claims and analyst output
cannot directly set acceptance.

This API result is separate from full batch verification. Reassigned Source work
retains Replay or capture obligations on its actual origin API, process task or
initialization scope. An async rule addition does not force re-recording an
unrelated API. A matching/delivery change needs fresh Replay of the affected scope
against the same Source. Only concrete absent Source evidence opens capture debt.

Startup-phase dirty evidence does not decide independent API acceptance. The
aggregate retains the original startup phase and its unstarted dependency counts
for diagnosis, including missing local-cache preparation. A real effect on the
API still fails its response or Case dependency checks. Unstarted initialization
for other APIs or process tasks does not become a Case failure or a consumed
occurrence; the final actual batch still checks startup and process closure.

After a genuine required origin execution, use
`dependency-attribution verify <obligation-id>`. API verification checks the actual
complete attempt; capture debt requires a new complete original input and current
execution. Process/startup obligations close through actual complete batch
execution. Focused attempts cannot be stitched together into a fictitious batch
session, and one physical occurrence is never consumed twice.

## Final whole-batch verification

After ordinary implementation and API acceptance, the integrator's final quality
review admits the exact candidate. The engine then executes one complete actual
batch session for formal revalidation. Method results are projections of that
same session; the final stage does not run a separate per-API round followed by
another sweep and another batch. First-pass and repair acceptance Replay retain
their existing diagnostic purpose before this final stage.

Final coverage has two requirements. The session must execute the complete
current sealed Source run, including its Case, startup and process obligations.
That run must also contain complete inputs for every required workflow method
API. The durable workflow method set survives scoped recapture; explicit workflow
skips affect that method requirement. A new recording containing only the repaired
origin cannot silently erase other required methods. Historical focused attempts,
receipts and separate Source runs cannot fill missing coverage in the final run.

Use `dependency-attribution batch --offset N` for the current batch result and
paginated actual Target request metadata, including run-owned requests. Follow
its `next_command` and each entry's explicit bounded query:

```text
backend-rewrite dependency-attribution target --session SESSION \
  --observation TARGET_ID --pointer /args/1/json/id
```

The same batch view returns `rule_analysis` when the latest finalized full
execution still matches the current Source inventory, ownership revision and
Target execution identity. Dispatch its independent repository analyst assignment.
Its `batch-evidence-*` token is accepted by the ordinary `rule plan --file ...
--evidence ...` transaction. The planner freezes the actual full report, runner
assertions and complete Source scope, then applies the shared typed preflight and
policy compare-and-swap checks. It neither invents an API issue nor borrows an API
worker's confirmation. Supported global, dependency-resource and task declarations
can be proposed here; API response, inbound and API-conditional permissions require
their real API issue. Unsupported effects or capture changes without an exact
proven origin scope are rejected explicitly. Applying a batch runtime change
requires a new complete actual session and grants no acceptance to the failed one.

The session and observation identify an authenticated actual request. Select a
non-root pointer; Redis argument indexes are zero-based after the command.
Queries return only a bounded selected value and require narrower selection for
oversized results. Batch summaries contain references and metadata rather than
raw SQL, Redis keys or request bodies. Keep private queried values out of shared
summaries. Authenticated retained entries may aid diagnosis when total coverage
is incomplete; their query result is not formal rule proof, Source ownership or
successful consumption.

An accepted final review, committed progress or manually completed API statuses
cannot create a batch receipt. Missing Source coverage remains an input
requirement; unresolved actual batch failures remain diagnosis work. A repaired
batch failure needs the returned `retry-batch --reason` action and a new complete
session. Final acceptance requires a current engine-issued receipt bound to that
session, sealed Source inventory, candidate, rules and attribution snapshot.
