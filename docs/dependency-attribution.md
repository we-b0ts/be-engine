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

Workflow state stores one shared owner/proof/rule template per finite occurrence
group, with every original Source UUID retained. Active ownership has unique
membership; history preserves the complete sequence of prior decisions and
revisions. This avoids duplicating large Source call-chain proofs hundreds of
thousands of times during ordinary status reads and state clones. Public
per-occurrence evidence remains the same typed projection.

The store reads the prior per-occurrence map and history array and writes compact
groups on the next ordinary coordinator mutation. It rejects duplicate active
UUIDs, mismatched legacy keys and contradictory templates for one proof revision.
It does not rewrite recordings, discard history, reduce required Source coverage
or change consumption. Rule, Source revision and sealed-inventory expiry checks
remain mandatory and operate on the shared groups.

`dependency-attribution show --api /route` returns one canonical API view with all
method contracts. It includes real attempt/session identity, response gates,
dependency failures, all attempted hypotheses (including rejected probes), original
Source IDs, protected unmatched Target IDs, ownership claims and scoped origin
obligations. Follow returned pagination commands. SQL/Redis arguments and raw
payloads stay in protected evidence queries; summary output contains identities,
coordinates, shapes and digests.

## Implementer claims

An API implementer owns its API behavior, including any traffic it reports as
missing. A concrete unused occurrence may be returned as an ownership dispute
without proving exclusion or tracing another API or task. The coordinator submits:

```json
{
  "schema": "dependency-attribution/v3",
  "api": "/current-api",
  "evidence_id": "<current-method-evidence-id>",
  "source_exchange_ids": ["<actual-unused-source-uuid>"],
  "reason": "The implementer returns these specific occurrences as not belonging to its API"
}
```

Use `backend-rewrite dependency-attribution claim --file claim.json`. The engine
checks current implementer confirmation, exact finalized real unused evidence and
original Source membership. Passing responses and an exclusion proof are not
required to report the dispute. An optional historical `exclusion` proof remains
readable. The analyst must either reject the return with Source proof, preserving
the original owner, or prove another owner under effective rules. A return never
waives dirty or incomplete capture and does not itself change the owner.

### Missing traffic remains with its reporting API

An unmatched request is an independent Target observation, even when it has no
Source candidate. Reporting missing traffic claims that traffic for the current
API; it does not open repository-analyst work. The existing API implementer traces
its actual async lifecycle, caches, client topology and complete capture evidence.
If the API's asynchronous work was captured elsewhere, it supplies its own
`async_api` rule. If capture omitted the required call, it supplies the exact
Source endpoint and omission reason: for example a fixed IP requiring explicit
interception or an IP URL returned in a dependency response requiring
`http.response_rewrite`. It does not infer capture loss from an empty candidate
page, or invent a hostname, missing response or unrelated owner.

The coordinator may retain authenticated observations with
`investigate --file investigation.json` using the same schema, canonical `api`,
current `evidence_id`, a nonempty factual `reason` and exact
`target_observation_ids`. The result and `show --api` explicitly retain
`owner: api_implementer` and return offline candidate-discovery commands.

The implementer's conclusion is published by the coordinator with
`dependency-attribution resolve --file diagnosis.json`. Supply `schema`, current
`evidence_id`, `expected_revision` from the API investigation view, and `resolution`
with `investigation_id`, `outcome`, `source_task`, current Source `proof`,
`origin_scope` and factual `reason`. Resolution checks the current API owner,
attempt, report, Source inventory and revision. `cross_scope` requires the
reporting API's effective async lifecycle rule; `missing_capture` retains capture
debt on that API. Value-rule, implementation and unresolved results remain
explicit and never grant acceptance. Analyst `apply` does not resolve owned
missing-traffic investigations.

When an implementer's async rule proves that its existing Source dependencies
were captured in another scope, the coordinator publishes that implementer's
positive ownership proof through the existing `context` / `apply` transaction
before resolving `cross_scope`. Bind the actual origin input, exact Source
occurrences and effective async lifecycle rule. This known-owner diagnosis does
not require another analyst. A rule or `resolve` result alone does not move
recorded ownership or grant matching permission. Keep missing origin/occurrence
proof unresolved; use a concrete ownership return if another owner is disputed.

## Independent analyst proof

The engine requests the repository analyst only for actual ownerless semantic
Source occurrences or concrete ownership returns. Changing batches, known-owned
startup dirt, unused dependencies or unmatched Target requests alone do not
request attribution analysis. Known-owned new inventories are admitted
mechanically without a repository scan.

All ownerless Source occurrences must acquire supported effective process-task
or async-origin API rules and independent positive attribution proof before
formal Replay. Empty or partial review cannot admit the remaining ownerless
inventory. A mistaken ownership return can instead be rejected with Source
proof. Status, scoped acceptance and the actual Replay execution boundary retain
the same gate. Capture and final-batch verification obligations remain separate.

The coordinator obtains `dependency-attribution context` and dispatches its exact
assignment to the read-only repository analyst. The context includes Source and
proof revisions, ownership returns, actual declared task groups,
unattributed business occurrences and origin obligations. Protocol control facts
remain in the inventory and follow their native contracts; they are not silently
counted as unattributed business requests.

`dependency-attribution source --exchange-id UUID` inspects an authenticated
original occurrence without exposing payloads. API-owned missing-traffic
investigations expose offline resource/operation candidate pages across Source
scopes to their implementer, with executable continuations:

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
Before the first Replay, use the context's exact `rule_planning` evidence token
and plan command for Source-only owner rules; no fabricated Target attempt is
needed. Source-only ownership planning cannot authorize value differences or
successful consumption.
New named process-owner rules bind the current workflow Source revision explicitly.
An older document-level `source_revision` remains the default for existing rules;
it neither changes those proofs nor overrides a newly reviewed owner's revision.
The native rule retains that explicit revision when it cannot use the compact
task declaration under the older header.
The analyst submission echoes `assignment_id`, `expected_revision`,
`recording_run_id`, `source_revision`, `source_inventory_id` and contains:

- `decisions`: positive ownership proposals;
- `investigation_resolutions`: empty; API-owned conclusions use `resolve`;
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
API aggregate does not enumerate startup dirt or initialization inventories.
Original run-level evidence remains available on demand through the issue's
`source-process-traffic` query for diagnosis, including missing local-cache
preparation. A real effect on the
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
Target execution identity. The coordinator routes known-owned failures to their
existing implementation owner; this query does not dispatch a repository analyst.
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
