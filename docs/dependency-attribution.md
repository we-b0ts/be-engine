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

## Report a disputed Source owner

Only the independent repository analyst investigates disputed or unknown Source
traffic ownership, including which Case, API or task triggered the traffic and
which lifecycle rule applies. The current implementer can trigger this analysis
by returning a concrete unused Source occurrence it believes is foreign:

1. The implementer uses `dependency-attribution show --api /route` and returns
   the exact unused Source UUIDs, their current method evidence ID and a bounded
   factual reason. Proving exclusion and tracing the true owner belong to the
   repository analyst.
2. The coordinator uses the returned `dependency_occurrences.claim_command` with
   the payload below. Once `status` returns `dependency_attribution_required`,
   the coordinator runs the returned context command and dispatches the exact
   read-only assignment to the repository analyst.

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

After a premature client transport end, later Cases can contain unused Source
occurrences produced by that origin's disconnect path. Return the exact unused
UUIDs from the affected Cases with the same claim command. Analyst context
lists earlier observed client-abort candidates as timing clues, including
origins separated by multiple subsequent Cases. The analyst proves the actual
call chain and exact occurrence ownership. For ordinary detached business use
the existing end-only async API rule. For the interrupted transport path bind
`engine.client_abort_tail:v1` with the current policy fingerprint and the
claimed UUIDs, using the earlier Case as owner. The engine requires a sealed,
cleanly observed premature client EOF or reset, a later original Case and a
shared Source process epoch. The overlay removes just those occurrences from
the later scopes and requires real Replay of the changed origin scope.
An unmatched Target request remains separate evidence. Temporal proximity alone
cannot authorize reassignment, consumption or a new response.

### Missing traffic remains with its reporting API

An unmatched request is an independent Target observation, even when it has no
Source candidate. When the implementer reports a missing dependency of its own
API, it traces the API's actual async lifecycle, caches, client topology and
complete capture evidence.
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
If the open question is foreign ownership and only unmatched Target observation
IDs are available, report the observation and evidence IDs as an unresolved
ownership question. The current engine has no analyst dispatch from those IDs
alone. A claim requires actual unused Source UUIDs from the current finalized
attempt.

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

Each analysis must assess the existing policy as well as the current occurrence
owner. Return the following findings with the ordinary attribution submission;
these are analysis and handoff content, not new submission fields:

- The Source owner and call chain, with exclusive proof connecting the current
  occurrence UUIDs to their actual origin input or process task.
- Whether the effective policy is missing, incomplete or sufficient, naming the
  applicable rule IDs and scenarios. If a change is needed, supply the smallest
  supported proposal. An async proposal describes its API/request/response
  trigger and analyzed `end` paths, including business cleanup on the applicable
  success, failure and cancellation branches. It does not list the
  API's intermediate SQL, Redis or other dependency requests.
- Why the current sealed recording needs correction: a missing lifecycle path,
  capture before the applicable rule took effect, or a concrete execution gap
  despite sufficient policy. Cite the available rule and recording evidence;
  current policy alone does not prove which rule was active during capture.
- The necessary policy publication, exact-UUID attribution proof and remaining
  real Replay or capture obligations for the coordinator.

Rule generation follows the completed ownership analysis. For an async origin,
combine its original Case scope with newly assigned occurrences and exclude
proven foreign work. From the complete effective tail, return the actual scenario,
end request templates, necessary response/message predicates and matching counts
from Case admission. Do not use the last page or only the formerly ownerless
subset as the Case boundary. Generalize physical task IDs and check earlier
matches; reuse existing coverage instead of accumulating duplicate candidates.
Author the proposal under `recording.async_api`, before independent optional
`recording.case_paths`. The logical rule identity remains `capture.async_api`.
The last observed exchange is evidence for a candidate, not independent ownership
proof. Redis nil means `when_response: {kind: nil}` on a complete native reply;
PUBLISH request JSON stays under `when_message`.

Any alternative end can enter ending. Once all ends have matched, close new
admission immediately and drain admitted requests; a single end follows this same
rule. Partial matches permit a fixed one-second probe after each fresh match. Any
subsequent relevant request start requires another fresh end before closure
becomes eligible; another one-second silence alone cannot close the Case. A completed probe
also requires no relevant requests in flight. Only unambiguously process-owned
requests are ignored. After the complete primary response, waiting for the first
or next end has no absolute deadline. Without a fresh end, five continuous minutes
of relevant business I/O silence and no relevant request in flight close the Case
normally with completion unobserved, keeping Source running for rule analysis.
Real business activity restarts that interval; writer queues and definite process
traffic do not. The primary HTTP transport timeout remains separate; explicit
shutdown or actual capture failure can interrupt observation.
The probe duration is not authored policy. Rule
proposals need no new Source completion signal, all-of groups or intermediate
request whitelist. The coordinator must receive either this proposal, an explicit
existing-coverage finding, or the concrete unsupported evidence alongside the
ordinary attribution submission.

These rules describe future recording scope; the attribution submission corrects
the finite existing recording separately. A sufficient effective policy need
not be changed just because an older recording still has ownerless traffic.
State which rule covers the Source path and continue supported manual
attribution with exact original UUIDs and positive proof. Do the same for a
demonstrated execution gap while reporting that gap separately: an engine repair
is not an additional prerequisite for ordinary proof/apply. Do not submit a
no-op rule plan. Absent required capture remains capture debt; an ownership
overlay cannot recreate traffic that was never recorded.

Established Source call-chain and lifecycle analysis can be reused across
batches while it remains applicable. Obtain current context and bind each new
proof to its actual inventory, UUIDs, origin Cases and rule fingerprints. A new
batch alone does not require repeating the repository analysis; a new Source
path or contradictory evidence requires reviewing the affected conclusion.

`dependency-attribution rules` returns complete active task/lifecycle rule groups
and their fingerprints. The coordinator publishes any necessary Source-proven
rule change through unified rule plan/apply first, then obtains fresh attribution
context, rebinds the already established exact-UUID ownership proof and follows the returned action
into genuine Replay. If the effective policy is already sufficient, skip rule
publication and obtain fresh attribution context directly. Applying policy or
ownership alone does not establish a pass.
Fresh context updates transaction identities; it does not require repeating the
completed Source ownership analysis.
Before the first Replay, use the context's exact `rule_planning` evidence token
and plan command for Source-only owner rules; no fabricated Target attempt is
needed. Source-only ownership planning cannot authorize value differences or
successful consumption.
Independent task declarations do not bind to a Source version. They describe
`process_dependencies.tasks.<task>.requests` using ordinary dependency commands;
for example, a Redis `SUBSCRIBE` command and its exact resource and arguments
anchor the receive stream without moving the original Startup handshake or a
Case's `PUBLISH`. Proof retains its actual Source origin and immutable recording
inventory. An older document header does not rewrite that evidence or couple the
continuing task declaration to a particular Source image.
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

### Submission shape and field values

The following example shows a Case-owned async decision. All placeholders,
sample UUIDs, API, rule ID and scenario index must be replaced with independently
verified facts from the current assignment. Copy `expected_revision` from
`context.revision`; the other envelope identities come from the same fresh
context. Reusing this JSON shape does not reuse ownership proof.

```json
{
  "schema": "dependency-attribution/v3",
  "assignment_id": "<context.assignment_id>",
  "expected_revision": 0,
  "recording_run_id": "<context.recording_run_id>",
  "source_revision": "<context.source_revision>",
  "source_inventory_id": "<context.source_inventory_id>",
  "decisions": [
    {
      "claim_ids": [],
      "source_exchange_ids": ["11111111-1111-4111-8111-111111111111"],
      "source_task": "<actual Source task or call-chain name>",
      "owner": {
        "kind": "case",
        "origin_case_id": "22222222-2222-4222-8222-222222222222",
        "task_instance": "<actual Source task identity>"
      },
      "proof": {
        "source_revision": "<context.source_revision>",
        "source_locations": ["src/jobs.rs:finish_job"],
        "call_chain": "<Source entrypoint, dispatch and dependency-producing calls>",
        "exclusive_scope": "<current occurrence-to-origin identity and exclusive scope proof>"
      },
      "impact": "runtime",
      "obligation_scope": {
        "kind": "api",
        "api": "/jobs",
        "method": "POST",
        "scenario": 0
      },
      "missing_evidence": null,
      "rule_binding": {
        "policy_fingerprint": "<context.effective_policy_fingerprint>",
        "rule_ids": ["capture.async_api:POST /jobs"]
      }
    }
  ],
  "investigation_resolutions": [],
  "claim_rejections": [],
  "unresolved_claim_ids": []
}
```

`owner.kind` is `case`, not `async_api`; the lifecycle is bound by `rule_binding`.
`obligation_scope.kind` is `api`, with the canonical route and separate method.
Its `scenario` is the zero-based index of the actual matching configured async
scenario, not an index into `rule_groups`. `method` and `scenario` also accept
`null` where the proven obligation covers that broader API scope. They must
describe the actual origin, not the API reporting unused traffic.

For an independent process task, the corresponding owner and obligation are:

```json
{
  "owner": {
    "kind": "process",
    "process_epoch": "33333333-3333-4333-8333-333333333333",
    "source_task": "<actual declared Source task>"
  },
  "obligation_scope": {
    "kind": "process",
    "source_task": "<same actual declared Source task>",
    "process_epoch": "33333333-3333-4333-8333-333333333333"
  }
}
```

This is a fragment of a decision, not a complete submission. Bind its complete
active process rule group and prove its actual task/epoch. Optional
`owner.task_instance` for Cases and `owner.invocation` for processes may be
omitted when they are not part of the proof.

| `impact` | Meaning |
| --- | --- |
| `classification` | Ownership classification only; existing actual execution must remain valid. |
| `runtime` | Admission or delivered scope changes; the original owner needs genuine Replay. |
| `missing_capture` | Required Source capture is absent; identify the absent scope in `missing_evidence`. |

For ownerless traffic, `claim_ids` can be empty. Ownership returns use the exact
current claim IDs. All supplied occurrence IDs must belong to the current sealed
inventory; counts, time proximity and old decisions are not substitutes for
proof. The engine validates impact and scope rather than treating these fields
as acceptance instructions.

Proof requires 1–64 `source_locations`. Each location, `call_chain`, and
`exclusive_scope` must be nonempty, trimmed, contain no control characters, and
fit within **1024 UTF-8 bytes per string**, not 1024 characters. Check with
`len(text.encode("utf-8"))` before submitting; keep detailed supporting notes
separate while retaining the decisive Source references and identity proof in
the submitted strings. Unknown JSON fields are rejected.

### Correcting an existing Case owner

An occurrence can already have a captured Case owner and still require a proven
ownership correction. For example, a previous input's async completion may
continue after the recorder admits the next input. The observed/admitted window
records provenance; it does not independently prove which input produced that
completion. Task identifiers alone are insufficient: trace the actual Source
entrypoint, task identity, calls and exclusive occurrence scope.

For a concrete Source attribution assignment or actual scope-gap investigation,
the independent analyst can include those exact original UUIDs in a fresh-context
decision. `apply` is not limited to the unattributed set. Use the proven origin
Case as `owner`, its supported lifecycle rule, `impact: runtime`, and the actual
origin API as `obligation_scope`. A foreign-unused claim returns genuinely unused
traffic; it is not a prerequisite for an independently proved owner correction.

Apply publishes an ownership overlay. It retains the immutable original capture,
moves the selected memberships from the old Case view to the new Case view, and
checks affected execution obligations. Do not edit the recording or scope files,
add Target calls to consume the wrong owner's traffic, or broaden matching windows.
If an actual Target investigation uses `cross_scope`, publish ownership proof
before resolving that investigation, then use the new current proof revision in
the resolution. Follow the returned action into genuine same-Source Replay;
neither a successful apply nor a resolved investigation is an API pass.

Ordinary MySQL session cleanup does not require an application `async_api` rule.
The engine can restore native Case membership when a complete, consecutive wire
transaction has one original admitted Case and its members fall within that
input's primary capture window. Its successful zero-effect `ROLLBACK` and at most
one immediately adjacent idle rollback inherit that Case, with the observed Case,
resource, process epoch and status continuity checked. Gaps, unknown or mixed
members, incomplete responses and ambiguous wire identities retain attribution
debt. This restores protocol closure without changing original facts, request
matching, or delivery requirements.

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
occurrence. Independent WholeSource verification still checks startup and process closure.

After a genuine required origin execution, use
`dependency-attribution verify <obligation-id>`. API verification checks the actual
complete attempt; capture debt requires a new complete original input and current
execution. Process/startup obligations close through actual complete batch
execution. Focused attempts cannot be stitched together into a fictitious batch
session, and one physical occurrence is never consumed twice.

## Final workflow and WholeSource verification

After ordinary API acceptance, the integrator's final quality review admits the
exact candidate. The engine then executes every Case of every current non-skipped
workflow method in one actual session. This `workflow_contracts` scope comes from
the workflow inventory and existing `only`/`skip` selection; a command's `--api`
cannot narrow it. All methods must pass their responses and Case-owned dependency
contracts. A final session does not reuse historical passes or repair subsets.
The workflow retains methods discovered in earlier batches. Recapture cannot
silently erase a still-selected method when it replaces the current inventory;
restore that method's complete inputs and inventory, or explicitly exclude its
route through the existing `only`/`skip` policy. An explicit `only: [/api]` can
exclude an earlier `/other` requirement without deleting its history.
The sealed Source recording must still be complete, including all original input
captures; failed recordings cannot be hidden by selecting their published Cases.

`terminal_allowed` additionally requires that current workflow receipt, the
existing final review, expert closure and committed progress publication. Pending
Startup/Process verification debt remains diagnostic and uncompleted. It cannot
turn an otherwise passing workflow API into a failure. API-origin obligations
within the current workflow must still be verified; debt for an excluded known
owner remains with that owner. Unknown or disputed Source ownership still needs
resolution before formal Replay.

WholeSource acceptance is stronger and remains independent. Its `batch_receipt`
and `batch_verified` require one actual complete Source session and strict
reconciliation of every Case, Startup and Process occurrence. A workflow receipt
does not manufacture that receipt, consume background traffic or finish its
obligations. Old states without a workflow receipt need genuine final execution;
no receipt is synthesized from historical API statuses.

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
