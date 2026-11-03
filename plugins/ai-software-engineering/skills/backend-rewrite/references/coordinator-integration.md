# Coordinator Integration

Use for `integration_required` and the separate final
`pre_revalidation_review_required` stage. The integrator merges assigned code
and resolves conflicts. The coordinator publishes its exact candidate and
reports the accepted handoffs. Do not assign code review to an ordinary integrator. It reads code only to
resolve actual conflicts. Ordinary integration does not run `review check`,
organization checks or quality gates.

## Retain One Integrator

Keep one integrator handle and separate worktree per workflow at
`<canonical-target-root>/.traffic-e2e/local/rewrite-worktrees/integrator`.
Use actual runtime spawn/resume tools and retain assignment IDs, canonical base,
input identities and results outside engine-owned state. Run one integration
assignment at a time. Do not bind this handle as an API implementer or report
integrator activity through `worker report`.

For a conflict-free integration, do not run `cargo build`, `cargo test`,
`cargo fmt`, `cargo clippy`, `review check` or other code checks. Git identity,
ancestry and clean-publication checks are delivery bookkeeping, not code checks.

## Dispatch

Read inventory and select current `integration_required` handoffs. Pass each
original workflow/recording, API, binding/dispatch, unique handoff ID, accepted
`delivery_commit`, worker base/worktree, local test results and shared impact.
A pooled checkout may already have been reused: consume the frozen accepted
commit, not its current files or HEAD. Handoff IDs and Git commits are separate
identities. Retain already integrated code in the canonical base.

Supply role `code-integrator`, task `integrate`, a unique assignment ID, canonical
root, retained integration worktree, canonical base and Source locations. The
integrator merges the chosen commits, resolves behavior-determined conflicts,
commits the candidate and returns its full commit ID and provenance. It does
not independently re-prove API business logic or perform a review check. Return
unresolved business decisions to their implementing owner. Do not require
formatting, line-limit splitting, spawn evidence, Clippy or full tests for
ordinary integration. Only when resolving an actual conflict changes code, run relevant module tests
and format when needed. Do not run a separate cargo build, Clippy, other lint
or source review; later stages handle quality checks centrally.

Additional ready handoffs may join before the candidate is returned. Record
which original handoffs the resulting commit includes. A later addition creates
a new candidate version, without repeating already completed integrations. No
review batch export, check command, review report or review acceptance is needed.

## While The Task Runs

Collect actual runtime events and continue independent authorized dispatch and
feedback. Query runtime status before and after bounded waits following
[the runtime protocol](coordinator-agent-protocol.md#mandatory-runtime-queries).
An unchanged action is not another integrator dispatch. Do not publish canonical
changes or start acceptance while publication is in progress. Respect active
traffic operations and preserve unfinished work.

## Reconcile The Result

Match original assignment, scopes/dispatches/handoffs and canonical base.

- `ready`: require exact candidate commit, included delivery identities,
  conflict resolutions, provenance and required inputs. No review report.
- `rework`: for an accepted handoff, use `commands.report_rework` with its
  original worker handle and handoff ID when the engine permits it. No check
  report is required. Return concrete business/conflict evidence to its owner.
- `stale`: preserve useful work and reassign only current work on the current base.
- `needs_input`: return the specific request to its input owner.
- `execution_failed`: resolve the actual task/local failure; it is not API completion.

A superseded assignment cannot advance state. Duplicate results do not repeat
merges or reports.

## Publish A Ready Candidate

Re-read status. Match original handoffs/dispatches, canonical base, relevant
inputs and candidate commit. Require fast-forward publication without unrelated
working changes, and no active verification. Return actual conflicts to the
integrator; the coordinator does not resolve business conflicts itself.

Record publication as in progress, then fast-forward canonical Git to the exact
candidate. If candidate equals base, retain that commit without an empty merge.
Apply required inputs through supported startup/rule/configuration transitions.
After publication, acknowledge each handoff still `handoff_ready` through its
returned `commands.report_worker`, supplying the original handoff ID and the
exact published candidate through `--delivery-commit COMMIT` or
`BACKEND_REWRITE_DELIVERY_COMMIT`. For a merged batch, use that same published
commit with each handoff's original worker handle and unique handoff ID.

Admission checks original identities, dispatch-base ancestry, committed managed
code and exact published HEAD. It does not scan source, enforce line limits,
require spawn evidence or run repository commands. This admission is not a
quality or API-correctness receipt. Refresh status and execute the returned
ordinary Replay acceptance action. Preserve already integrated handoffs; after
an interruption report only the remaining ready ones.

## Admit The Final Pre-Revalidation Candidate

Only `pre_revalidation_review_required` requests the complete review. Use a
separate `pre_revalidation_review` assignment in the retained worktree; this is
not an ordinary integration task. Pass `details.quality_check`,
`details.quality_paths`, current canonical base, and the exact `commands.check`.
Follow [final review](code-integrator.md#final-pre-revalidation-review).

This final stage owns complete file-size enforcement and responsibility splits,
spawn-ownership evidence, Source/Replay isolation, formatting and configured
quality checks/tests. Fix structural findings together on the final candidate.
If review changes code, commit those changes, rerun affected checks and review
that version. Then publish the exact passing commit and invoke `review accept
--report /absolute/final-report.json`. The engine never runs repository tools.

Admission binds the final code, build inputs, review/verification policy,
inventory and recording. It opens a complete fresh revalidation of the resulting
candidate, even when review corrections were intended to preserve behavior.
Earlier per-API successes are not final proof for refactored code. An ordinary
delivery receipt cannot replace final review. Relevant later changes require
fresh final proof; progress-only publication can reuse an admitted matching
receipt. A request to stop at ordinary API `completed` does not authorize this
stage or its final sweep.

## Resume Publication

Restore the original assignment and actual canonical state. Already published
matching candidates are not merged again. Complete missing input/report steps
before acceptance. For an ordinary integration, compare canonical HEAD with the
returned candidate and supply that exact `delivery_commit`; do not run a check to
repair a publication mismatch. If canonical moved elsewhere, preserve work and
reconcile with the integrator. For final review, retain the passing report and
publish its exact checked candidate before `review accept`. Never reset code,
relabel a stale handoff, or fabricate a recovery command.
