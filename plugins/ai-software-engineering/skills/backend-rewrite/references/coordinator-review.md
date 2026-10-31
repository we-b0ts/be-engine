# Coordinator Review Actions

Use for handoff admission, `source_review_required`,
`pre_revalidation_review_required`, or a returned quality finding. Consume
reports and version-bound agent results; delegate source inspection instead of
proving semantics yourself.

## Admit A Worker Handoff

Check that the worker's identity, exact commit, report, and required evidence
are present and match the retained assignment. Report `handoff_ready` with
`--review-report` or `BACKEND_REWRITE_WORKER_REVIEW_REPORT`. The engine rejects
missing, failing, wrong-dispatch, and stale reports. A passing worker report must
cover Source rules, Replay isolation and current delivery identity. It does not
execute repository quality commands or certify full integration quality. Workers
build/debug and run relevant tests as needed and do not need Clippy. The
integrator executes the configured quality tool before final revalidation.

An ended worker with incomplete unaccepted delivery is `idle`; resume the same
binding for missing material. Use `rework_required` only after an accepted
handoff. Admission does not replace integration or formal acceptance.

## Final Review Before Full Revalidation

On the existing `pre_revalidation_review_required` stage, delegate
`details.quality_check`, `details.quality_paths` and the returned `commands.check`
to the retained integrator in its assigned worktree. The integrator executes
the configured tool on the final committed candidate and fixes findings. Only
after success does it run `review check --pre-revalidation --quality-check TOOL
--worktree ...` to report the successful check and obtain the Source/isolation
receipt. The engine does not execute repository commands. Return the exact
checked candidate and passing receipt for coordinator admission.

Publish the exact passing candidate and invoke `review accept --report
/absolute/final-report.json` through the
[final publication protocol](coordinator-integration.md#admit-the-final-pre-revalidation-candidate).
The state machine validates code, relevant inputs, policy, inventory and adopted
recording before it permits full revalidation. Ordinary worker or integration
reports, failing reports and stale receipts cannot open the gate. Relevant
changes require fresh final proof; progress-only publication can reuse an
already admitted matching receipt. Check acceptance never repeats the suite.

After admission, formal final revalidation is one actual complete batch session.
Its method results come from that session; do not schedule separate final
per-API runs followed by another sweep. The sealed Source run must cover its
complete inventory and every required workflow method. Final review and committed
progress do not certify missing traffic or create a batch receipt.

## Delegate Candidate Review And Admit The Report

Purpose confirmation establishes the committed `pr_base` snapshot as trusted.
Adopt completed external recordings and run Replay; an unchanged baseline needs no source review
at startup. Ignore historical ordinary review receipts as a reason to create an
assignment. Progress-only commits do not change this Source-review exemption;
it does not substitute for the final pre-revalidation gate.
Source/configuration changes relative to the purpose baseline restore normal
review admission before verification and delivery, including external edits.
Worker handoff and outstanding finding admission still require their reports.

On `source_review_required`, execute `commands.show` when a current report is
available. Delegate missing/stale quality proof or findings to the retained
code integrator through [coordinator-integration.md](coordinator-integration.md).
Supply `commands.check` as an integrator-local command with its actual assigned
worktree; never execute checks in the canonical coordinator worktree.
Ordinary engine candidate review covers the whole branch against `pr_base` and
repeats Source/Replay-isolation checks without mandatory repository commands.
Do not require a full fmt/test/Clippy suite for each integration. The separate
`pre_revalidation_review_required` action supplies the required quality tool
and reporting command and requires its distinct final-stage report. The
integrator runs the tool once for the final candidate before reporting success;
the engine command does not repeat it.
Changes already published on the canonical branch still need a current receipt;
use that exact version for a global quality refresh without manufacturing a
worker handoff. Follow the integration protocol to synchronize a retained
worktree after external changes.

The integrator returns a passing report for its exact candidate. Follow
[Publish A Ready Candidate](coordinator-integration.md#publish-a-ready-candidate)
for assignment/base/input freshness, exact-commit publication, batch handoff
reports and global report admission. The engine validates the published candidate
and frozen quality inputs without executing checks again. Missing, failing or
stale reports return to the integrator; they cannot make Replay or delivery eligible.

Admission requires the exact reviewed commit. Once admitted, the engine can
retain that receipt across progress-only commits when the reviewed commit is
still an ancestor and code, canonical inputs, rules and the diff base remain
unchanged, with no new `Hardcode-Source-Evidence` trailers. Follow the resulting
status; progress publication alone does not
require another integration task or quality run. This reuse applies only to an
already accepted receipt, never to a candidate awaiting admission.

For a HEAD mismatch or interrupted publication, follow
[Resume Publication](coordinator-integration.md#resume-publication) before retrying admission.

For missing semantic evidence or unknown ownership, delegate a `review` task
through [coordinator-integration.md](coordinator-integration.md). Supply the exact
report/findings and inspected target version. Have the integrator extend its
current check with `--evidence`; never re-label evidence
from another version. Spawn review does not require a human approval or a
hardcode source-evidence trailer.

For a source finding in `findings`, use the returned responsible work item and
execute `review rework --report /absolute/failed-candidate-report.json --finding
ID --owner 'api:/path'`. The engine validates the
unpublished candidate and its unchanged canonical base before routing; it never
publishes or accepts failing code. When using the current canonical report,
omit `--report` and use `commands.rework` with `BACKEND_REWRITE_REVIEW_FINDING`
and `BACKEND_REWRITE_REVIEW_OWNER`.
Do not invent an integrator owner value or route to whichever API is selected.
Preserve integrator-authored provenance in feedback to the responsible worker;
use the existing work-item repair path for code changes.

Routine formatting and Clippy failures stay with the integrator for repair and
a fresh final-stage check when required; they do not require a worker round trip.
Final-stage command failures and `quality.replay_isolation.violations`, including
public-domain findings, do not necessarily have source finding IDs. For a defect
requiring API behavior decisions in an accepted handoff, use its existing
`rework_required` worker report with
the original dispatch and handoff identity; return exact command logs or
file/line/domain evidence to that worker. Keep integration-induced errors with
the integrator. Without an accepted handoff, retain the failed candidate and
return the concrete ownership/input request; do not invent a source finding ID.

After routing, consume the returned dispatch/resume action. Findings on one
work item and target revision may join its existing repair. Retain findings
with their observed fingerprint if a later integration makes the current review
report stale; require the assignee to check its actual worktree before repair.

Review waiting uses `wait_required` with `source_review_rework`, not an execution
failure. Handle worker feedback and integration while repairs run; do not rerun
unchanged checks or supersede the worker repeatedly. Return to global status
after each action.
