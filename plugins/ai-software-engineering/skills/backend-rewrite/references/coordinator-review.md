# Coordinator Review Actions

Use for handoff admission, `source_review_required`, or a returned quality
finding. Consume reports and version-bound agent results; delegate source
inspection instead of proving semantics yourself.

## Admit A Worker Handoff

Check that the worker's identity, exact commit, report, and required evidence
are present and match the retained assignment. Report `handoff_ready` with
`--review-report` or `BACKEND_REWRITE_WORKER_REVIEW_REPORT`. The engine rejects
missing, failing, wrong-dispatch, and stale reports. A passing report must cover
the full shared quality suite, including Replay isolation and configured
repository gates; a source-only report is insufficient.

An ended worker with incomplete unaccepted delivery is `idle`; resume the same
binding for missing material. Use `rework_required` only after an accepted
handoff. Admission does not replace integration or formal acceptance.

## Delegate Candidate Review And Admit The Report

Purpose confirmation establishes the committed `pr_base` snapshot as trusted.
Start its recording/Replay directly; an unchanged baseline needs no source review
at startup or final completion. Ignore historical receipts as a reason to create
an integrator assignment. Progress-only commits do not change this exemption.
Source/configuration changes relative to the purpose baseline restore normal
review admission before verification and delivery, including external edits.
Worker handoff and outstanding finding admission still require their reports.

On `source_review_required`, execute `commands.show` when a current report is
available. Delegate missing/stale quality proof or findings to the retained
code integrator through [coordinator-integration.md](coordinator-integration.md).
Supply `commands.check` as an integrator-local command with its actual assigned
worktree; never execute checks in the canonical coordinator worktree.
Candidate review covers the whole branch against `pr_base` and runs the same
complete quality implementation as worker review.
Changes already published on the canonical branch still need a current receipt;
use that exact version for a global quality refresh without manufacturing a
worker handoff. Follow the integration protocol to synchronize a retained
worktree after external changes.

The integrator returns a passing report for its exact candidate. Publish only
that candidate after checking assignment, base and configuration freshness.
For an accepted work-item handoff, use `worker report --activity integrated
--review-report /absolute/report.json` with the original handoff and dispatch.
For global evidence work or final quality refresh, execute the returned accept
command with `BACKEND_REWRITE_REVIEW_REPORT`, or `review accept --report
/absolute/report.json`. The engine verifies published code and frozen quality
inputs without executing the checks again. Missing, failing or stale reports
return to the integrator; they cannot make Replay or final delivery eligible.

Admission requires the exact reviewed commit. Once admitted, the engine can
retain that receipt across progress-only commits when the reviewed commit is
still an ancestor and code, canonical inputs, rules and the diff base remain
unchanged, with no new `Hardcode-Source-Evidence` trailers. Follow the resulting
status; progress publication alone does not
require another integration task or quality run. This reuse applies only to an
already accepted receipt, never to a candidate awaiting admission.

A HEAD mismatch at admission is a publication/reconciliation issue. Compare the
report's reviewed commit and canonical base with the actual canonical HEAD, then
follow [Resume Publication](coordinator-integration.md#resume-publication).
Identical file content does not satisfy exact-commit admission, and rerunning
checks alone cannot complete a missing publication.

For missing semantic evidence or unknown ownership, delegate a `review` task
through [coordinator-integration.md](coordinator-integration.md). Supply the exact
report/findings and inspected target version. Have the integrator extend its
current check with `--evidence`; never re-label evidence
from another version. Spawn review does not require a human approval or a
hardcode source-evidence trailer.

For a source finding in `findings`, use the returned responsible work item and
execute `review rework --report /absolute/failed-candidate-report.json --finding
ID --owner 'api:METHOD /path'` (or `process-output:ID`). The engine validates the
unpublished candidate and its unchanged canonical base before routing; it never
publishes or accepts failing code. When using the current canonical report,
omit `--report` and use `commands.rework` with `BACKEND_REWRITE_REVIEW_FINDING`
and `BACKEND_REWRITE_REVIEW_OWNER`.
Do not invent an integrator owner value or route to whichever API is selected.
Preserve integrator-authored provenance in feedback to the responsible worker;
use the existing work-item repair path for code changes.

Configured command failures and `quality.replay_isolation.violations`, including
public-domain findings, do not necessarily have source finding IDs. For a defect
in an accepted handoff, use its existing `rework_required` worker report with
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
