# Coordinator Review Actions

Use for handoff admission, `source_review_required`, or a returned quality
finding. Consume reports and version-bound agent results; delegate source
inspection instead of proving semantics yourself.

## Admit A Worker Handoff

Check that the worker's identity, exact commit, report, and required evidence
are present and match the retained assignment. Report `handoff_ready` with
`--review-report` or `BACKEND_REWRITE_WORKER_REVIEW_REPORT`. The engine rejects
missing, failing, wrong-dispatch, and stale reports.

An ended worker with incomplete unaccepted delivery is `idle`; resume the same
binding for missing material. Use `rework_required` only after an accepted
handoff. Admission does not replace integration or formal acceptance.

## Execute Integrated Review

On `source_review_required`, execute `commands.show`. If it reports that the
report is absent or stale, execute `commands.check` and consume that result.
Read `status`, findings, and the current target fingerprint. Integrated review
covers the whole branch against `pr_base`
and remains required before acceptance and final delivery.

For missing semantic evidence or unknown ownership, delegate a `review` task
through [coordinator-integration.md](coordinator-integration.md). Supply the exact
report/findings and inspected target version. Submit returned current evidence
by extending the engine-issued check with `--evidence`; never re-label evidence
from another version. Spawn review does not require a human approval or a
hardcode source-evidence trailer.

For `changes_required`, use the returned responsible work item and execute
`commands.rework` with `BACKEND_REWRITE_REVIEW_FINDING` and
`BACKEND_REWRITE_REVIEW_OWNER` (`api:METHOD /path` or `process-output:ID`).
Do not invent an integrator owner value or route to whichever API is selected.
Preserve integrator-authored provenance in feedback to the responsible worker;
use the existing work-item repair path for code changes.

After routing, consume the returned dispatch/resume action. Findings on one
work item and target revision may join its existing repair. Retain findings
with their observed fingerprint if a later integration makes the current review
report stale; require the assignee to check its actual worktree before repair.

Review waiting uses `wait_required` with `source_review_rework`, not an execution
failure. Handle worker feedback and integration while repairs run; do not rerun
unchanged checks or supersede the worker repeatedly. Return to global status
after each action.
