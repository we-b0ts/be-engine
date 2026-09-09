# Implementation Worker Review And Handoff

Use before returning an implementation handoff from the assigned worktree,
including unchanged code when a post-input resume still requires delivery.
Read [source-review-rules.md](source-review-rules.md) for rules and evidence format.

## Check The Final Delivery

Your scoped evidence supplies `context.review.assignment` and
`context.review.check`: the registered worktree, frozen dispatch base, and local
check command. Missing or mismatched assignment data is an input error; return
it instead of registering yourself or creating a local workflow.

When code changed, finish edits, run focused tests, and commit the delivery.
Otherwise retain the existing commit and report which local checks apply;
do not create an empty patch or commit. In both cases execute the
returned check with its canonical target root and assigned worker worktree.
It reads engine state and writes a local report; it may run while another API's
traffic verification is active. The frozen base covers committed, staged,
unstaged, and untracked changes. Do not narrow the diff to a moving HEAD.

Consume `status`, `findings`, `next_step`, and `report_path`. Exit code zero only
means the command executed. For `changes_required`, fix the code. For
`evidence_required`, inspect source using the evidence contract and extend the
returned check with `--evidence /absolute/path/evidence.json`. Rerun after the
final edit and commit; only a current `passed` report qualifies for handoff.

The bundled organization script may be an earlier local check; it does not
replace this report. Any later edit or commit requires another check.

## Return And Stop

Return the original evidence overview's workflow/recording, work scope, issue,
binding, and dispatch identities; proven cause and source evidence; changed
files and shared impact; exact commit/patch; local test results; passing absolute
`report_path` and spawn evidence; required coordinator inputs; remaining risks.

Do not report your own handoff, run integrated quality or traffic acceptance,
or mark the work item complete. End the turn and retain your assignment.
