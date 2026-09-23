# API Implementer Review And Handoff

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
traffic verification is active. Review uses the canonical project's complete PR
diff and checks ancestry against the frozen dispatch base. It covers committed,
staged, unstaged, and untracked changes. Do not narrow the diff to a moving HEAD.
For a nested target, this includes every canonical `delivery.managed_paths`
directory in the same Git worktree. Findings for siblings use target-relative
paths such as `../backend-rs/src/lib.rs`; use those exact paths in review
evidence. Tracked candidate changes outside the target and managed paths are
rejected rather than silently omitted.

The command runs the same complete quality implementation for worker and
integration deliveries: source rules, Replay isolation, source-sensitive public
domain checks (including tests), and every configured repository gate such as
fmt, test, and clippy. It reads the canonical project's gate configuration and
executes those exact commands in the assigned worktree. A locally modified
project configuration cannot waive a required gate. Failures stay with the
delivery: fix them before returning a handoff.

Consume `status`, `findings`, `quality`, `next_step`, and `report_path`. The
quality section retains isolation findings and each command's result/log path.
Exit code zero only
means the command executed. For `changes_required`, fix the code. For
`evidence_required`, inspect source using the evidence contract and extend the
returned check with `--evidence /absolute/path/evidence.json`. Rerun after the
final edit and commit; only a current `passed` report qualifies for handoff.
For `demo.test` or `sample.test` findings, follow
[Public-Domain Hardcode Evidence](source-review-rules.md#public-domain-hardcode-evidence)
and supply one exact `--hardcode-ai-verified` mapping per proven occurrence.
Public-domain exceptions never waive private Replay markers.

The bundled organization script may be an earlier local check; it does not
replace this report. Reports bind the code, canonical configuration, runtime
inputs, and rules. Any later edit, commit, or relevant input change requires
another check. A source-only legacy report cannot qualify as full quality proof.

## Return And Stop

Return the original evidence overview's workflow/recording, work scope, issue,
binding, and dispatch identities; proven cause and source evidence; changed
files and shared impact; exact commit/patch; local test results; passing absolute
`report_path` and spawn evidence; required coordinator inputs; remaining risks.

Do not report your own handoff, accept an integration report or run traffic acceptance,
or mark the work item complete. End the turn and retain your assignment.
