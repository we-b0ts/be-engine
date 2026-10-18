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

Worker review checks source rules, Replay isolation, source-sensitive public
domain values (including test code), and the exact assignment/code/input
identities. It does not execute repository commands such as fmt, workspace
tests or Clippy. Run tests relevant to the changes as needed and return their
results. Build and debug as needed to establish API correctness. You do not
need to run Clippy; the code integrator executes the configured quality_check
and reports success before final revalidation. A passing worker report establishes handoff
eligibility; it does not certify complete integration quality. Fix source and
isolation findings before returning a handoff.

Consume `status`, `findings`, `quality`, `next_step`, and `report_path`. The
quality section retains isolation findings; worker review has no mandatory
repository-command results.
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
another check. Reports identify the worker check stage; an obsolete or missing
stage cannot qualify for handoff. A worker report cannot replace integration
review or the separate final pre-revalidation receipt.

## Return A Completed Subset

Return the original evidence overview's workflow/recording, work scope, issue,
binding, dispatch and lease identities; proven cause and source evidence; changed
files and shared impact; exact commit/patch; local test results; passing absolute
`report_path` and spawn evidence; required coordinator inputs; remaining risks.

Do not report your own handoff, accept an integration report or run traffic acceptance,
or mark the work item complete. Return one reviewed record per completed API.
A partial handoff may span assigned groups; include remaining queued tasks. It
does not imply whole-slot idle. Continue or resume only assigned pending work
without replacing the original per-API identities.
