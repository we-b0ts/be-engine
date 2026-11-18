# Coordinator Final Review Actions

A non-pre-revalidation `review check` returns `passed` with an explicit
no-check-needed message and performs no source or repository checks. It is not
a workflow requirement. Ordinary worker handoff and integration require exact committed deliveries,
not a `review check` report. Submit pooled worker deliveries with
`delivery_commit`; after publishing the integrator's candidate, acknowledge its
original handoffs with `worker report --activity integrated --delivery-commit
COMMIT`. Follow [integration](coordinator-integration.md). The engine captures
identity receipts during admission without running source or repository checks.

## Final Review Before Full Revalidation

Only `pre_revalidation_review_required` requests review. Delegate its exact
`details.quality_check`, `details.quality_paths` and `commands.check` in a separate
final-review assignment at the current canonical base. Perform complete-file
line limits and required splits, asynchronous ownership evidence, Source/Replay
isolation, formatting and required quality/tests on the final committed code.
After successful checks, run `review check --pre-revalidation --quality-check
TOOL --worktree ...`. The engine checks source and binds the tool attestation;
it never executes repository commands itself.

Review fixes can change the candidate. Commit them and refresh affected checks
and source review before publishing that exact passing version and invoking
`review accept --report ...`. Then start a complete final revalidation of that
version. Earlier ordinary Replay results cannot substitute for that sweep.
A request to stop at ordinary API `completed` leaves this stage pending.

## Findings And Rework

Inspect final findings and exact source locations. Keep line-limit splitting,
formatting and other routine cleanup in the final-review worktree. Resolve
spawn evidence with the actual startup/request trigger and task lifecycle; do
not relabel evidence from another version. Follow
[source-review-rules.md](source-review-rules.md).

For behavior decisions, route a real finding with `review rework --report
/absolute/failed-candidate-report.json --finding ID --owner 'api:/path'`, or the
current canonical report's returned command. Standard quality/isolation errors
without a source finding ID can use the accepted handoff's `rework_required`
path with precise logs/locations. Never invent an integrator owner or finding.

Retain source/commit provenance. The responsible worker returns a committed
repair without `review check`; ordinary integration merges it without a check.
Resume the consolidated final review afterwards. An unchanged wait is not a
reason to rerun checks or supersede a live worker. Only a passing exact final
receipt can open the full revalidation sweep. Preserve the receipt across
progress-only publication; code or relevant input changes require fresh proof.
