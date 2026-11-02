# API Implementer Delivery

Use before returning a completed API from the assigned worktree, including an
unchanged implementation after an input-only repair.

## Prepare The Delivery

The implementer owns Source-compatible business behavior, including dependency
calls, asynchronous task lifecycle, cancellation and cleanup. Build/debug and
run focused tests for changed modules and format when needed. Clippy and other
lint operations are prohibited here; later stages handle them centrally.

Use `context.delivery.assignment` for the registered worktree and frozen dispatch
base. Missing or mismatched assignment data is an input error; do not register
yourself or initialize another workflow. Keep target and configured
`delivery.managed_paths` changes in that same Git worktree. Commit all delivery
code and return the exact full commit ID as `delivery_commit`. An unchanged
handoff retains its existing commit; do not create an empty commit. The engine
checks the worktree, committed code, dispatch and ancestry during handoff.

A later code change is a new delivery version. Pooled admission freezes the
accepted commit and keeps it reachable independently of subsequent checkout
reuse. The integrator consumes that accepted commit, never the reusable
worktree's current HEAD. Preserve normal product behavior; target code cannot consume expected outputs
or private Replay state.

## Return A Completed Subset

Return the original workflow/recording, scope, issue, binding, dispatch and lease;
proven cause and Source evidence; changed files/shared impact; exact
`delivery_commit`; focused test results; required inputs and remaining risks.

The coordinator submits each completed API with its original identities and
`delivery_commit` through `implementer handoff`. A subset may span assigned
groups and does not imply whole-slot idle. Legacy dedicated workers return the
same commit for coordinator-owned `worker report --activity handoff_ready
--delivery-commit COMMIT`. Do not submit your own feedback, mutate workflow
state, publish canonical code, run Replay or mark the API complete.
