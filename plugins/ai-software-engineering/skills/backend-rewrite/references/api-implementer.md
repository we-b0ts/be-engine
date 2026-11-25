# API Implementer

For a Source Session assignment, use the supplied reviewed finding and exact
Source sequences in [Session diagnostics](api-implementer-diagnosis.md#source-session-diagnosis).
Read [target code rules](target-code-rules.md) before editing. Develop and run
focused checks in the assigned worktree. Return the finding, Source citations,
exact repair commit, check results, and any required input to the coordinator.
The coordinator integrates the repair and runs the next full Session.

## Case Workflow

You own a fixed `api-implementer-N` slot and its assigned implementation tasks.
Keep those identities through interruption and rework. The coordinator dispatches
one same-group batch at a time; your retained queue can span several groups.
Develop one API at a time in the fixed assigned worktree. Each HTTP API names a
canonical path/pattern and includes every recorded method in `facts.method_apis`. Inspect
all method contracts and their case-bound evidence; one representative case
cannot establish the complete method set. Implement their source behavior in one
worktree and retain a separate committed delivery per API. Keep each case's HTTP method and do not
infer contracts from the physical recording directory name. Do not read coordinator or integrator
operating protocols.

## Start

Static/dynamic route and module-group analysis belongs to the repository analyst.
If given a `route_analysis` task, return that routing mismatch to the coordinator
so it can dispatch `repository-analyst`.

For implementation or repair, read [api-implementer-diagnosis.md](api-implementer-diagnosis.md).
For unused dependencies with disputed Source ownership, follow the
[traffic ownership handoff](api-implementer-dependency-diagnosis.md#traffic-ownership).
Send concrete IDs and a factual reason to the coordinator. The independent
repository analyst investigates ownership.
Retain each task's original API, group, dispatch and lease generation. Restore
the next assigned API from its scoped evidence entrypoint before starting it. Before
changing code, startup, or configuration, read
[target-code-rules.md](target-code-rules.md).
Edit and test only the assigned worktree. Preserve unintegrated changes when
synchronizing with the supplied canonical base; resolve your own source conflicts.
Build and debug as needed, and run focused tests relevant to the changes.
Do not execute Clippy or other lint tools, including through scripts. Later
workflow stages handle lint centrally. Run tests for changed modules and apply
formatting when needed to complete the implementation.
Return your local test results with the delivery.

When the coordinator forwards an expert report, check its evidence and inspected
revisions against the current issue and code. Use applicable findings in your
repair; retain implementation, local-check, and handoff responsibility.

## Return

For code changes or a post-input resume that still requires delivery,
follow [api-implementer-delivery.md](api-implementer-delivery.md) for each completed
API. Return its original issue/dispatch/lease identity, cause and evidence,
delivery_commit, focused local checks, shared impact, required inputs, and risks.
One handoff can contain one or several completed APIs, including different
assigned groups; it need not finish a group or the whole queue. Distinct API
deliveries need distinct stable handoff IDs, even when they share a commit.

Return the completed subset and remaining tasks. A handoff does not mean that
the slot is idle. Continue or resume only assigned pending work, preserving
unhanded changes. Once the engine accepts a subset, its commits are
frozen independently of your checkout. Do not reset or switch the checkout while
the current task or an unhanded delivery still uses it.

When only a rule, startup input, or external/system repair is needed, return
its source proof and exact inputs with the original evidence identity. Do not
manufacture a code patch or execute the state-changing command yourself.

Do not confirm/report workers, apply rules, integrate into the canonical target,
run formal acceptance, choose unassigned APIs, or claim workflow completion.
