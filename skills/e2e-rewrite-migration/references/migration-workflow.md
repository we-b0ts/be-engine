# Migration Workflow

Use this reference as the stage router for one behavior-preserving rewrite unit.
Load the linked contracts only when their stage or condition applies.

## 1. Discover

Inspect source route registrations or job wiring, relevant behavior and tests,
target conventions and startup, the supplied recording layout, and current Git
state. Treat the source implementation as behavior evidence, not text to copy.

Read the target-language reference, such as [rust.md](rust.md), only for the
selected language. Read [target-runtime.md](target-runtime.md) before changing
startup, dependency wiring, configuration, commands, logging, or `AGENTS.md`.

## 2. Prepare One Canonical Group

Use `recorded-e2e-cases` as the sole authority for case discovery, source-route
association, grouping, replay, assertions, dependency coverage, recorder
feedback, and its completion gate.

For a collection or multi-API source, select one unprocessed directory and use
its first published case only to discover a candidate route. Confirm whether it
is static or dynamic, then call `traffic-e2e-run prepare`; a dynamic route
requires its safe whole-segment pattern. Complete that grouping before business
implementation analysis. If the user did not name an API, start with one
complete low-risk GET group.

Keep recordings external and immutable. Never copy, move, rename, edit, or
silently default to a developer-machine recording path.

## 3. Establish Delivery State

Read [delivery.md](delivery.md). Resolve the integration branch from user or
target-repository evidence, protect existing work, and create a focused feature
branch when safe. Do not assume a universal base branch or automatically stash
and switch a dirty worktree.

`traffic-e2e-run` creates current pointers and generated evidence according to
[e2e-run-state.md](e2e-run-state.md). AI never writes or repairs those files
itself.

Before creating those files, require `.migration/local/` in the target root
`.gitignore` and verify a representative local path with `git check-ignore`.
Keep current pointers, state, reports, logs, and temporary runtime data under
that local root; never stage or commit them.

## 4. Implement The Selected Behavior

Read [implementation-quality.md](implementation-quality.md). Inspect only the
selected source capability and implement the smallest idiomatic target behavior
that preserves its contract.

Use the same genuine dependency interfaces, production adapters, and protocol
clients in normal runtime and recorded E2E. The target project MUST NOT read
`dependencies.jsonl` or dependency fixtures to produce dependency results, and
MUST NOT read `expected-response.json` outside final assertions. Recorder-owned
replay is the only consumer that supplies recorded dependency behavior.

Maintain normal startup separately from replay orchestration. Add only focused
local tests needed by the selected scope. Provide the standard
`scripts/<project>-cli` facade from
[target-runtime.md](target-runtime.md), delegating to existing native commands.

## 5. Focused Replay And Iterate

Run the complete selected API through `traffic-e2e-run run-api`. Fix product
code only after grouping, replay lifecycle, dependency routing, and evidence
are complete enough to prove a behavior defect. Focused attempts do not change
full-round progress, streaks, or verified excludes.

Continue while each cycle provides new evidence or fixes a distinct evidenced
defect. If the same root cause repeats for three consecutive cycles without new
evidence or meaningful progress, stop the group as `blocked` or `incomplete`.
Always rerun the focused API after the last behavior, policy, assertion, wiring,
or structural change; final verification is not a retry.

## 6. Full Regression Round

After every published case is prepared exactly once and every migrated API has
a current focused pass, call `traffic-e2e-run run`. Do not edit target behavior
during the command. The runner executes the full case set, finalizes and
aggregates, runs per-API verified-excludes ensure, updates full-round streaks
and `e2e-progress.yaml`, and atomically publishes global `latest`. Repeat
unchanged successful full rounds until progress reaches `status: complete`.

If the full round fails, return to focused `run-api` for the affected API. After
the fix, restart the full round from the beginning; earlier passing cases from
the failed round cannot contribute to consecutive success.

## 7. Converge And Verify

After the group first passes, perform the structural convergence and semantics
review in [implementation-quality.md](implementation-quality.md), then rerun the
entire selected case set. Run normal-startup smoke and the target repository's
required quality checks. Read [logging.md](logging.md) only when runnable-service
diagnostics are missing or changed by the migration.

Update factual `AGENTS.md` map entries made inaccurate or materially incomplete
by the current change. Do not change repository policy or completion gates
without explicit user authorization.

After convergence or any other behavior-affecting change, rerun the affected
focused API and then a new full round.

## 8. Deliver

After producing useful focused changes and running the applicable target checks,
follow [delivery.md](delivery.md) to create a focused commit, push the feature
branch, and open and verify the PR to the resolved integration branch. Do this
even when recorded E2E leaves the migration `incomplete` or `blocked`.

An unavailable canonical artifact, unresolved semantics gap, or unverified
final change still keeps the migration `incomplete` or `blocked`; the PR records
that state and does not manufacture completion evidence.
