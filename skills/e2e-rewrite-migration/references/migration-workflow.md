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
Read [repository-memory.md](repository-memory.md) and the resolved target
migration notes before implementation or replay.

## 2. Prepare One Canonical Group

Use `recorded-e2e-cases` as the sole authority for case discovery, source-route
association, grouping, replay, assertions, dependency coverage, recorder
feedback, and its completion gate.

If `.migration/e2e.yaml` is missing, call `traffic-e2e-run init` with the
confirmed project CLI, replay policy, and PR base before preparing a
group. Ask the user for any project-specific value when repository evidence is
insufficient; never guess, hand-write, or silently inherit another project's
paths or PR base. Every runner command must reject a missing or incomplete
config or a PR base that no longer resolves.

For a collection or multi-API source, select one unprocessed directory and use
its first published case only to discover a candidate route. Confirm whether it
is static or dynamic, then call `traffic-e2e-run prepare`; a dynamic route
requires its safe whole-segment pattern. Complete that grouping before business
implementation analysis. If the user did not name an API, start with one
complete low-risk GET group.

Keep recordings external and immutable. Never copy, move, rename, edit, or
silently default to a developer-machine recording path.

## 3. Establish Delivery State

Read [delivery.md](delivery.md). Resolve `pr_base`, protect existing work, and
create a focused feature branch when safe. Do not work on `pr_base`.

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
full-round progress or verified excludes.

Continue while each cycle provides new evidence or fixes a distinct evidenced
defect. If the same root cause repeats for three consecutive cycles without new
evidence or meaningful progress, stop the group as `blocked` or `incomplete`.
After a fixed and verified problem meets the cross-scope reuse rule, upsert the
concise migration-notes lesson from `repository-memory.md`.
Always rerun the focused API after the last behavior, policy, assertion, wiring,
or structural change; final verification is not a retry.

## 6. Full Regression Round

After every published case is prepared exactly once and every migrated API has
a current focused pass, call `traffic-e2e-run run`. Do not edit target behavior
during the command. The runner executes the full case set, finalizes and
aggregates, runs per-API verified-excludes ensure, updates
`e2e-progress.yaml`, and atomically publishes global `latest`. One successful
round with finalized, complete, clean evidence reaches `status: complete`.

If the full round fails, return to focused `run-api` for the affected API. After
the fix, restart the full round from the beginning; the failed round is not
completion evidence.

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
append the single concise changelog entry required by
[repository-memory.md](repository-memory.md), then follow
[delivery.md](delivery.md) to create a focused commit, push the feature branch,
and open and verify the PR to `pr_base`. Do this even
when recorded E2E leaves the migration `incomplete` or `blocked`.

An unavailable canonical artifact, unresolved semantics gap, or unverified
final change still keeps the migration `incomplete` or `blocked`; the PR records
that state and does not manufacture completion evidence.
