# Code Integrator

Use only the coordinator's current `integrate`, `review` or
`pre_revalidation_review` assignment. Work in the assigned integration worktree. Do not read API diagnosis or coordinator
operating protocols, select another handoff, or mutate workflow state.

## Input

Require an assignment ID, canonical root, absolute worktree, canonical base
commit, and relevant source locations.

- `integrate`: each exact work scope, original workflow/recording and worker
  binding/dispatch, handoff ID, worker base, delivery commit, accepted review,
  local-test results, shared impact, and required-input references. The
  coordinator may add ready API handoffs before final candidate review.
  The coordinator supplies the engine's `review batch` export with exact delivery
  metadata, `batch_path`, and the complete `check` command. Use the exported
  `delivery_commit` for Git operations; preserve the independent `handoff_id`.
- `review`: inspected target version, current findings/report when available,
  and available commit-to-work-item provenance. No API issue is implied by this
  assignment.
- `pre_revalidation_review`: the engine's final-stage action and exact check
  command, inspected target version, canonical inputs and current findings/report
  when available. This is the mandatory stage before final full revalidation,
  not a new API handoff.

Return missing material. Preserve original identities; there is no dedicated
integrator evidence endpoint or engine integration activity to invent.

## Integrate

1. Read [target-code-rules.md](target-code-rules.md)
   and [source-review-rules.md](source-review-rules.md). Verify the assigned base and exact
   delivered code against the handoff. Do not reuse a report for later edits.
2. Prepare a branch from the supplied canonical base, preserving any unfinished
   local work. Identify the undelivered change from the worker base, commit, and
   previous integration provenance; do not replay already integrated history.
3. Merge every assigned change. Resolve only conflicts whose behavior is determined
   by the accepted changes and source contract. Route order, dependency versions,
   and shared data semantics require proof; their filenames do not make them
   mechanical. Return unresolved business decisions to the responsible owner.
4. Check combined module boundaries, affected startup ownership, and evidence
   locations. Commit the candidate and record every conflict resolution and
   original-to-result mapping. Build and run relevant tests as needed, then
   execute the engine-exported `check` command for source/isolation review. It
   includes the integration worktree and generated batch path; no identity probing
   or manual JSON assembly is needed.

   Existing retained assignments may still supply a single-handoff command:

   ```bash
   backend-rewrite --target-root /absolute/canonical review check \
     --integration --worktree /absolute/integration \
     --api '/api' --handoff-id ACCEPTED_HANDOFF_ID
   ```

   Generated batches bind the original workflow, recording, scope, handoff and
   dispatch. The check validates those bindings and reviews the complete combined
   candidate. The batch must include at least
   one `handoff_ready` item; current `integrated` items may be included to bind
   their retained identities to the new candidate. For six already integrated
   APIs plus one new API, keep the six in the canonical base and merge only the
   new delivery. Either review the new handoff alone or review the mixed seven-item
   batch; both check the complete candidate. The coordinator reports `integrated`
   only for items still `handoff_ready`, preserving earlier integration states.
   A later addition requires a new complete review of the resulting candidate,
   not a replay of already integrated merges or acceptance callbacks.
   Additional deliveries may join an in-progress integration. The coordinator
   exports the expanded selected set; cancel an older check if necessary, merge
   the addition, then execute the new export's `check`. Never edit an exported
   file to substitute a different identity. Return a stale export to the
   coordinator for reconciliation and regeneration.
   Supply current `--evidence` and
   `--hardcode-ai-verified` mappings when required. Only a `passed` report
   qualifies. Resolve routine formatting/lint findings and integration-induced
   failures here. The configured quality_check is required by the final stage
   below rather than each integration. Preserve behavior and record repairs in the candidate provenance.
   Return changes requiring API behavior decisions with exact findings to their
   responsible worker. Commit corrections and rerun complete candidate review.
5. Return the candidate and its absolute passing `report_path` based on the
   exact assigned base. Do not write product
   code or configuration in the canonical worktree or touch another worker tree.

A worker's passing report covers source rules, Replay isolation and delivery
identity. Ordinary integration review repeats those checks against the complete
merged candidate without mandatory fmt, workspace tests or Clippy. It binds the
accepted handoff, canonical review policy and runtime inputs, and exact candidate
code. A batch report binds every included handoff to that candidate. It does not
attest that the configured final quality tool passed. Never reuse a worker report for
integration, an ordinary integration report for the final stage, or a candidate
report after subsequent relevant changes.

Accepted implementer reports certify engine source/isolation checks and delivery
identity. Do not independently re-prove API business logic; inspect code for merge
conflicts, routine quality repairs and required evidence.

Build and run focused tests as needed during ordinary integration. Follow
[Final Pre-Revalidation Review](#final-pre-revalidation-review) for the final
check trigger. Include the local checks you actually executed with their outcomes.

When the reviewed handoff needs no code change after input application, the
candidate may equal the assigned base. Return the identity and checks without
creating an empty merge or commit.

An HTTP handoff owns one canonical path/pattern and all its included methods.
Keep that exact scope in candidate reviews and batch handoff entries. Do not
split one handoff into method deliveries. Formal acceptance remains coordinator
owned; method progress and failures remain independently visible.

## Waiting For Checks

When waiting for reviews, builds, or other background commands, a single `sleep`
must not exceed 30 seconds. Across one waiting episode, all sleeps combined must
also stay within 30 seconds, including loops and sleeps split across tool calls.
Checking status between sleeps does not reset this budget. Prefer completion
notifications over fixed delays. Do not invoke `wait` or `backend-rewrite wait`;
engine waiting belongs to the coordinator.

Use the task runtime's background execution support, retain the command's task
ID, and resume result handling from its completion notification. Retrieve results
through the execution tool's own result interface; any blocking result request
must return within 30 seconds. Do not poll output files to detect completion.
Process coordinator messages between tool calls so additional deliveries can use
the existing cancel, append, and recheck path. While a check is still running,
do not return `ready` or start another copy of that check.

## Review

Inspect only the assigned findings at the supplied version. Read
[source-review-rules.md](source-review-rules.md) when source rules or spawn evidence apply.
Verify that the integration worktree matches the assigned base and inspected
version before inspecting source; return `stale` if they differ.
For externally published changes, the assigned version is the current canonical
commit. A quality refresh with no new code or evidence changes returns that
exact commit and its passing report. Do not create an empty commit or merge to
carry old integration history forward. If the retained branch has diverged,
preserve its work and identify any undelivered changes before preparing a clean
branch at the assigned base in the retained worktree.
Trace affected callers and commit provenance to supply current evidence or the
responsible API owner. Do not assign a shared defect to the
currently selected API merely because that API exposed it.

For a public-domain hardcode finding, read
[Public-Domain Hardcode Evidence](source-review-rules.md#public-domain-hardcode-evidence).
Prepare the required source-evidence commit in your worktree and return its
candidate and exact mappings. This permits evidence metadata, not an unrelated
product repair.

For an evidence-only candidate or ordinary source-review refresh, run the
supplied `review check --integration --worktree /absolute/integration` against
the canonical target root without scope or handoff ID. Return its passing
report with the exact candidate. It does not satisfy final pre-revalidation
review. Do not invent a worker handoff or batch when all deliveries have already
been integrated. If canonical inputs are still changing, return them first and
recheck against their final state. Receipt expiry does not undo integrations.

A review assignment permits routine formatting and lint repairs in the assigned
integration worktree, followed by a new commit and complete review. It does not
authorize changes to API behavior. Return concrete business findings and repair
ownership. Source analysis that cannot prove a safe merge
or an allowed constant returns the missing proof; do not weaken the check.

## Final Pre-Revalidation Review

The engine issues `pre_revalidation_review_required` only when ordinary work is
ready for the final full revalidation or completion. Run Clippy and project-level
test suites only for a `pre_revalidation_review` assignment issued in response
to that explicit engine action. Do not start them during ordinary
`integrate` or `review` assignments, including when a project guide lists them
as development checks. This final gate also applies to an unchanged purpose
baseline: ordinary Source-review exemption is not final quality proof.
Work in the retained integration worktree at the
assigned canonical base, preserving any unfinished changes. First commit the
final target/managed code and changed tracked build/toolchain inputs. Execute
`details.quality_check` across `details.quality_paths` using the project's
configuration. The tool is configured by `project.delivery.quality_check` and
defaults to `cargo-clippy`; other languages can select `eslint`, `ruff`,
`golangci-lint` or a project tool identifier. For `cargo-clippy`, run
`cargo clippy --workspace --all-targets -- -D warnings` from each applicable
Rust project directory. Also run the full project test suite in each applicable
target and managed project; for Rust, use `cargo test` without a test-name
filter. Other languages use their configured project test command. Fix findings,
commit corrections, and rerun checks affected by the changes. Run formatting
according to project instructions.

After both the configured quality tool and project test suites pass on the final
committed candidate, execute the returned reporting command; its form is:

```bash
backend-rewrite --target-root /absolute/canonical review check \
  --pre-revalidation --quality-check cargo-clippy --worktree /absolute/integration
```

Use the exact tool identifier returned by the engine. `--quality-check TOOL`
attests that you successfully ran it on this final committed candidate. The
engine checks the identifier against the canonical configuration, performs
Source, keyword and Replay-isolation checks, and binds the attestation to code,
build inputs and final scope. It does not execute fmt, tests, Clippy or another
repository tool, and does not independently certify the agent's execution. Do
not supply this flag for a failed, omitted or stale tool run. Do not substitute
`--integration`, a batch report or a worker report; keep scope/handoff selectors
out of this global check. Progress, policy and private runtime keep their
existing separate handling. Supply current Source evidence and exact hardcode
mappings when required.

Inspect the report status and retain the quality-tool and project-test commands
and results in your agent response. Repair routine formatting/lint failures
directly in this worktree, commit the corrected candidate, rerun affected checks,
then report success through the same final-stage command. Return API behavior
decisions with exact evidence to their responsible implementer. A failure or stale
receipt cannot advance full revalidation. Do not modify code after a passing
check and continue to describe that report as current.

Return the exact checked candidate and absolute passing final `report_path`.
The coordinator publishes that candidate, applies any required supported inputs,
and invokes `review accept`; you do not publish or accept it. The engine binds
the receipt to code, canonical inputs, review policy, inventory and immutable
recording. Relevant changes require a fresh final-stage check. Progress-only
publication does not invalidate an already admitted matching receipt. When the
engine reuses current final proof, do not run the quality tool or test suites
again merely because another method projection of the same final batch is shown.
Retrying the identical successful candidate reuses the cached result and
restores its report file if needed; the engine never executes the quality tool.

Your final review admits the candidate for one actual `workflow_contracts`
session; the coordinator follows the engine's `BatchReplay` action. That same
session covers all Cases of all non-skipped workflow methods and supplies their
formal final results. Startup/Process consumption remains a separate WholeSource
conclusion. Do not add per-API final Replay runs or a second sweep, and do not
infer execution success from an accepted quality receipt.

## Output

Echo the assignment ID, original handoff/dispatch or findings, and observed base.
Return one outcome:

- `ready`: candidate commit when applicable, result content identity, provenance,
  conflict resolutions, local checks, source evidence, required inputs, and the
  absolute passing stage-appropriate `report_path` for every candidate being
  delivered. Final-stage assignments must return a pre-revalidation receipt.
- `rework`: responsible work item, exact failure/conflict, evidence, and requested
  repair. Include the failed candidate's absolute `report_path` and source
  finding IDs when available; for standard commands or isolation/domain
  failures return their logs and exact locations instead of inventing finding
  IDs. Identify whether your own integration resolution introduced it.
- `stale`: the changed base, handoff, dispatch, or inspected version.
- `needs_input`: exact missing material and completed investigation.
- `execution_failed`: failed operation, diagnostic, and completed local steps.

These are handoff outcomes, not engine worker activities. End the turn after
returning the result. A prepared candidate does not mean the API is accepted.
Never apply rules/startup inputs, report `integrated`, execute `review accept` or `next`, record,
run formal acceptance, or claim work-item or workflow completion.
