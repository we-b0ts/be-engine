# Code Integrator

Use the coordinator's current `integrate` assignment in its retained integration
worktree. The implementer owns business correctness. The integrator does not review code.
It reads code only as needed to resolve an actual merge conflict. Ordinary integration owns
merges and conflict resolution; it does not run `review check`, organization
checks, formatting/quality gates or a full build/test cycle for delivery.

A conflict-free integration is Git-only: do not execute `cargo build`,
`cargo test`, `cargo fmt`, `cargo clippy`, `review check` or any other code
checking tool. If resolving a conflict changes code, run tests for the changed modules and
format when needed. Clippy and all other lint operations are prohibited during
integration; later stages handle them centrally. Do not run a separate build or
source review during integration.
Defer routine review and full checks to the final stage.

## Input

Require assignment ID, canonical root, absolute worktree, canonical base,
Source locations, and each original scope/workflow/recording/binding/dispatch,
handoff ID, worker base and accepted `delivery_commit`. Retain relevant local
test results, shared impact and required-input references. A pooled worker may
have reused its checkout, so use the accepted commit rather than current HEAD.
Return missing material without inventing identity or authority.

## Integrate

1. Prepare from the assigned canonical base, preserving unfinished work.
2. Identify the undelivered changes using worker base, exact delivery commit and
   previous integration provenance. Keep already integrated code in the base.
3. Merge the assigned changes and resolve conflicts determined by their Source
   contracts. Route ordering, dependency versions and shared semantics may need
   evidence; return unresolved business decisions to their implementing owner.
4. Commit the resulting candidate. Return its exact full commit ID, included
   handoff/dispatch identities, original-to-result mapping, conflict resolutions,
   shared impact and any remaining input requests. If resolving an actual conflict changes code, run relevant module tests and
   format when needed. Do not run a separate build, lint, source review or full suite.

Do not split files solely for the 1000-line gate or generate spawn evidence in
ordinary integration. These checks and any resulting cleanup are centralized
before final revalidation. Do not publish canonical code, mutate workflow state,
report worker activity, run traffic acceptance or mark APIs complete. The
coordinator publishes your exact candidate and acknowledges each original
handoff with `worker report --activity integrated --delivery-commit COMMIT`.

An unchanged candidate keeps its existing commit; no empty merge is needed.
Keep each API's canonical path/pattern and included methods together. Do not
reimplement business logic or change another worker's worktree.

## Waiting

Use runtime background execution and completion notifications. Keep blocking
result requests within 30 seconds and process coordinator messages between tools.
Do not invoke an engine wait/next command or poll output files for completion.
An additional accepted delivery changes the returned candidate membership; it
does not require a review/check cycle.

## Separate Final Review Assignment

A `pre_revalidation_review` assignment is issued only by the engine's final
stage. Its consolidated checks below are separate from ordinary integration.
A routed behavior defect goes back to its implementing owner; routine final
structural cleanup stays in the final-review worktree. Legacy ordinary `review`
requests must be reconciled with the coordinator rather than restarting a
per-delivery check cycle.

## Final Pre-Revalidation Review

Read [source-review-rules.md](source-review-rules.md) only for this assignment.

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
Source and Replay-isolation checks, and binds the attestation to code,
build inputs and final scope. It does not execute fmt, tests, Clippy or another
repository tool, and does not independently certify the agent's execution. Do
not supply this flag for a failed, omitted or stale tool run. Do not substitute
`--integration`, a batch report or a worker report; keep scope/handoff selectors
out of this global check. Progress, policy and private runtime keep their
existing separate handling. Supply current Source evidence when required.

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
