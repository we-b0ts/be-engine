# Worker And Integrated Source Review

`backend-rewrite review check` owns three target source rules. Do not substitute
an untracked shell check or a prose assertion that review passed.

- Changed production Rust files must have at most 1000 complete physical lines,
  including comments, blank lines and a final line without a trailing newline.
- Explicit `serde_json::Value` and ordinary imports/aliases in the diff are
  prohibited. Use structs, enums and typed maps. `json!` is allowed: this rule
  intentionally does not ban inferred values or expand macros.
- Each added `tokio::spawn` or ordinary imported spelling requires AI review of
  the actual trigger. Initialization-owned tasks may pass with evidence.
  Request-owned tasks must be removed/restructured; unknown ownership cannot pass.

The syntax scan ignores comments, string examples and explicit `#[cfg(test)]`
modules/functions. The full-file line limit still includes their lines. It does
not prove a call graph or discover every macro/wrapper. When changing callers of
an existing task launcher, inspect its ownership even if no new spawn is found.

## Worker Delivery

The coordinator registers the assigned worktree with `worker confirm --worktree`
on dispatch and resume. The engine freezes canonical HEAD as the dispatch base.
If an older dispatch lacks the assignment, repeat its confirmation with the same
handle and the actual assigned worktree. Do not create a workflow in the worktree.

The scoped evidence response includes `context.review.assignment` and
`context.review.check`. Execute that check after the final edit and commit.
Its canonical `--target-root` selects the workflow; `--worktree` selects the
worker code. The worker check only reads coordinator state and writes a local
report. It can run while another API's traffic verification is active.

Consume `status`, `findings`, `next_step` and `report_path`. A successfully
executed review command may report `changes_required` or `evidence_required`;
only `passed` qualifies for handoff. Correct violations in the same worker turn.
Checks include committed, staged, unstaged and untracked changes from the frozen
base. Do not use a moving HEAD-only diff to omit already committed work.

For spawn findings, inspect the startup entry, call chain and all callers.
An async callback registered in main may execute on every request; its definition
location does not make its task initialization-owned. Shared launchers reachable
from requests are request-owned even if main also calls them. Even an immediately
awaited spawn is rejected when a request triggers it.

Write evidence under the ignored local directory or another temporary path:

```json
{
  "spawns": [{
    "finding_id": "<exact finding id>",
    "ownership": "startup",
    "startup_entry": {"file": "src/main.rs", "line": 20, "fact": "Calls start_workers before serving requests"},
    "call_chain": [
      {"file": "src/main.rs", "line": 20, "fact": "Startup invokes start_workers"},
      {"file": "src/jobs.rs", "line": 42, "fact": "Exact reported spawn creates the persistent queue consumer"}
    ],
    "request_path_review": "Inspected all callers; handlers enqueue bounded work and never call the launcher",
    "task_lifecycle": "Application owns one consumer, bounded admission, error reporting, cancellation and shutdown join"
  }]
}
```

Each call chain must include the exact reported spawn file and line. Every
location must exist and every factual explanation must come from inspected code.
Use `request` or `unknown` when that is the conclusion; do not relabel a finding
to obtain a passing result. The engine checks coverage, locations and freshness;
the AI is responsible for the semantic ownership judgment.

Rerun the returned check with `--evidence /absolute/path/evidence.json`. Deliver
the exact commit/patch plus the returned `report_path` and spawn explanation in
the normal handoff. A subsequent edit or commit requires another check.

## Coordinator Acceptance And Recovery

Inspect the report and its ownership evidence before reporting `handoff_ready`.
Supply `--review-report` or `BACKEND_REWRITE_WORKER_REVIEW_REPORT` with its exact
path. The engine rejects absent, failing, wrong-dispatch or stale reports before
accepting the handoff. This does not replace integration or traffic acceptance.

An ended worker with an incomplete, unaccepted delivery is reported `idle` and
resumed using its original binding. Do not report it running or use
`rework_required` before a handoff was accepted. Once a handoff is accepted,
ordinary `rework_required` retains the existing handoff protocol.

Integrated review checks the whole branch diff against the configured PR base,
including committed and working-tree code. It reuses applicable accepted spawn
evidence and runs before API acceptance, process-output acceptance and final
delivery. Its records stay in engine-owned local state, outside code fingerprints.

On `source_review_required`, use `commands.show` if a report exists; otherwise
execute `commands.check`. For `evidence_required`, inspect target code or obtain
the worker's explanation and extend `commands.check` with `--evidence`. No human
approval or source-evidence commit trailer is required for these reviews.

For `changes_required`, identify the owning work item; do not assign another API's
change to whichever API is currently selected. Execute `commands.rework` with
`BACKEND_REWRITE_REVIEW_FINDING` set to the finding id and
`BACKEND_REWRITE_REVIEW_OWNER` set to `api:METHOD /path` or `process-output:ID`.
This also reopens an already completed item's retained worker binding when a
final-delivery check exposes the issue. Follow the returned dispatch/resume and
confirmation commands. Workers read the fresh issue and `context.review`.
The assigned findings are preserved in `context.review.rework.findings` with
their observed target fingerprint, including when a behavioral issue remains
active or a later integration makes `review show` stale. Recheck those locations
against the assigned worktree before repairing them.

After routing, follow the returned action before routing more work. Dispatch,
worker status checks and handoff integration remain available; when the repair
is in progress and no such action is ready, the engine returns `wait_required`
with resource `source_review_rework`. Execute its `commands.wait`, reconcile
worker events, and integrate the corrected handoff. Do not rerun an unchanged
review or repeatedly supersede the worker. Additional findings routed to the
same work item on the same target revision join its current repair dispatch.

Review waiting is a normal workflow action, not `execution_failed` or a traffic
failure. Do not hot-loop the unchanged check. Return to global `status` after
every review, handoff or integration action; other workers may continue.
