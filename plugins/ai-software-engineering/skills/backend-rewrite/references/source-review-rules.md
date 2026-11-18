# Source Review Rules

Read when your assignment requires checking changed target code or supplying
source evidence. This reference defines source rules and evidence format only.
Use your role's entrypoint for report execution and handoff.

Outside pre-revalidation, `review check` returns success and explains that no
check is needed. It captures delivery identity only and performs no source scan
or repository checks.

`backend-rewrite review check --pre-revalidation` applies Source and
Replay-isolation rules to the final candidate. Implementer handoff and ordinary
integration do not call review check, enforce file-size gates, or require spawn
ownership evidence or a quality report. They submit exact committed deliveries;
the engine captures and validates identity without source scans or repository
commands. Implementers own business behavior; integrators own merges/conflicts.

Before final full revalidation, the final-review assignment consolidates file
splits, asynchronous task ownership, Source/isolation, formatting and required
quality/tests. The configured quality tool is run on the final committed code,
then reported with `review check --pre-revalidation --quality-check TOOL
--worktree ...`. The engine records that result without executing repository
tools. Commit review corrections and refresh affected checks before publishing
and admitting the exact final candidate. Full revalidation covers that version;
ordinary delivery receipts and historical API successes cannot replace it.

Final review scans the whole PR, including code inherited before worker dispatch.
`validation.scan_base_revision` is the merge base with the configured PR base;
`base_revision` identifies the delivery base and does not narrow the scan.
Keep the scan scope and supply current truthful evidence for inherited spawn
findings; still-valid integrated evidence is reused automatically. Inherited
findings do not by themselves require one API worker to rewrite another API.
For extracted test helpers, put `#![cfg(test)]` in the child file so the compiler
enforces its test-only scope. The scanner does not infer external module cfg
from a filename or parent declaration. `#[tokio::test]` functions are also
excluded; runtime siblings still require ordinary ownership evidence.

- Changed production Rust files must have at most 1000 complete physical lines,
  including comments, blank lines and a final line without a trailing newline.
- Each added `tokio::spawn` or ordinary imported spelling requires AI review of
  the actual trigger. Initialization-owned tasks may pass with evidence.
  Request-owned tasks must be removed/restructured; unknown ownership cannot pass.

The syntax scan ignores comments, string examples and explicit `#[cfg(test)]`
modules/functions. The full-file line limit still includes their lines. It does
not prove a call graph or discover every macro/wrapper. When changing callers of
an existing task launcher, inspect its ownership even if no new spawn is found.

The final review also checks Replay isolation. The final pre-revalidation
command records the integrator's successful quality check for the target and
managed projects without running that tool. The scanner rejects `.trp.test` in
all added Rust lines. It also rejects Replay fake addresses, private runtime
state and recording artifacts in production Rust paths.

## Spawn Evidence

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
For a managed sibling, copy the exact target-relative finding path
into evidence, including leading components such as `../backend-rs/`.
