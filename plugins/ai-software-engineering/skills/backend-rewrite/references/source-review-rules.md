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
managed projects without running that tool.
Source-sensitive
`demo.test` and `sample.test` values are checked in test code too. `.trp.test`
is prohibited in all added Rust lines; other private Replay hostnames, fake
addresses, private state and recording artifacts cannot enter production paths.
These checks prevent target behavior from depending on the verification
environment or its expected outputs. They do not execute traffic Replay.
Follow [Public-Domain Hardcode Evidence](#public-domain-hardcode-evidence) only
for the narrowly allowed public-domain source-proof exception. Ordinary
configured values must remain configuration; traffic samples are not source
proof.

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

## Public-Domain Hardcode Evidence

Use this exception only when API-implementer or integration review identifies a
`replay-isolation` public-domain finding. Inspect source and prepare exact
evidence in the assigned worktree, then repeat the final candidate's `review check --pre-revalidation`
with the proven mappings. Report acceptance and traffic verification remain
coordinator-owned.

All added Rust lines, including tests, reject `.trp.test`. Other Replay-private
markers remain prohibited in production paths. Only the public-domain rules for
`sample.test` and `demo.test` accept the source-proof exception below. This is
not an exemption for private Replay values.

Prove that the same value is hardcoded in source code. Traffic, recordings,
logs, runtime configuration, and container state are not source proof. Inspect
the exact source revision and target occurrence. Return the narrow source fact
and one mapping per finding.

The target occurrence must be committed at its exact position. Record one
commit trailer per occurrence in the candidate history:

```text
Hardcode-Source-Evidence: TARGET_FILE:LINE:COLUMN <= SOURCE_REPOSITORY@SOURCE_REVISION:SOURCE_FILE:LINE:COLUMN
```

`SOURCE_REVISION` is the inspected 7-64 hexadecimal commit ID. Preserve product
content while preparing a missing evidence trailer on the assigned base; keep
already committed target positions valid. `TARGET_FILE` is relative to the
target and may begin with a configured managed sibling path such as
`../backend-rs/`; use the exact path reported by the gate. Return the candidate
commit and the exact corresponding mappings:

```text
TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@SOURCE_REVISION:SOURCE_FILE:LINE:COLUMN
```

Supply each mapping through a separate `review check --hardcode-ai-verified`
argument. A changed target location requires a newly current mapping and report.

Missing, duplicate, stale, unrelated, or uncommitted positions fail the gate.
Do not relabel unknown provenance as source-proven. Return unproven occurrences
as findings for their responsible API implementer.
