# Source Review Rules

Read when your assignment requires checking changed target code or supplying
source evidence. This reference defines source rules and evidence format only.
Use your role's entrypoint for report execution and handoff.

`backend-rewrite review check` runs the complete shared delivery quality suite.
Its source review includes the following rules. Do not substitute an untracked
shell check or a prose assertion that review passed.

- Changed production Rust files must have at most 1000 complete physical lines,
  including comments, blank lines and a final line without a trailing newline.
- Each added `tokio::spawn` or ordinary imported spelling requires AI review of
  the actual trigger. Initialization-owned tasks may pass with evidence.
  Request-owned tasks must be removed/restructured; unknown ownership cannot pass.

The syntax scan ignores comments, string examples and explicit `#[cfg(test)]`
modules/functions. The full-file line limit still includes their lines. It does
not prove a call graph or discover every macro/wrapper. When changing callers of
an existing task launcher, inspect its ownership even if no new spawn is found.

The same command also checks Replay isolation and runs all canonical project
quality gates, with their exact argv, in the reviewed worktree. Source-sensitive
`demo.test` and `sample.test` values are checked in test code too. `.trp.test`
is prohibited in all added Rust lines; other private Replay hostnames, fake
addresses, private state and recording artifacts cannot enter production paths.
These checks prevent target behavior from depending on the verification
environment or its expected outputs. They do not execute traffic Replay.
Read [integrator-hardcode-evidence.md](integrator-hardcode-evidence.md) only for
the narrowly allowed public-domain source-proof exception. Ordinary configured
values must remain configuration; traffic samples are not source proof.

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
