# Traffic E2E Code Organization

Read the backend-engineering
[code-organization reference](../plugins/ai-software-engineering/skills/backend-engineering/references/code-organization.md)
for the generic boundary, naming, cohesion, dependency-direction, refactoring,
and size rules. This file contains only traffic-e2e-specific package and module
ownership.

## Package Shape

Keep this repository as one Rust crate unless the user asks for a workspace,
the project gains multiple deployable artifacts, or multiple real packages
need a shared library. Ask before creating a workspace when the boundary is
unclear.

## Current Boundaries

- Supported dependency protocols are peer domains: MySQL, Redis, Memcached,
  Kafka, and Motan. Do not group protocols by a presumed business use such as
  cache or RPC.
- Top-level `mysql`, `redis`, `memcached`, `kafka`, and `motan` modules own
  reusable protocol parsing and encoding only. They do not own recording or
  replay.
- Top-level `http` owns reusable HTTP forwarding policy. `proxy/http` and
  `gateway/http` own their respective runtimes, while `recorder/http` owns
  recorded HTTP case persistence.
- `recorder/<protocol>` owns capture-time protocol adapters, while
  `replay/<protocol>` owns matching and response behavior for recorded
  evidence. Both may depend on the top-level protocol module, never the
  reverse.
- `main.rs` owns CLI and binary bootstrap only.
- `lib.rs` owns application wiring, shared state, and stable exports.
- Proxy and gateway modules own connection and request orchestration.
- Protocol and semantic modules own parsing, encoding, and interpretation.
- Recorder event, run, writer, and summary modules own capture, persistence,
  and reporting.
- Replay modules own recorded dependency matching and replay lifecycle.
- Config, TLS, DNS, and process lookup remain focused infrastructure concerns.

Prefer these boundaries while they remain accurate. When implementation proves
that a current parent no longer expresses ownership, make the smallest
feature-local adjustment and preserve observable contracts.

## Repository Check

After the final Rust product-code edit and before commit, run the checker
bundled with `backend-engineering`:

```bash
plugins/ai-software-engineering/skills/backend-engineering/scripts/check-code-organization
```

Before an MR, set `CODE_ORG_BASE` to the target branch. Use `--all` only for an
explicit repository-wide audit.
