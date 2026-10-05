# Repository Map

## Overview

This is a Rust traffic E2E engine and backend rewrite coordinator. It records
HTTP, HTTPS, HTTP gateway, fake-DNS TCP/UDP gateways, MySQL, Redis, Memcached,
and constrained Kafka traffic to JSONL files, then groups, replays, and
verifies recorded contracts.

The primary crate is in `src/` and builds three default binaries. `traffic-e2e` exposes
the low-level recording, replay, comparison, configuration, and diagnostic
engine; `backend-rewrite` exposes AI-facing rewrite orchestration directly on
the same crate; `backend-rewrite-admin` exposes explicit administrator-owned
startup snapshot repair outside ordinary AI workflows. Standard engine
workflow commands are `config init`, `record`, `record-comparison`, `prepare`,
`run-api`, `run`, `status`, `recover`, and `abort`; managed recording, replay,
and target isolation are also provided by the `traffic-e2e` binary, while
low-level tooling is under `diagnose`. Recorder
configuration starts from `config/project.example.yaml`. Repository scripts
are development or manual host-trust tools only.

The optional `online-recording` feature adds `recording-online`, a standalone
Source/Recorder app with Redis discovery and completion and no project loader;
see [docs/online-recording.md](docs/online-recording.md).

## Read First

- Development, runtime, recording, replay, and testing commands:
  [docs/development.md](docs/development.md)
- Traffic-e2e-specific package and module ownership:
  [docs/code-organization.md](docs/code-organization.md)
- Traffic recording, replay, and verification skill:
  [plugins/ai-software-engineering/skills/traffic-e2e/SKILL.md](plugins/ai-software-engineering/skills/traffic-e2e/SKILL.md)

## Essential Commands

Before opening or updating an MR, run at least the following. Replace
`origin/master` when the MR targets another branch:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
CODE_ORG_BASE=origin/master \
  plugins/ai-software-engineering/skills/backend-rewrite/scripts/check-code-organization
```

Useful focused tests:

```bash
cargo test mysql::wire
cargo test recorder::mysql::semantic
cargo test proxy_integration
```

For local recording and replay:

```bash
traffic-e2e diagnose recorder --config config/project.example.yaml
traffic-e2e replay path/to/case-dir
traffic-e2e replay --no-intercept path/to/case-dir
traffic-e2e target exec -- path/to/prebuilt-target
```

## Non-Negotiable Rules

- Keep async code on `tokio`.
- Do not replace `.cargo/config.toml` registry settings unless explicitly asked.
- Do not commit generated CA files, traffic recordings, test captures, local
  swap files, `target/`, `data/`, `recordings/`, or `.traffic-e2e/local/`.
- Use `dependencies.jsonl` for replay-oriented semantic dependency data.
  Use `dependencies-debug.jsonl` only for protocol-level debugging.
- Preserve MySQL `CLIENT_SSL` behavior end to end: recording terminates TLS on
  both sides for semantic capture, and replay accepts TLS with the replay CA.
  Keep the permissive self-signed certificate policy isolated to the recording
  connector for MySQL upstreams; HTTPS verification must remain strict.
- Keep sensitive data handling explicit. Add newly sensitive headers to
  `recording.redact_headers` defaults or document the choice.
- Before changing product code, follow this repository's
  [module ownership and code-organization requirements](docs/code-organization.md).
  Treat the initial boundary as a hypothesis and review the implemented
  responsibilities again before completion. Keep feature-local structural
  convergence in scope and unrelated legacy cleanup out of scope.
- Product source files must not exceed 1000 lines after a change. If a touched
  file is already over 1000 lines, follow the backend code-organization rules
  and split the relevant responsibility before adding new behavior.

## Git Hygiene

Work on feature branches. Keep commits focused and avoid committing unrelated
local edits. Before pushing, confirm:

```bash
git status --short
git diff --check
```
