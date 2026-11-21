# Repository Map

## Overview

This is a Rust traffic E2E engine and backend rewrite coordinator. It records
HTTP, HTTPS, HTTP gateway, fake-DNS TCP/UDP gateways, MySQL, and Redis
traffic to JSONL files, then groups, replays, and
verifies recorded contracts.

The root `src/` owns three CLI entrypoints and a public API facade.
Workspace crate directories sit at the root with short names, for example
`engine-replay/` for the Cargo package `traffic-engine-replay`.
`traffic-e2e-app` composes the independent `traffic-rewrite` coordinator and
`traffic-replay-runtime` session service over shared `traffic-engine` services.
`traffic-engine` provides repository initialization and the shared service facade.
`traffic-engine-e2erun` owns managed E2E execution and Target lifecycle. Shared
environment, configuration, evidence, policy, recording, Replay and verification
adapters live in the corresponding `traffic-engine-*` packages. `traffic-replay`,
`traffic-rewrite-core`, `traffic-recorder` and `traffic-recording-store` retain
implementation-independent kernels and contracts. `traffic-e2e` exposes
the low-level recording, replay, configuration, and diagnostic
engine; `backend-rewrite` exposes AI-facing rewrite orchestration directly on
the shared application services; `backend-rewrite-admin` exposes explicit administrator-owned
startup snapshot repair outside ordinary AI workflows. Standard engine
workflow commands are `config init`, `record`, `prepare`,
`run-api`, `run`, `status`, `recover`, and `abort`; managed recording, replay,
and target isolation are also provided by the `traffic-e2e` binary, while
low-level tooling is under `diagnose`. Recorder
configuration starts from `config/project.example.yaml`. Repository scripts
are development or manual host-trust tools only.

`traffic-e2e record` runs Source and Recorder directly with optional Redis
coordination. Projects own the recording container; backend-rewrite consumes
completed recordings without starting capture. See [docs/recording.md](docs/recording.md).

## Read First

- Development, runtime, recording, replay, and testing commands:
  [docs/development.md](docs/development.md)
- Traffic-e2e-specific package and module ownership:
  [docs/code-organization.md](docs/code-organization.md)
- Traffic recording, replay, and verification skill:
  [plugins/ai-software-engineering/skills/traffic-e2e/SKILL.md](plugins/ai-software-engineering/skills/traffic-e2e/SKILL.md)

## Essential Commands

Before opening or updating an MR, run at least the following. Replace
`origin/main` when the MR targets another branch:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
CODE_ORG_BASE=origin/main \
  plugins/ai-software-engineering/skills/backend-rewrite/scripts/check-code-organization
```

Useful focused tests:

```bash
cargo test -p traffic-protocol-mysql
cargo test -p traffic-protocol-mysql-sql
cargo test -p traffic-protocol-mysql capture::semantic
cargo test proxy_integration
```

For local recording and replay:

```bash
traffic-e2e diagnose recorder --config .traffic-e2e/project.yaml
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
