# Repository Map

## Overview

This is a Rust single-binary traffic recorder proxy. It records HTTP, HTTPS,
HTTP gateway, fake-DNS TCP/UDP gateways, MySQL, Redis, Memcached, and
constrained Kafka traffic to JSONL files.

The primary crate is in `src/` and builds the `traffic-recorder-proxy` binary.
Recorder configuration starts from `config/recorder.example.toml`. Local command
facades live in `scripts/`, especially `traffic-record` and `traffic-replay`.

## Read First

- Development, runtime, recording, replay, and testing commands:
  [docs/development.md](docs/development.md)
- Pre-change module review, naming, cohesion, dependency direction, and
  refactoring rules:
  [docs/code-organization.md](docs/code-organization.md)
- Recorded E2E replay skill:
  [skills/recorded-e2e-cases/SKILL.md](skills/recorded-e2e-cases/SKILL.md)
- Cross-language E2E rewrite migration skill:
  [skills/e2e-rewrite-migration/SKILL.md](skills/e2e-rewrite-migration/SKILL.md)

## Essential Commands

Before opening or updating an MR, run at least:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
scripts/check-code-organization
```

Useful focused tests:

```bash
cargo test mysql::wire
cargo test mysql::semantic
cargo test proxy_integration
```

For local recording and replay:

```bash
cargo run -- --config config/recorder.example.toml
traffic-record config/recorder.example.toml
traffic-replay path/to/case-dir
traffic-replay --no-intercept path/to/case-dir
```

## Non-Negotiable Rules

- Keep async code on `tokio`.
- Do not replace `.cargo/config.toml` registry settings unless explicitly asked.
- Do not commit generated CA files, traffic recordings, test captures, local
  swap files, `target/`, `data/`, or `recordings/`.
- Use `dependencies.jsonl` for replay-oriented semantic dependency data.
  Use `dependencies-debug.jsonl` only for protocol-level debugging.
- MySQL TLS MITM is intentionally out of scope for v1. If `CLIENT_SSL` is
  detected, keep rejecting and recording the reason.
- Keep sensitive data handling explicit. Add newly sensitive headers to
  `recording.redact_headers` defaults or document the choice.
- Before changing product code, review the touched code against
  [docs/code-organization.md](docs/code-organization.md). Treat the initial
  boundary as a hypothesis and review the implemented responsibilities again
  before completion. Keep feature-local structural convergence in scope and
  unrelated legacy cleanup out of scope.
- Product source files must not exceed 1000 lines after a change. If a touched
  file is already over 1000 lines, follow
  [docs/code-organization.md](docs/code-organization.md) and split the relevant
  responsibility before adding new behavior.

## Git Hygiene

Work on feature branches. Keep commits focused and avoid committing unrelated
local edits. Before pushing, confirm:

```bash
git status --short
git diff --check
```
