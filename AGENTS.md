# Repository Map

## Overview

This is a Rust single-binary traffic E2E CLI. It records HTTP, HTTPS, HTTP
gateway, fake-DNS TCP/UDP gateways, MySQL, Redis, Memcached, and constrained
Kafka traffic to JSONL files, then groups, replays, and verifies recorded
contracts.

The primary crate is in `src/` and builds the `traffic-e2e` binary. Standard
workflow commands are `config init`, `rewrite ...`, `record`, `record-comparison`, `prepare`,
`run-api`, `run`, `status`, `recover`, and `abort`; managed recording, replay, and target isolation are
also provided by the same binary, while low-level tooling is under `diagnose`.
Recorder
configuration starts from `config/recorder.example.toml`. Repository scripts
are development or manual host-trust tools only.

## Read First

- Development, runtime, recording, replay, and testing commands:
  [docs/development.md](docs/development.md)
- Traffic-e2e-specific package and module ownership:
  [docs/code-organization.md](docs/code-organization.md)
- Backend engineering standards for AI coding work:
  [plugins/ai-software-engineering/skills/backend-engineering/SKILL.md](plugins/ai-software-engineering/skills/backend-engineering/SKILL.md)
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
  plugins/ai-software-engineering/skills/backend-engineering/scripts/check-code-organization
```

Useful focused tests:

```bash
cargo test mysql::wire
cargo test recorder::mysql::semantic
cargo test proxy_integration
```

For local recording and replay:

```bash
traffic-e2e diagnose recorder --config config/recorder.example.toml
traffic-e2e replay path/to/case-dir
traffic-e2e replay --no-intercept path/to/case-dir
traffic-e2e target exec -- path/to/prebuilt-target
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
- In this traffic-e2e engine repository, agents are explicitly allowed to read
  `.traffic-e2e/.ai-forbidden/**` when developing, diagnosing, reviewing, or
  testing engine behavior. This repository-maintainer exception does not apply
  to an ordinary rewrite in a target repository. The directory remains an
  internal implementation detail and this exception does not authorize
  editing runtime state or exposing sensitive contents.
- Before changing product code, follow the backend-engineering
  [code-organization rules](plugins/ai-software-engineering/skills/backend-engineering/references/code-organization.md)
  and this repository's [module ownership](docs/code-organization.md). Treat
  the initial boundary as a hypothesis and review the implemented
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
