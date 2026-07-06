# Repository Guidelines

## Project Overview

This is a Rust single-binary traffic recorder proxy. It records HTTP, HTTPS,
HTTP gateway, fake-DNS/TCP gateway, and MySQL traffic to JSONL files.

The primary crate is in `src/` and builds the `traffic-recorder-proxy` binary.
Example runtime configuration lives in `config.example.toml`. Local helper
scripts live in `scripts/`.

## Rust Tooling

Use the standard Cargo workflow:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build
```

Before opening or updating an MR, run at least:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The repository includes `.cargo/config.toml` for the configured crates.io mirror.
Do not replace that registry configuration unless explicitly asked.

## Running Locally

Run the service with:

```bash
cargo run -- --config config.example.toml
```

For watch-mode development:

```bash
./scripts/dev.sh
```

`scripts/dev.sh` enables local DNS capture and fake-IP TCP redirect by default,
which modifies local DNS/iptables state through the setup scripts. Use this when
you intentionally want the recorder to intercept local traffic. To skip those
rules:

```bash
./scripts/dev.sh --no-dns
```

When using the setup scripts directly, always pair `up` with `down`:

```bash
sudo ./scripts/setup_local_dns.sh up
sudo ./scripts/setup_fake_ip_redirect.sh up
sudo ./scripts/setup_fake_ip_redirect.sh down
sudo ./scripts/setup_local_dns.sh down
```

## Recording Files

Generated runtime artifacts are ignored by git:

- `target/`
- `data/`
- `recordings/`
- `*.swp`

Do not commit generated CA files, traffic recordings, test captures, or local
swap files.

Case output is organized as:

```text
<rule-name>/<case-id>/request.json
<rule-name>/<case-id>/expected-response.json
<rule-name>/<case-id>/dependencies.jsonl
<rule-name>/<case-id>/dependencies-debug.jsonl
```

Use `dependencies.jsonl` for mock-oriented semantic data. Use
`dependencies-debug.jsonl` only for protocol-level debugging.

## Coding Guidelines

- Keep async code on `tokio`.
- Prefer the existing module boundaries:
  - `http_proxy.rs` for explicit HTTP/HTTPS proxy behavior.
  - `http_gateway.rs` for tcpcopy-style HTTP gateway behavior.
  - `dns_mock.rs` and `tcp_gateway.rs` for fake-DNS/fake-IP interception.
  - `mysql_protocol.rs` for low-level MySQL packet parsing.
  - `mysql_semantic.rs` for semantic MySQL exchange parsing.
  - `recorder.rs` for JSONL event structures and file writes.
- Keep recorder events backward-friendly where possible. Add fields instead of
  reshaping existing event payloads unless the caller explicitly wants a format
  change.
- Keep sensitive data handling explicit. New HTTP headers that may contain
  secrets should be added to `recording.redact_headers` defaults or documented.
- MySQL TLS MITM is intentionally out of scope for v1. If `CLIENT_SSL` is
  detected, keep rejecting and recording the reason.
- For mock generation, prefer semantic `mysql_exchange` records over raw
  packet/base64 payloads.

## Testing Guidance

Add unit tests near the parser or module being changed. Add integration tests in
`tests/proxy_integration.rs` when changing externally visible proxy behavior.

Useful focused test commands:

```bash
cargo test mysql_protocol
cargo test mysql_semantic
cargo test proxy_integration
```

Network or root-requiring behavior should be covered with isolated unit tests
where possible. Do not require host iptables changes for automated tests.

## Git Hygiene

Work on feature branches. Keep commits focused and avoid committing unrelated
local edits. Before pushing, confirm:

```bash
git status --short
git diff --check
```
