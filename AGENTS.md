# Repository Guidelines

## Project Overview

This is a Rust single-binary traffic recorder proxy. It records HTTP, HTTPS,
HTTP gateway, fake-DNS/TCP gateway, and MySQL traffic to JSONL files.

The primary crate is in `src/` and builds the `traffic-recorder-proxy` binary.
Recorder runtime configuration lives in `recorder.example.toml`. Replay defaults
are built into `scripts/traffic-replay`, which takes a recorded case directory
directly. Local recorder/replay helper scripts live in `scripts/`, including
`scripts/traffic-record` and `scripts/traffic-replay`.

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
cargo run -- --config recorder.example.toml
```

For watch-mode recording:

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
traffic-record recorder.example.toml
```

`traffic-record` enables local DNS capture and fake-IP TCP redirect by default,
which modifies local DNS/iptables state through the setup scripts. Use this
when you intentionally want the recorder to intercept local traffic. To skip
those rules:

```bash
traffic-record --no-dns recorder.example.toml
```

`recorder.example.toml` enables `[local_record]` owner filtering for the
dedicated Unix user `trp-record`. Prefer running the source service as that user
so bootstrap and case dependencies are not polluted by unrelated local
processes. `traffic-record --user`, `traffic-record --owner-uid`,
`traffic-record --all-users`, or `OWNER_UID` override the config.

For replay-mode development:

```bash
cargo build
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/debug/traffic-recorder-proxy" "$HOME/.local/bin/traffic-recorder-proxy"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
ln -sf "$PWD/scripts/traffic-replay" "$HOME/.local/bin/traffic-replay"
traffic-replay path/to/case-dir
traffic-replay --no-intercept path/to/case-dir
```

`traffic-replay` also defaults to owner filtering for `trp-record`. Run the
target service as that user, or pass `--user`, `--owner-uid`, or `--all-users`
when the replay environment requires a different scope.

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
<rule-name>/<uri-group>/<case-id>/request.json
<rule-name>/<uri-group>/<case-id>/expected-response.json
<rule-name>/<uri-group>/<case-id>/dependencies.jsonl
<rule-name>/<uri-group>/<case-id>/dependencies-summary.json
<rule-name>/<uri-group>/<case-id>/dependencies-debug.jsonl
bootstrap-dependencies.jsonl
bootstrap-dependencies-summary.json
bootstrap-dependencies-debug.jsonl
```

Use `dependencies.jsonl` for replay-oriented semantic data. Use
`dependencies-debug.jsonl` only for protocol-level debugging. Root-level
bootstrap dependency files capture replay-oriented dependencies observed before
the first case starts; replay discovers them by walking upward from a case
directory.

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
- For managed replay, prefer semantic `mysql_exchange` records over raw
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
