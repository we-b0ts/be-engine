# Code Organization

Use this file for module boundaries, package decisions, code-size gates, and
refactoring expectations in this repository.

## Package Shape

This repository is currently a single Rust binary crate. Keep it that way unless
there is strong evidence that a workspace is needed.

Create a Cargo workspace only when:

- the user explicitly asks for one
- the project gains multiple deployable binaries or services
- a shared library boundary is needed by multiple real packages
- the existing repo structure has already moved to a workspace

If the need is uncertain, ask before creating the workspace.

## Current Module Map

Prefer the existing boundaries when adding or moving code:

- `main.rs`: binary bootstrap only
- `lib.rs`: application wiring, shared state, and module exports
- `config.rs`: runtime configuration structures and loading
- `http_proxy.rs`: explicit HTTP/HTTPS proxy behavior
- `http_gateway.rs`: tcpcopy-style HTTP gateway behavior
- `dns_mock.rs`: fake-DNS behavior
- `tcp_gateway.rs`: fake-IP TCP interception and routing
- `mysql_proxy.rs`: MySQL proxy/session orchestration
- `mysql_protocol.rs`: low-level MySQL packet parsing and encoding
- `mysql_semantic.rs`: semantic MySQL exchange parsing
- `mysql_replay.rs`: managed MySQL dependency replay
- `recorder.rs`: JSONL event structures and file writes
- `dependency_summary.rs`: dependency summary construction
- `process_lookup.rs`: local process ownership lookup
- `tls.rs`: CA and TLS helpers

## Dependency Direction

Keep responsibilities separated:

- protocol parsers should not write files or mutate recording directories
- record writers should not parse protocol bytes
- gateway/proxy modules should orchestrate sessions, not own semantic decoders
- replay modules should prefer semantic `mysql_exchange` records over raw packet
  payloads
- config loading should stay separate from runtime behavior
- tests and fixtures must not be required by normal recorder or replay startup

Avoid catch-all helper files. If a helper grows, split it by topic such as
paths, time, redaction, process lookup, packet codec, matching, or report
formatting.

## Code-Size Gates

Product source files must stay below 1000 lines after a change.

Use these thresholds:

- 600 lines: self-review whether responsibilities are mixing
- 800 lines: split or document why the file still has one clear responsibility
- 1000 lines: hard stop; do not complete the change until the relevant
  responsibility is extracted, unless the user explicitly forbids refactoring
  for that turn

Existing files already over 1000 lines are refactor hotspots:

- `src/mysql_replay.rs`
- `src/mysql_semantic.rs`
- `src/tcp_gateway.rs`
- `src/recorder.rs`

When a task touches one of these files, do a scoped extraction before adding new
behavior. Keep the extraction tied to the current change, such as moving replay
matching, response encoding, semantic column mapping, recorder events, or file
writing into smaller modules. Do not perform broad unrelated rewrites.

## Suggested Refactor Directions

Use these as guidance when a touched file crosses a size gate:

- split `mysql_replay` by runtime state, fake DNS/gateway, MySQL session,
  exchange matching, response encoding, and replay report
- split `mysql_semantic` by tracker, prepared statements, resultset parsing,
  column schema, value decoding, and tests
- split `recorder` by event types, writers, case paths, body encoding, and
  summaries
- split `tcp_gateway` by fake-IP routing, listener lifecycle, connection copy,
  process matching, and dependency attachment

Prefer small, reversible extractions with focused tests. Preserve public event
formats unless the user explicitly asks for a breaking format change.

## Completion Check

Before declaring a change complete:

```bash
wc -l src/*.rs | sort -n
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If any touched product source file remains over 1000 lines, report the
refactoring blocker or the explicit user exception in the final response.
