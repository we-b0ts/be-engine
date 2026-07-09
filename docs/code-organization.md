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
- `http_gateway_case.rs`: HTTP gateway case finalization and invalid-case
  classification
- `dns_mock.rs`: fake-DNS behavior
- `tcp_gateway.rs`: fake-IP TCP interception and routing
- `mysql_proxy.rs`: MySQL proxy/session orchestration
- `mysql_protocol.rs`: low-level MySQL packet parsing and encoding
- `mysql_semantic.rs`: semantic MySQL exchange parsing
- `mysql_replay.rs`: managed MySQL dependency replay
- `mysql_replay_control.rs`: replay session control socket, session state, and
  control client
- `mysql_replay_records.rs`: replay dependency records, identity matching,
  target assignment, and report model
- `mysql_replay_dns.rs`: replay DNS question parsing and fake A responses
- `mysql_replay_session.rs`: replay MySQL session command handling
- `mysql_replay_response.rs`: replay MySQL response packet encoding
- `mysql_replay_values.rs`: replay value conversion, built-in responses, and
  low-level value helpers
- `recorder.rs`: JSONL writes, case file writes, dependency attachment, and
  body capture helpers
- `recorder_event.rs`: recorder event and payload data structures
- `recorder_run.rs`: recording run reports, staging, publishing, and failed
  case handling
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

## Module Topology Review

Before adding behavior to an existing domain, review whether the current module
topology still explains ownership clearly. Pay attention to domain clusters,
same-prefix files, oversized files, catch-all helper modules, and test/replay
support leaking into normal runtime paths.

Prefer real Rust module namespaces when they make a domain clearer. For example,
a growing group such as `mysql_replay_*` can become a `mysql::replay` module
tree when the next MySQL replay change needs to touch or extend it. The goal is
clarity of ownership, not cosmetic directory churn; keeping the current layout
is fine when it is the least surprising shape for the change.

Do not treat `include!`-based extraction or loose same-prefix files as a
long-term architecture by default. They are acceptable as temporary or
mechanical steps, but the next substantial change in that area should consider
moving to ordinary Rust modules unless there is a generated-code or
macro-driven reason to keep `include!`.

## Code-Size Gates

Product source files must stay below 1000 lines after a change.

Use these thresholds:

- 600 lines: self-review whether responsibilities are mixing
- 800 lines: split or document why the file still has one clear responsibility
- 1000 lines: hard stop; do not complete the change until the relevant
  responsibility is extracted, unless the user explicitly forbids refactoring
  for that turn

Existing files already over 1000 lines are refactor hotspots:

- `src/mysql_semantic.rs`
- `src/tcp_gateway.rs`

When a task touches one of these files, do a scoped extraction before adding new
behavior. Keep the extraction tied to the current change, such as moving replay
matching, response encoding, semantic column mapping, recorder events, or file
writing into smaller modules. Do not perform broad unrelated rewrites.

## Suggested Refactor Directions

Use these as guidance when a touched file crosses a size gate:

- move `mysql_replay` leaf files toward a real `mysql::replay` namespace when a
  replay change needs to extend that area
- split `mysql_semantic` by tracker, prepared statements, resultset parsing,
  column schema, value decoding, and tests
- move recorder event/run/body responsibilities toward a `recorder` namespace
  if the current loose files become harder to navigate
- split `tcp_gateway` by fake-IP routing, listener lifecycle, connection copy,
  process matching, and dependency attachment
- group HTTP proxy/gateway/case responsibilities under an `http` namespace if
  future HTTP work makes the current top-level files noisy

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
