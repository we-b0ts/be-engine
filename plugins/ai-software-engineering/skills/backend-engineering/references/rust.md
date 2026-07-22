# Rust Backend Engineering

Apply the generic backend contracts first. Use this reference only for Rust.

## Runtime And Structure

Reuse the target crate layout, async runtime, framework, configuration, and
diagnostics. Keep binary entrypoints focused on arguments, config, wiring, and
startup. Use real modules and narrow interfaces; avoid `include!` or prefix
sprawl as substitutes for ownership boundaries.

Keep async code on the repository's established runtime. With Tokio, do not run
blocking filesystem, process, compression, cryptographic, or CPU-heavy parsing
work on executor threads; use a bounded `spawn_blocking` or dedicated pool.
Avoid holding synchronous or asynchronous locks across `.await` unless the
locked resource explicitly requires it and contention is understood.

Track every spawned task through an owner, cancellation token, task set, or
supervisor. Detached tasks need bounded admission, error reporting, and
shutdown behavior.

## Allocation And Data

Prefer borrowed data and immutable `bytes::Bytes`-style buffers where lifetime
and framework support make ownership clear. Do not add `clone()` or `Arc` only
to satisfy the borrow checker without reviewing retained memory and
concurrency semantics.

Avoid repeated `serde_json::Value` cloning and parse/serialize cycles for large
payloads. Use typed models, streaming deserializers, buffered writers, or direct
serialization when they preserve the wire contract and measurements justify
the complexity.

## Errors And Dependencies

Preserve root causes with typed errors or contextual error chains. Do not turn
timeouts, pool exhaustion, protocol errors, and remote application errors into
one opaque variant before observability and retry decisions are made.

Reuse long-lived clients and pools. Configure acquisition and operation
deadlines, pool bounds, connection behavior, and shutdown explicitly. Use the
same genuine adapters in normal runtime and integration paths.

## Quality Gate

Run the repository's required commands. Without stricter equivalents, use:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

For runnable services, also verify normal startup, readiness, graceful
shutdown, and any material performance or failure paths changed by the work.
