# Use process logging through `brz-logs`

Initialize logging once in the final binary. Libraries and application modules
emit ordinary `tracing` events; they do not install subscribers. Preserve the
source's operational log content and the target's configured output contract.

## Dependency

Use the latest stable release from the project's configured Cargo registry and
pin it exactly. Replace `<latest-version>` with the verified release number
without a `v` prefix; it is a placeholder, not a Cargo version expression.
Replace the old Git dependency, preserve registry configuration, and update
`Cargo.lock`.

```toml
[dependencies]
brz-logs = { package = "brz-logs", version = "=<latest-version>", features = ["metrics"] }
tracing = "0.1"
```

Keep the explicit `package` field so the dependency is available as `brz_logs::`.
Enable `metrics` in the final binary; library crates only need `tracing`.

## Initialize and retain the guard

Initialize after reading logging configuration but before constructing clients,
starting workers, or emitting product events. Retain `LogsGuard` until all event
producers have stopped:

```rust,ignore
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let logs = brz_logs::init_default()?;
    let result = run_service(); // Includes orderly shutdown of all workers.
    logs.flush()?;
    result
}
```

`init_default()` reads `BREEZE_LOG_DIR` and `RUST_LOG`. Use
`brz_logs::init(LogsConfig::from_env().with_directory(log_directory))` when the
application configuration supplies an explicit directory. Do not install a
second global subscriber or duplicate application events to stdout/stderr.
Failures before initialization may use stderr.

## Directory and event routing

The SDK default directory is `../logs`, relative to the process working directory.
If deployment requires a fixed location such as `/data1/weibo/logs`, configure it
explicitly through `BREEZE_LOG_DIR` or `LogsConfig::with_directory`. Ensure that
directory is writable by the runtime identity (the generated image uses UID 998).
Do not copy source logs or recorded output into it.

Each enabled event goes to exactly one file:

| Levels | File |
| --- | --- |
| TRACE, DEBUG, INFO | `info.log` |
| WARN | `warn.log` |
| ERROR | `error.log` |

The SDK formats fixed UTC+8 timestamps without a timezone suffix; application
code supplies the event message and structured fields. Use `tracing::trace!`,
`debug!`, `info!`, `warn!`, and `error!`. Preserve useful diagnostics without
logging secrets, credentials, full sensitive payloads, or unbounded content.

## Buffering, health, and shutdown

The SDK uses a bounded queue and one background file writer. Keep file I/O off
request/Tokio worker threads. Use `LogsConfig` for queue capacity, maximum line
size, overflow policy, and flush policy; tune only when required by the runtime
contract, keeping memory bounded.

| Setting or signal | Usage |
| --- | --- |
| `OverflowPolicy::DropNewest` | Default; queue saturation does not block producers |
| `OverflowPolicy::Block` | Only when the contract prefers backpressure and callers can tolerate blocking |
| `FlushPolicy::IntervalAndError` | Default: periodic flush plus flush after ERROR events |
| `FlushPolicy::EveryLine` | More file-system work; select only when explicitly required |
| `LogsGuard::dropped_lines()` | Cumulative dropped-line count |
| `LOG / queue_dropped` metric | Full-queue losses during the current profile interval |
| `LogsGuard::last_error()` | Background file failure for health reporting; do not poll per request |

Dropping the guard drains accepted events, flushes files, and joins the writer.
Stop workers first so late shutdown events are retained. Use `flush()` when a
flush barrier or error result is required; do not recursively report flush
failures through the failed logger.

Prefer normal return over `std::process::exit`, which skips destructors. If a
fatal path must exit directly, emit its final event and explicitly flush first.
Do not add an unbounded channel, one task per event, a second file buffer, or
synchronous per-event writes around the SDK.
