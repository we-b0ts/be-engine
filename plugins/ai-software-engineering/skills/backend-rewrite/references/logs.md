# Use process logging through `brz-logs`

Use this guide when a Rust target installs process logging through `brz-logs`
or changes application log routing, buffering, flushing, or shutdown. Logging
is a process-level runtime capability: initialize it once in the final binary,
then use `tracing` events from libraries and application modules.

## Install one process logger

Pin the dependency to the fixed `v0.0.1` tag and enable `metrics` by default.
Product packages emit events through `tracing`; only the final binary depends
on `brz-logs` to install the global subscriber:

```toml
brz-logs = { package = "logs", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/logs.git", tag = "v0.0.1", features = ["metrics"] }
```

Initialize logging after startup arguments and native configuration needed to
select the logging configuration are available, but before constructing
dependency clients, starting workers, or emitting product events. Retain the
guard for the process lifetime:

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let logs = brz_logs::init_default()?;
    tracing::info!(service = "example", "service starting");

    run_service()?;
    logs.flush()?;
    Ok(())
}

# fn run_service() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
```

`init_default` reads `BREEZE_LOG_DIR` and `RUST_LOG`, falling back to the
standard defaults. Use `brz_logs::init(LogsConfig)` when the source-compatible
runtime configuration requires explicit values. Do not install another global
`tracing` subscriber or add a separate stdout/stderr formatting layer.

## Preserve the file and line contract

The default directory is `/data1/weibo/logs`. The target image must create the
directory and make it writable by the runtime identity, UID 998. Runtime
configuration may override the directory without changing event call sites.
Do not copy source logs or recorded output into the target directory.

Each enabled event is written to exactly one file:

- `TRACE`, `DEBUG`, and `INFO` go to `info.log`;
- `WARN` goes to `warn.log`;
- `ERROR` goes to `error.log`.

Do not duplicate application events to stdout, stderr, or a less severe file.
Failures before the subscriber is installed may use stderr because the file
logger is not yet available.

Lines use a fixed UTC+8 wall-clock timestamp without a timezone suffix:

```text
2026-08-30 15:10:17 [INFO] ListStorage get new version. listId:6296, version:1684410575955, hash:4185ad0d, length:10000
```

Emit ordinary `tracing::trace!`, `debug!`, `info!`, `warn!`, and `error!`
events. Keep stable diagnostic fields structured, and do not log secrets,
credentials, full sensitive payloads, or unbounded-cardinality values.

## Keep logging bounded and off the I/O path

The default logger formats the event on the caller thread and transfers the
completed line through a bounded queue. One background thread owns all three
files and performs batched vectored writes and flushes. File I/O therefore does
not run on a Tokio worker or request thread.

`LogsConfig` controls the filter, queue capacity, arena capacity, maximum line
size, overflow behavior, and flush policy. Every configured queue and line size
must remain bounded:

```rust,no_run
use std::time::Duration;

use brz_logs::{FlushPolicy, LogsConfig, OverflowPolicy};

let config = LogsConfig::from_env()
    .with_queue_capacity(16_384)
    .with_arena_chunk_bytes(16 * 1024 * 1024)
    .with_max_line_bytes(64 * 1024)
    .with_overflow_policy(OverflowPolicy::DropNewest)
    .with_flush_policy(FlushPolicy::IntervalAndError(Duration::from_secs(1)));
let logs = brz_logs::init(config)?;
# logs.flush()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `OverflowPolicy::DropNewest` for normal service logging so queue saturation
does not block the application hot path. `LogsGuard::dropped_lines` exposes
the cumulative loss count. With the optional `metrics` feature, a full queue
also increments the count-only `type=LOG,name=queue_dropped` profile metric;
its `total_count` covers one profile interval. This is operational health data,
not traffic behavior, and must not be added to process-output comparison rules.
Use `OverflowPolicy::Block` only when the product contract explicitly prefers
backpressure over log loss and the affected call paths can tolerate blocking.

The line arena owns one backing buffer divided into two chunks. Each chunk is
16 MiB by default, for 32 MiB total reserved capacity. Change
`arena_chunk_bytes` only during initialization. A line's initial segment adapts
between 512 bytes, 1 KiB, and 2 KiB. Longer lines append segments up to 2 KiB
without moving already-formatted bytes. After 512 consecutive low-usage lines,
the initial segment shrinks by one step. Arena tickets are released after the
background writer consumes the line.

The worker drains at most `queue_capacity` entries into one logical batch and
keeps the order of entries for each destination file. Each vectored file-system
write contains at most 1024 arena segments, so a fully occupied default queue
may require multiple system calls. Do not add a separate per-file byte buffer:
the queued arena segments are written directly without another body copy.

The standard `IntervalAndError` policy flushes all files periodically and
flushes an `ERROR` event immediately. `EveryLine` trades substantially more
file-system work for durability and is not a default production setting.
Inspect `LogsGuard::last_error` when runtime health reporting needs to expose a
background file failure; do not poll it per request.

Do not replace the bounded queued design with an unbounded channel, a task
per event, or synchronous file writes. A proposed allocation, queue, or
formatting optimization requires a representative measurement before adding
complex ownership or unsafe code.

## Flush during shutdown and fatal exits

On normal return, dropping `LogsGuard` drains the accepted queue, flushes all
files, and joins the logging thread. Keep the guard alive until all event
producers and background workers have stopped so late shutdown events are not
lost.

`std::process::exit` skips destructors. Prefer returning an exit status through
the normal shutdown path. If an unrecoverable path must call `process::exit`,
emit the final event and call `LogsGuard::flush` before exiting. Treat a flush
failure as startup or operational diagnostic evidence; do not recursively log
that failure through the failed logger.

## Check before delivery

1. Verify there is exactly one subscriber initialization and the guard remains
   owned until shutdown.
2. Verify the image creates the configured directory writable by UID 998 and
   no source or recorded logs are copied into it.
3. Verify each level reaches only its designated file with the UTC+8 timestamp
   and no timezone suffix or console duplicate.
4. Exercise queue saturation, truncation, periodic/error flush, file-open or
   write failure, explicit flush, and graceful shutdown behavior when changing
   logging infrastructure.
5. Run the target repository's focused checks. Return the coordinator-issued
   acceptance command unchanged; the main orchestrator runs it after
   integration.
