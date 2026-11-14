//! Exact Source-stop scope, distinct from peer failures and value permissions.
use super::*;
use control::dependency_tail::RecordedReference;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncReadExt;

pub(crate) async fn load_refs(case_dir: &Path) -> Result<BTreeSet<RecordedReference>> {
    let directory = case_dir.to_owned();
    tokio::task::spawn_blocking(move || control::dependency_tail::load_cleanup_refs(&directory))
        .await
        .context("async cleanup scope loading task failed")?
}

/// A stopped Target is an independently observed client termination. Before
/// the trusted controller arms this gate, the same termination is a failure.
pub(in crate::replay) async fn await_target_end(
    io: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
    gate: &AtomicBool,
    state: &Arc<Mutex<ReplayState>>,
    case: &str,
) -> Result<()> {
    await_end(io, gate, state, case, false).await
}

/// Before an upstream connect succeeds, Source has no complete protocol
/// request observation. Drain its caller's initial bytes without inventing one.
pub(in crate::replay) async fn await_connection_end(
    io: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
    gate: &AtomicBool,
    state: &Arc<Mutex<ReplayState>>,
    case: &str,
) -> Result<()> {
    await_end(io, gate, state, case, true).await
}

async fn await_end(
    io: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
    gate: &AtomicBool,
    state: &Arc<Mutex<ReplayState>>,
    case: &str,
    before_request: bool,
) -> Result<()> {
    let mut buffer = [0; 8192];
    let mut check = tokio::time::interval(std::time::Duration::from_millis(25));
    loop {
        let read = tokio::select! {
            read = io.read(&mut buffer) => read,
            _ = check.tick() => {
                let state = state.lock().await;
                ensure!(state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(), "Case ended while its admitted cleanup dependency remained open");
                if let Some(deadline) = state.async_cleanup_deadline(case) {
                    ensure!(tokio::time::Instant::now() < deadline,"Target dependency remained open after the engine lifecycle cleanup budget");
                }
                continue;
            }
        };
        match read {
            Ok(0) => {
                accept_peer_end(gate, state, case).await?;
                return Ok(());
            }
            Ok(_) => ensure!(
                before_request || gate.load(Ordering::Acquire),
                "Target sent another request while an admitted dependency was awaiting engine lifecycle stop"
            ),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                accept_peer_end(gate, state, case).await?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Writing the recorded failure and committing its delivery use separate tasks.
/// Retain an observed EOF only while those already claimed writes are committing;
/// an absent request or an unflushed cleanup prefix cannot authorize termination.
pub(in crate::replay) async fn accept_peer_end(
    gate: &AtomicBool,
    state: &Arc<Mutex<ReplayState>>,
    case: &str,
) -> Result<()> {
    let deadline = control::dependency_tail::deadline(state, case).await;
    loop {
        {
            let state = state.lock().await;
            ensure!(
                state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(),
                "Case ended before its admitted cleanup dependency terminated"
            );
            if let Some(deadline) = state.async_cleanup_deadline(case) {
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "Target dependency terminated after the engine lifecycle cleanup budget"
                );
            }
            state.arm_failure_cleanup_if_ready(case);
            if gate.load(Ordering::Acquire) {
                return Ok(());
            }
            ensure!(
                state.async_failure_delivery_pending(case),
                "Target terminated an admitted dependency before engine lifecycle stop"
            );
        }
        let deadline = deadline.context("async failure delivery has no common Case deadline")?;
        ensure!(
            tokio::time::Instant::now() < deadline,
            "Target termination preceded committed dependency failure before the common Case deadline"
        );
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + std::time::Duration::from_millis(1)).min(deadline),
        )
        .await;
    }
}

#[cfg(test)]
mod tests;
