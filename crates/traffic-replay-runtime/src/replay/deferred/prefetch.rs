//! One bounded immutable read ahead, supervised by the Replay runtime.
use super::*;

pub(in crate::replay) async fn enqueue<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    case_id: Option<&str>,
) -> Result<bool> {
    let state = state.lock().await;
    let Some(deferred) = &state.deferred else {
        return Ok(false);
    };
    let id = case_id.context("prefetch requires case_id")?;
    let case = state.cases.get(id).context("unknown prefetch case")?;
    let Some(inventory) = deferred.files.get(id) else {
        return Ok(false);
    };
    if case.status != ReplayCaseStatus::Pending
        || inventory.source_bytes > deferred.cache_bytes as u64
        || deferred.cache_bytes == 0
    {
        return Ok(false);
    }
    Ok(deferred
        .prefetch_tx
        .try_send((case.dependencies_path.clone(), inventory.index.clone()))
        .is_ok())
}

pub(in crate::replay) async fn run<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
) -> Result<()> {
    let Some(deferred) = state.lock().await.deferred.clone() else {
        return std::future::pending().await;
    };
    let mut receiver = deferred.prefetch_rx.lock().await;
    while let Some((path, index)) = receiver.recv().await {
        let reader = deferred.reader.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            scoped_read::read(&path, &index, &reader)?;
            Ok(())
        })
        .await
        .context("dependency prefetch worker failed")?;
        if let Err(error) = result {
            warn!(%error, "dependency prefetch failed; Case preparation will retry");
        }
    }
    Ok(())
}
