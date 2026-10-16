//! Delay, contract materialization and successful Memcached delivery accounting.
use super::*;

pub(super) async fn deliver_memcached_exchange(
    reader: &mut MemcachedBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedMemcachedExchange,
) -> Result<bool> {
    if matched.timing.outcome().is_client_terminated() {
        let result = if reader.buffer.is_empty() {
            matched
                .timing
                .await_client_termination(&mut reader.inner)
                .await
                .map(|_| ())
        } else {
            Err(anyhow!(
                "client sent another Memcached request instead of terminating the connection"
            ))
        };
        match result {
            Ok(()) => {
                state.lock().await.memcached.complete_exchange(matched);
                return Ok(true);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .memcached
                    .fail_exchange(matched, error.to_string());
                return Err(error);
            }
        }
    }

    matched.timing.delay_response().await;
    let prepared = {
        let replay = state.lock().await;
        contracts::materialize_response(&replay, matched)
    };
    let (frames, decision) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            state
                .lock()
                .await
                .memcached
                .fail_exchange(matched, format!("response contract failed: {error:#}"));
            return Err(error);
        }
    };
    for response in &frames {
        if let Err(error) = reader.inner.write_all(response).await {
            state.lock().await.memcached.fail_exchange(
                matched,
                format!("failed to deliver recorded Memcached response: {error}"),
            );
            return Err(error.into());
        }
    }
    let mut replay = state.lock().await;
    if let Some(policy) = replay.replay_policy.as_mut() {
        policy.commit(matched.report.case_id.as_deref(), decision);
    }
    replay.memcached.complete_exchange(matched);
    Ok(false)
}
