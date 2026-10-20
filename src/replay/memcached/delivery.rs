//! Delay, contract materialization and successful Memcached delivery accounting.
use super::*;

pub(super) async fn deliver_memcached_exchange(
    reader: &mut MemcachedBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedMemcachedExchange,
    started: tokio::time::Instant,
) -> Result<bool> {
    if matched.timing.outcome().is_client_terminated()
        || matched.timing.outcome().is_server_terminated()
    {
        match deliver_termination(reader, matched, started).await {
            Ok(()) => {
                state.lock().await.memcached.complete_exchange(matched);
                if matched.timing.outcome().termination().is_some_and(|end| {
                    end.side == crate::dependency::TerminationSide::Server
                        && end.kind == crate::dependency::TerminationKind::Eof
                }) {
                    let mut probe = [0_u8; 1];
                    if !reader.buffer.is_empty()
                        || matches!(tokio::io::AsyncReadExt::read(reader.inner, &mut probe).await, Ok(count) if count > 0)
                    {
                        state.lock().await.memcached.fail_exchange(
                            matched,
                            "client sent another Memcached request after recorded server EOF"
                                .into(),
                        );
                        super::super::exchange::retain_connection(reader.inner).await;
                    }
                }
                return Ok(true);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .memcached
                    .fail_exchange(matched, error.to_string());
                super::super::exchange::retain_connection(reader.inner).await;
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

pub(super) fn validate_termination(record: &RecordedExchange) -> Result<()> {
    anyhow::ensure!(
        !record.outcome.termination().is_some_and(
            |termination| termination.scope == crate::dependency::TerminationScope::Stream
        ),
        "Memcached native termination cannot have stream scope"
    );
    if record.outcome.termination().is_some() && !record.response_frames.is_empty() {
        anyhow::ensure!(
            record.response_frame_offsets_ms.len() == record.response_frames.len(),
            "Memcached terminated prefix requires an offset for every delivered frame"
        );
        anyhow::ensure!(
            record
                .response_frame_offsets_ms
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
                && record
                    .response_frame_offsets_ms
                    .iter()
                    .all(|offset| *offset <= record.duration_ms),
            "Memcached response prefix has invalid delivery timing"
        );
    }
    Ok(())
}

async fn deliver_termination(
    buffered: &mut MemcachedBufferedReader<&mut TcpStream>,
    matched: &MatchedMemcachedExchange,
    started: tokio::time::Instant,
) -> Result<()> {
    anyhow::ensure!(
        buffered.buffer.is_empty(),
        "Target pipelined another Memcached request before recorded termination; native termination batch replay is unsupported"
    );
    let control = crate::dependency::termination::ConnectionControl::new(buffered.inner)?;
    let (mut reader, mut writer) = tokio::io::split(&mut *buffered.inner);
    let prefix = async {
        for (index, frame) in matched.response_frames.iter().enumerate() {
            if let Some(offset) = matched.response_frame_offsets_ms.get(index) {
                tokio::time::sleep_until(started + std::time::Duration::from_millis(*offset)).await;
            }
            writer.write_all(frame).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let observe = async {
        if matched.timing.outcome().is_server_terminated() {
            matched
                .timing
                .await_server_deadline(&mut reader, started, 64 * 1024 * 1024)
                .await
        } else {
            matched
                .timing
                .await_client_termination_at(&mut reader, started)
                .await?;
            Ok(Vec::new())
        }
    };
    let (_, pending) = tokio::try_join!(prefix, observe)?;
    anyhow::ensure!(
        pending.is_empty(),
        "Target pipelined another Memcached request before recorded server termination; native termination batch replay is unsupported"
    );
    if matched.timing.outcome().is_server_terminated() {
        matched
            .timing
            .terminate_server_at(&mut writer, &control, started)
            .await?;
    }
    Ok(())
}
