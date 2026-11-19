//! Ordered Redis response forwarding and delivery recording.
use super::*;
use std::collections::BTreeMap;

pub(super) async fn run_ordered_writer(
    client_write: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    mut output_rx: mpsc::Receiver<RedisOutput>,
    host: Arc<dyn CaptureHost>,
    context: ConnectionContext,
    connection_id: Uuid,
    termination: ConnectionTermination,
    client_control: ConnectionControl,
) -> Result<(u64, bool)> {
    let mut next_sequence = 1_u64;
    let mut buffered =
        BTreeMap::<u64, (Bytes, Option<(PendingRedisExchange, RedisFrameKind)>)>::new();
    let mut deferred_pushes = VecDeque::<QueuedPush>::new();
    let mut bytes = 0_u64;
    let mut client_open = true;
    let mut replay_safe = true;
    while let Some(output) = output_rx.recv().await {
        match output {
            RedisOutput::Sequenced(output) => {
                let SequencedRedisOutput {
                    sequence,
                    bytes: payload,
                    completion,
                } = *output;
                buffered.insert(sequence, (payload, completion));
                while let Some((payload, completion)) = buffered.remove(&next_sequence) {
                    if client_open {
                        let receipt = completion.as_ref().and_then(|(exchange, _)| {
                            exchange
                                .capture
                                .prepare_output(traffic_model::trace::OutputKind::End)
                        });
                        let (written, result) = write_response(&client_write, &payload).await;
                        bytes += written as u64;
                        match result {
                            Ok(()) => {
                                if let Some(receipt) = receipt {
                                    receipt.commit();
                                }
                                if let Some((exchange, response_kind)) = completion {
                                    record_exchange(
                                        connection_id,
                                        &context,
                                        exchange,
                                        response_kind,
                                        &payload,
                                        DependencyExchangeOutcome::Response,
                                    )
                                    .await?;
                                }
                            }
                            Err(error) if termination.observe_client_io_error(&error) => {
                                client_open = false;
                                if let Some((mut exchange, _)) = completion {
                                    if written > 0 {
                                        exchange.warnings.push("Redis short write prefix has no captured delivery timing".to_string());
                                    }
                                    replay_safe &= record_termination(
                                        connection_id,
                                        &context,
                                        exchange,
                                        &payload[..written],
                                        &termination,
                                        !host.is_degraded() && written == 0,
                                    )
                                    .await?;
                                }
                            }
                            Err(error) => return Err(error.into()),
                        }
                    } else if let Some((exchange, _)) = completion {
                        client_open = false;
                        replay_safe &= record_termination(
                            connection_id,
                            &context,
                            exchange,
                            b"",
                            &termination,
                            !host.is_degraded(),
                        )
                        .await?;
                    }
                    next_sequence += 1;
                }
                if buffered.is_empty() {
                    while let Some(push) = deferred_pushes.pop_front() {
                        if pubsub::write_push(
                            &client_write,
                            &termination,
                            &mut client_open,
                            &mut bytes,
                            &push.bytes,
                        )
                        .await?
                        {
                            push.capture.record().await?;
                        }
                    }
                }
            }
            RedisOutput::PubSubPush { push } => {
                if buffered.is_empty() {
                    if pubsub::write_push(
                        &client_write,
                        &termination,
                        &mut client_open,
                        &mut bytes,
                        &push.bytes,
                    )
                    .await?
                    {
                        push.capture.record().await?;
                    }
                } else {
                    deferred_pushes.push_back(push);
                }
            }
            RedisOutput::Terminated {
                exchanges,
                response,
                reset,
            } => {
                if !response.is_empty() && exchanges.is_empty() {
                    host.degrade(
                        "Redis response prefix arrived without a pending request".to_string(),
                    );
                    replay_safe = false;
                }
                let mut written = 0;
                let mut complete_delivery = true;
                if !response.is_empty() && client_open {
                    let (delivered, result) = write_response(&client_write, &response).await;
                    written = delivered;
                    bytes += written as u64;
                    match result {
                        Ok(()) => {}
                        Err(error) if termination.observe_client_io_error(&error) => {
                            complete_delivery = false;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                // EOF applies to the response direction immediately, even while the
                // request reader still owns an output sender. Never wait for it here.
                // Recorder cleanup has already closed the registered sockets.
                // It is not another peer FIN/RST, and repeating the shutdown
                // can turn an idle clean connection into a false capture error.
                if !termination.engine_stopped() {
                    let receipts: Vec<_> = exchanges
                        .iter()
                        .filter_map(|exchange| {
                            let (outcome, _) = termination.outcome_since(exchange.started)?;
                            let terminal = outcome.termination()?;
                            exchange.capture.prepare_output(
                                traffic_model::trace::OutputKind::Terminated {
                                    termination: terminal,
                                },
                            )
                        })
                        .collect();
                    let close = if reset {
                        client_control.reset()
                    } else {
                        client_control.shutdown_write()
                    };
                    // A client can reset after its request half closes, before
                    // this server end arrives. Closing that socket is idempotent;
                    // NotConnected supplies no new peer-termination evidence for
                    // the pending exchanges processed below.
                    if let Err(error) = close
                        && error.kind() != std::io::ErrorKind::NotConnected
                    {
                        return Err(error.into());
                    }
                    for receipt in receipts {
                        receipt.commit();
                    }
                }
                client_open = false;
                for (index, mut exchange) in exchanges.into_iter().enumerate() {
                    let timed_delivery = index != 0 || complete_delivery || written == 0;
                    if !timed_delivery {
                        exchange.warnings.push(
                            "Redis short write prefix has no captured delivery timing".to_string(),
                        );
                    }
                    replay_safe &= record_termination(
                        connection_id,
                        &context,
                        exchange,
                        if index == 0 {
                            &response[..written]
                        } else {
                            b""
                        },
                        &termination,
                        !host.is_degraded() && timed_delivery,
                    )
                    .await?;
                    next_sequence += 1;
                }
                // Responses behind an interrupted pipeline command cannot be sent
                // after the response direction has ended.
                for (_, (_, completion)) in std::mem::take(&mut buffered) {
                    if let Some((exchange, _)) = completion {
                        replay_safe &= record_termination(
                            connection_id,
                            &context,
                            exchange,
                            b"",
                            &termination,
                            !host.is_degraded(),
                        )
                        .await?;
                    }
                }
            }
        }
    }
    if !buffered.is_empty() {
        return Err(anyhow!("Redis response ordering ended with sequence gaps"));
    }
    if client_open {
        let _ = client_write.lock().await.shutdown().await;
    }
    Ok((bytes, replay_safe))
}

/// `write_all` discards its progress on an error. Keep the delivered prefix so
/// a client reset after a short write cannot become a fabricated empty response.
async fn write_response(
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    payload: &[u8],
) -> (usize, std::io::Result<()>) {
    let mut writer = writer.lock().await;
    write_payload(&mut *writer, payload).await
}

async fn write_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> (usize, std::io::Result<()>) {
    let mut written = 0;
    while written < payload.len() {
        match writer.write(&payload[written..]).await {
            Ok(0) => return (written, Err(std::io::ErrorKind::WriteZero.into())),
            Ok(bytes) => written += bytes,
            Err(error) => return (written, Err(error)),
        }
    }
    (written, Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn failed_short_write_keeps_the_delivered_prefix_length() {
        let (mut writer, mut peer) = tokio::io::duplex(2);
        let close = tokio::spawn(async move {
            let mut prefix = [0; 2];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"ab");
        });
        let (written, result) = write_payload(&mut writer, b"abcdef").await;
        close.await.unwrap();
        assert_eq!(written, 2);
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }
}
