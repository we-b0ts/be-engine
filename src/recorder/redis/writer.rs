//! Ordered Redis response forwarding and delivery recording.
use super::*;
use std::collections::BTreeMap;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_ordered_writer(
    client_write: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    mut output_rx: mpsc::Receiver<RedisOutput>,
    state: AppState,
    context: ConnectionContext,
    connection_id: Uuid,
    termination: ConnectionTermination,
    max_frame_bytes: usize,
    client_control: ConnectionControl,
    capture_health: Arc<ConnectionCaptureHealth>,
) -> Result<(u64, bool)> {
    let mut next_sequence = 1_u64;
    let mut buffered =
        BTreeMap::<u64, (Bytes, Option<(PendingRedisExchange, RedisFrameKind)>)>::new();
    let mut deferred_pushes = VecDeque::<Box<pubsub::CapturedPush>>::new();
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
                                .targets
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
                                        &state,
                                        connection_id,
                                        &context,
                                        exchange,
                                        response_kind,
                                        &payload,
                                        DependencyExchangeOutcome::Response,
                                        max_frame_bytes,
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
                                        &state,
                                        connection_id,
                                        &context,
                                        exchange,
                                        &payload[..written],
                                        &termination,
                                        !capture_health.is_degraded() && written == 0,
                                        max_frame_bytes,
                                    )
                                    .await?;
                                }
                            }
                            Err(error) => return Err(error.into()),
                        }
                    } else if let Some((exchange, _)) = completion {
                        client_open = false;
                        replay_safe &= record_termination(
                            &state,
                            connection_id,
                            &context,
                            exchange,
                            b"",
                            &termination,
                            !capture_health.is_degraded(),
                            max_frame_bytes,
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
                            push.record(&state).await?;
                        }
                    }
                }
            }
            RedisOutput::PubSubPush { capture } => {
                if buffered.is_empty() {
                    if pubsub::write_push(
                        &client_write,
                        &termination,
                        &mut client_open,
                        &mut bytes,
                        &capture.bytes,
                    )
                    .await?
                    {
                        capture.record(&state).await?;
                    }
                } else {
                    deferred_pushes.push_back(capture);
                }
            }
            RedisOutput::Terminated {
                exchanges,
                response,
                reset,
            } => {
                if !response.is_empty() && exchanges.is_empty() {
                    capture_health.activate(
                        &state,
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
                            exchange.targets.prepare_output(
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
                        &state,
                        connection_id,
                        &context,
                        exchange,
                        if index == 0 {
                            &response[..written]
                        } else {
                            b""
                        },
                        &termination,
                        !capture_health.is_degraded() && timed_delivery,
                        max_frame_bytes,
                    )
                    .await?;
                    next_sequence += 1;
                }
                // Responses behind an interrupted pipeline command cannot be sent
                // after the response direction has ended.
                for (_, (_, completion)) in std::mem::take(&mut buffered) {
                    if let Some((exchange, _)) = completion {
                        replay_safe &= record_termination(
                            &state,
                            connection_id,
                            &context,
                            exchange,
                            b"",
                            &termination,
                            !capture_health.is_degraded(),
                            max_frame_bytes,
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
    async fn disconnected_client_close_does_not_invent_peer_completion() {
        for (engine_stop, pending_request) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let temp = tempfile::tempdir().unwrap();
            let mut config = crate::AppConfig::default();
            config.recording.output_dir = temp.path().join("recordings");
            config.tls.ca_cert_path = temp.path().join("ca.pem");
            config.tls.ca_key_path = temp.path().join("ca-key.pem");
            let state = AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, accepted) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let _peer = client.unwrap();
            let stream = accepted.unwrap().0;
            let control = ConnectionControl::new(&stream).unwrap();
            control.reset().unwrap();
            assert_eq!(
                control.shutdown_write().unwrap_err().kind(),
                std::io::ErrorKind::NotConnected
            );
            let (_read, write) = stream.into_split();
            let termination = ConnectionTermination::default();
            if engine_stop {
                termination.observe_engine_stop();
            }
            let connection = Uuid::new_v4();
            let exchanges = if pending_request {
                let command = RedisCommand {
                    name: "GET".into(),
                    args: vec![b"key".to_vec()],
                };
                let targets = state.capture_dependency_request(
                    crate::recorder::request::DependencyRequest::Redis {
                        target_port: 6379,
                        command: &command.name,
                        args: &command.args,
                    },
                );
                targets.bind_protocol(crate::dependency::observation::ProtocolRef::connection(
                    "redis", connection, 1,
                ));
                vec![PendingRedisExchange {
                    targets,
                    sequence: 1,
                    recorded_args: command.args.clone(),
                    command,
                    session: RedisSession {
                        resp_version: 2,
                        database: 0,
                        username: None,
                        subscriptions: pubsub::Subscriptions::default(),
                    },
                    session_setup: false,
                    replay_safe: true,
                    warnings: Vec::new(),
                    cache_snapshot_rule: None,
                    cache_snapshot_key: None,
                    cache_snapshot_hit: false,
                    started: Instant::now(),
                    request_started_at: Utc::now(),
                    ended_at: None,
                }]
            } else {
                vec![]
            };
            let (tx, rx) = mpsc::channel(1);
            tx.send(RedisOutput::Terminated {
                exchanges,
                response: Bytes::new(),
                reset: false,
            })
            .await
            .unwrap();
            drop(tx);
            let context = ConnectionContext {
                client_addr: None,
                target_host: "redis.test".into(),
                target_port: 6379,
                target_addr: "127.0.0.1:6379".into(),
                upstream_addr: "127.0.0.1:6379".into(),
            };
            let health = Arc::new(ConnectionCaptureHealth::new(
                connection,
                "redis",
                None,
                context.target_addr.clone(),
            ));
            let result = run_ordered_writer(
                Arc::new(Mutex::new(write)),
                rx,
                state.clone(),
                context,
                connection,
                termination.clone(),
                4096,
                control,
                health,
            )
            .await;
            assert_eq!(result.unwrap(), (0, !pending_request));
            assert!(termination.peer_snapshot().is_none());
            if pending_request {
                state.recorder().flush_traffic().await.unwrap();
                let raw = crate::recorder::test_io::read_to_string(
                    state.recorder().run_dir.join("traffic.jsonl"),
                )
                .await
                .unwrap();
                let exchange = raw
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .find(|row| row["event_type"] == "redis_exchange")
                    .unwrap();
                assert_eq!(exchange["replay_safe"], false);
                assert_eq!(exchange["outcome"], "response");
                assert!(!exchange["parse_warnings"].as_array().unwrap().is_empty());
            }
        }
    }

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
