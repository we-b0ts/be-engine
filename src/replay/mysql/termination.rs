//! Deliver recorded packet prefixes while independently observing transport termination.
use super::*;

pub(super) async fn deliver(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    matched: &MatchedExchange,
    control: &crate::dependency::termination::ConnectionControl,
    started: tokio::time::Instant,
    row_encoding: ResultRowEncoding,
    fast: bool,
) -> Result<()> {
    anyhow::ensure!(
        !matched.timing.outcome().termination().is_some_and(
            |termination| termination.scope == crate::dependency::TerminationScope::Stream
        ),
        "MySQL native termination cannot have stream scope"
    );
    let packets = prefix_packets(matched, row_encoding)?;
    let timing = matched.timing.for_replay(fast);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let deliver_prefix = deliver_prefix(&mut writer, matched, started, fast, packets);
    let observe = async {
        if matched.timing.outcome().is_server_terminated() {
            timing
                .await_server_deadline(&mut reader, started, 16 * 1024 * 1024)
                .await
        } else {
            timing
                .await_client_termination_at(&mut reader, started)
                .await?;
            Ok(Vec::new())
        }
    };
    let (_, pending) = tokio::try_join!(deliver_prefix, observe)?;
    matched.claim.wait_sequence_delivery().await?;
    anyhow::ensure!(
        pending.is_empty(),
        "Target pipelined another MySQL request before recorded server termination; native termination batch replay is unsupported"
    );
    if matched.timing.outcome().is_server_terminated() {
        timing
            .terminate_server_at(&mut writer, control, started)
            .await?;
    }
    Ok(())
}

pub(super) async fn deliver_prefix(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin + ?Sized),
    matched: &MatchedExchange,
    started: tokio::time::Instant,
    fast: bool,
    packets: Vec<(u64, Vec<u8>)>,
) -> Result<()> {
    use traffic_protocol_mysql::response_progress::{ResponseBoundary, ResponseProgress};
    let mut progress = ResponseProgress::new(&matched.record.command);
    let mut assembler = crate::mysql::wire::continuation::MysqlPacketAssembler::default();
    for (offset, raw) in packets {
        let packet = MysqlPacket {
            sequence_id: raw[3],
            payload: raw[4..].to_vec(),
        };
        let message = assembler.push(&packet)?;
        let boundary = message
            .as_deref()
            .and_then(|message| progress.observe(message));
        if boundary.is_some() {
            matched.claim.wait_sequence_delivery().await?;
        }
        if !fast {
            tokio::time::sleep_until(started + std::time::Duration::from_millis(offset)).await;
        }
        tokio::io::AsyncWriteExt::write_all(writer, &raw).await?;
        tokio::io::AsyncWriteExt::flush(writer).await?;
        if let Some(boundary) = boundary
            && let Some(sequence) = matched.claim.sequence()
        {
            let kind = match boundary {
                ResponseBoundary::Headers => traffic_replay::EventKind::ResponseHeaders,
                ResponseBoundary::Row => traffic_replay::EventKind::ResponsePart,
            };
            ensure!(
                sequence.reserved_kind() == Some(kind),
                "MySQL prefix output differs from its recorded boundary"
            );
            sequence.publish()?;
        }
    }
    Ok(())
}

/// Preserve only complete packets actually observed before the lifecycle or peer end.
pub(super) fn prefix_packets(
    matched: &MatchedExchange,
    row_encoding: ResultRowEncoding,
) -> Result<Vec<(u64, Vec<u8>)>> {
    anyhow::ensure!(
        matched.record.parse_warnings.is_empty() || matched.record.lifecycle_cleanup,
        "terminated MySQL exchange contains unsafe parse evidence"
    );
    let response = matched.record.response.materialize()?;
    if !response.wire_prefix.is_empty() {
        anyhow::ensure!(
            matched.record.command == matched.report.command
                && matched.record.sql.as_deref().map(normalize_sql)
                    == matched.report.sql.as_deref().map(normalize_sql)
                && matched.record.params == matched.report.params,
            "terminated MySQL packet prefixes require the recorded query shape and parameters"
        );
        anyhow::ensure!(
            matches!(
                (matched.record.command.as_str(), row_encoding),
                ("COM_QUERY" | "COM_STMT_PREPARE", ResultRowEncoding::Text)
                    | ("COM_STMT_EXECUTE", ResultRowEncoding::Binary)
            ),
            "terminated MySQL packet prefixes cannot cross text and binary command encodings"
        );
    }
    let mut previous = 0;
    let mut packets = Vec::with_capacity(response.wire_prefix.len());
    for prefix in &response.wire_prefix {
        anyhow::ensure!(
            !prefix.packet.truncated
                && prefix.offset_ms >= previous
                && prefix.offset_ms <= matched.record.duration_ms,
            "terminated MySQL response prefix has unsafe capture or timing"
        );
        previous = prefix.offset_ms;
        let raw = match prefix.packet.encoding.as_str() {
            "base64" => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(&prefix.packet.data)?
            }
            "utf8" => prefix.packet.data.as_bytes().to_vec(),
            _ => anyhow::bail!("unsupported MySQL response prefix encoding"),
        };
        anyhow::ensure!(
            raw.len() >= 4
                && u32::from_le_bytes([raw[0], raw[1], raw[2], 0]) as usize == raw.len() - 4,
            "terminated MySQL response prefix contains a partial packet"
        );
        packets.push((prefix.offset_ms, raw));
    }
    Ok(packets)
}
