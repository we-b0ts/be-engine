pub(in crate::replay) async fn write_response(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    response: &RecordedMysqlResponse,
    row_encoding: ResultRowEncoding,
    status_flags: u16,
) -> Result<()> {
    write_response_ordered(stream, response, row_encoding, status_flags, None).await
}

pub(super) async fn write_response_ordered(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    response: &RecordedMysqlResponse,
    row_encoding: ResultRowEncoding,
    status_flags: u16,
    sequence: Option<&traffic_replay::SequenceClaim>,
) -> Result<()> {
    let kind = match response.status.as_str() {
        "resultset" => "resultset",
        "ok" => "ok",
        _ => "error",
    };
    super::wire_diagnostics::response_kind(kind, Some(status_flags));
    match response.status.as_str() {
        "resultset" => {
            write_resultset_ordered(
                stream,
                &response.columns,
                &response.rows,
                row_encoding,
                status_flags,
                sequence,
            )
            .await
        }
        "ok" => {
            write_packet_and_flush(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: ok_payload_with_status(
                        response.affected_rows.unwrap_or_default(),
                        response.last_insert_id.unwrap_or_default(),
                        status_flags,
                    ),
                },
            )
            .await
        }
        "error" => {
            write_packet_and_flush(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: err_payload(
                        response.error_code.unwrap_or(1105),
                        response
                            .error_message
                            .as_deref()
                            .unwrap_or("recorded MySQL dependency error"),
                    ),
                },
            )
            .await
        }
        other => {
            write_packet_and_flush(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: err_payload(
                        1105,
                        &format!("unsupported recorded MySQL response status {other}"),
                    ),
                },
            )
            .await
        }
    }
}

pub(in crate::replay) async fn write_stmt_prepare_ok(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    statement_id: u32,
    metadata: &StatementMetadata,
    status_flags: u16,
) -> Result<()> {
    super::wire_diagnostics::response_kind("prepare_ok_and_metadata", Some(status_flags));
    if !super::wire_diagnostics::active()
        && let Some(bytes) = metadata.encoded(statement_id, status_flags)
    {
        stream
            .write_all(&bytes)
            .await
            .context("failed to write MySQL prepare metadata")?;
        return flush_response(stream, "failed to flush MySQL prepare metadata").await;
    }

    let mut sequence_id = 1_u8;
    for (payload, _) in
        traffic_protocol_mysql::prepare::prepare_messages(metadata, statement_id, status_flags)
    {
        sequence_id = write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload,
            },
        )
        .await?;
    }
    // TLS may buffer writes. Deliver the complete metadata before waiting for EXECUTE.
    flush_response(stream, "failed to flush MySQL prepare metadata").await
}

async fn write_resultset_ordered(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    columns: &[RecordedMysqlColumn],
    rows: &[Vec<RecordedMysqlValue>],
    row_encoding: ResultRowEncoding,
    status_flags: u16,
    sequence: Option<&traffic_replay::SequenceClaim>,
) -> Result<()> {
    if columns.is_empty() {
        return write_packet_and_flush(
            stream,
            MysqlPacket {
                sequence_id: 1,
                payload: err_payload(1105, "recorded resultset has no column metadata"),
            },
        )
        .await;
    }

    let mut sequence_id = 1_u8;
    sequence_id = write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: lenenc_int(columns.len() as u64),
        },
    )
    .await?;

    for column in columns {
        sequence_id = write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: column_definition_payload(column),
            },
        )
        .await?;
    }
    sequence_id = write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: eof_payload_with_status(status_flags),
        },
    )
    .await?;

    // The prepared Source trace decides whether this response exposes logical
    // row boundaries. Ordinary one-message responses retain one wire receipt.
    let rows_sequence = sequence
        .filter(|claim| claim.reserved_kind() == Some(traffic_replay::EventKind::ResponseHeaders));
    if let Some(claim) = rows_sequence {
        flush_response(stream, "failed to flush MySQL result metadata").await?;
        claim.publish()?;
    }
    let mut next_row = 0;
    while next_row < rows.len() {
        let count = if let Some(claim) = rows_sequence {
            claim
                .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(30))
                .await?;
            let count = claim.consecutive_parts(rows.len() - next_row);
            ensure!(count > 0, "MySQL row has no recorded output boundary");
            count
        } else {
            rows.len() - next_row
        };
        for row in &rows[next_row..next_row + count] {
            let payload = match row_encoding {
                ResultRowEncoding::Text => text_row_payload(row),
                ResultRowEncoding::Binary => binary_row_payload(columns, row),
            }?;
            sequence_id = write_packet(
                stream,
                MysqlPacket {
                    sequence_id,
                    payload,
                },
            )
            .await?;
        }
        if let Some(claim) = rows_sequence {
            flush_response(stream, "failed to flush MySQL result rows").await?;
            claim.publish_parts(count)?;
        }
        next_row += count;
    }
    if let Some(claim) = rows_sequence {
        claim
            .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(30))
            .await?;
        ensure!(
            claim.reserved_kind() == Some(traffic_replay::EventKind::ResponseEnd),
            "MySQL result has remaining recorded rows"
        );
    }
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: eof_payload_with_status(status_flags),
        },
    )
    .await?;
    // TLS may accept writes into its buffer without sending every packet.
    // The sibling write_stmt_prepare_ok flushes for the same reason; without
    // this flush, large resultsets (e.g. 316-column JOINs) stay buffered in
    // the rustls layer and never reach the target, which then blocks waiting
    // for the response until its request timeout. Small resultsets sometimes
    // slipped through because a single TLS record auto-flushed, but any
    // multi-record resultset reliably deadlocks.
    flush_response(stream, "failed to flush MySQL resultset").await
}

pub(in crate::replay) async fn write_packet(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    packet: MysqlPacket,
) -> Result<u8> {
    let result = crate::mysql::wire::continuation::write_message(stream, &packet).await;
    super::wire_diagnostics::response(&packet, result.as_ref().ok().copied());
    result.context("failed to write MySQL replay message")
}

pub(in crate::replay) async fn write_packet_and_flush(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    packet: MysqlPacket,
) -> Result<()> {
    write_packet(stream, packet).await?;
    flush_response(stream, "failed to flush MySQL replay packet").await
}

async fn flush_response(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    context: &'static str,
) -> Result<()> {
    let result = stream.flush().await;
    super::wire_diagnostics::flushed(result.is_ok());
    result.context(context)
}

use super::*;
pub(in crate::replay) use traffic_protocol_mysql::response::*;
