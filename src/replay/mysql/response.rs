//! Native output plans use the shared Replay delivery transaction.
use super::*;
pub(in crate::replay) use traffic_protocol_mysql::response::*;

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
    let mut output = traffic_protocol_mysql::output::response(response, row_encoding, status_flags);
    traffic_replay::output::deliver(stream, &mut output, sequence).await
}

pub(in crate::replay) async fn write_stmt_prepare_ok(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    statement_id: u32,
    metadata: &StatementMetadata,
    status_flags: u16,
) -> Result<()> {
    let mut output = traffic_protocol_mysql::output::prepare(statement_id, metadata, status_flags);
    traffic_replay::output::deliver(stream, &mut output, None).await
}

pub(in crate::replay) async fn write_packet_and_flush(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    packet: MysqlPacket,
) -> Result<()> {
    let mut output = traffic_protocol_mysql::output::packet(packet);
    traffic_replay::output::deliver(stream, &mut output, None).await
}
