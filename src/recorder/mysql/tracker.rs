use crate::DependencyExchangeOutcome;
use crate::mysql::wire::{ClientCommand, MysqlPacket, ServerPacketInfo};
use crate::recorder::{MysqlExchangeEvent, MysqlResponseEvent, ProcessInfo};

use super::response::MysqlResponseTracker;
use super::semantic::{MysqlExchangeContext, MysqlSemanticTracker};

pub(super) struct MysqlQueryTracker {
    response: MysqlResponseTracker,
    semantic: MysqlSemanticTracker,
}

#[derive(Default)]
pub(super) struct MysqlQueryCompletion {
    response: Option<MysqlResponseEvent>,
    exchange: Option<MysqlExchangeEvent>,
}

impl MysqlQueryTracker {
    pub(super) fn new(
        max_body_bytes: usize,
        record_raw_packets: bool,
        context: MysqlExchangeContext,
    ) -> Self {
        Self {
            response: MysqlResponseTracker::new(max_body_bytes, record_raw_packets),
            semantic: MysqlSemanticTracker::new(max_body_bytes, context),
        }
    }

    pub(super) fn database(&self) -> Option<&str> {
        self.semantic.database()
    }

    pub(super) fn prepared_sql_for_packet(&self, packet: &MysqlPacket) -> Option<&str> {
        self.semantic.prepared_sql_for_packet(packet)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn start_query(
        &mut self,
        connection_id: uuid::Uuid,
        query_sequence: u64,
        command: &ClientCommand,
        packet: &MysqlPacket,
        client_addr: Option<String>,
        client_process: Option<ProcessInfo>,
    ) -> MysqlQueryCompletion {
        let response = self.response.start_query(
            connection_id,
            query_sequence,
            command.command_name.clone(),
            client_addr.clone(),
            client_process.clone(),
        );
        let exchange = self.semantic.start_query(
            connection_id,
            query_sequence,
            command,
            packet,
            client_addr,
            client_process,
        );
        MysqlQueryCompletion::new(response, exchange)
    }

    pub(super) fn observe_no_response_command(
        &mut self,
        command: &ClientCommand,
        packet: &MysqlPacket,
        closes_connection: bool,
    ) -> MysqlQueryCompletion {
        let fallback_status = if closes_connection {
            "client_terminated"
        } else {
            "incomplete"
        };
        let response = self.response.finish_active(fallback_status);
        let exchange = if closes_connection {
            self.semantic
                .finish_active(fallback_status, None, None, None)
        } else {
            self.semantic.observe_no_response_command(command, packet)
        };
        MysqlQueryCompletion::new(response, exchange)
    }

    pub(super) fn observe_server_packet(
        &mut self,
        packet: &MysqlPacket,
        packet_info: ServerPacketInfo,
    ) -> MysqlQueryCompletion {
        self.semantic.observe_packet(packet);
        let response = self.response.observe_packet(packet, packet_info);
        let exchange = response
            .as_ref()
            .and_then(|response| self.semantic.finish_from_response(response));
        MysqlQueryCompletion::new(response, exchange)
    }

    pub(super) fn finish_active(&mut self, status: &str) -> MysqlQueryCompletion {
        let response = self.response.finish_active(status);
        let exchange = match response.as_ref() {
            Some(response) if status != "client_terminated" => {
                self.semantic.finish_from_response(response)
            }
            Some(response) => self.semantic.finish_active(
                status,
                response.error_code,
                response.error_message.clone(),
                Some(response.duration_ms),
            ),
            None => self.semantic.finish_active(status, None, None, None),
        };
        MysqlQueryCompletion::new(response, exchange)
    }
}

impl MysqlQueryCompletion {
    fn new(response: Option<MysqlResponseEvent>, exchange: Option<MysqlExchangeEvent>) -> Self {
        Self { response, exchange }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.response.is_none() && self.exchange.is_none()
    }

    pub(super) fn mark_client_terminated(&mut self) {
        let Some(exchange) = self.exchange.as_mut() else {
            return;
        };
        exchange.outcome = DependencyExchangeOutcome::ClientTerminated;
        exchange.response.status = "client_terminated".to_string();
        exchange.response.error_code = None;
        exchange.response.error_message = None;
        exchange.response.affected_rows = None;
        exchange.response.last_insert_id = None;
        exchange.response.columns.clear();
        exchange.response.rows.clear();
        exchange.response.row_count = 0;
        exchange.response.rows_truncated = false;
    }

    pub(super) fn sequences(&self) -> (Option<u64>, Option<u64>) {
        (
            self.response
                .as_ref()
                .map(|response| response.query_sequence),
            self.exchange
                .as_ref()
                .map(|exchange| exchange.query_sequence),
        )
    }

    pub(super) fn into_parts(self) -> (Option<MysqlResponseEvent>, Option<MysqlExchangeEvent>) {
        (self.response, self.exchange)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mysql::wire::{parse_client_command, parse_server_packet};

    #[test]
    fn completed_response_is_detached_before_the_next_query_starts() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());

        let first = query_packet("SET character_set_results = NULL");
        let first_command = parse_client_command(&first).unwrap();
        assert!(
            tracker
                .start_query(uuid::Uuid::nil(), 5, &first_command, &first, None, None,)
                .is_empty()
        );

        let ok = ok_packet();
        let first_completion = tracker.observe_server_packet(&ok, parse_server_packet(&ok));
        assert_eq!(first_completion.sequences(), (Some(5), Some(5)));

        let second = query_packet("SET autocommit=1");
        let second_command = parse_client_command(&second).unwrap();
        assert!(
            tracker
                .start_query(uuid::Uuid::nil(), 6, &second_command, &second, None, None,)
                .is_empty(),
            "the completed first exchange must not be flushed as incomplete"
        );

        let second_completion = tracker.observe_server_packet(&ok, parse_server_packet(&ok));
        let (response, exchange) = second_completion.into_parts();
        assert_eq!(response.unwrap().query_sequence, 6);
        let exchange = exchange.unwrap();
        assert_eq!(exchange.query_sequence, 6);
        assert_eq!(exchange.response.status, "ok");
        assert_eq!(exchange.outcome, DependencyExchangeOutcome::Response);
    }

    #[test]
    fn completed_response_can_be_reclassified_when_the_client_terminates() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());
        let query = query_packet("SELECT 1");
        let command = parse_client_command(&query).unwrap();
        tracker.start_query(uuid::Uuid::nil(), 1, &command, &query, None, None);

        let ok = ok_packet();
        let mut completion = tracker.observe_server_packet(&ok, parse_server_packet(&ok));
        completion.mark_client_terminated();

        let (response, exchange) = completion.into_parts();
        assert_eq!(response.unwrap().status, "ok");
        let exchange = exchange.unwrap();
        assert_eq!(
            exchange.outcome,
            DependencyExchangeOutcome::ClientTerminated
        );
        assert_eq!(exchange.response.status, "client_terminated");
        assert!(exchange.response.affected_rows.is_none());
    }

    fn query_packet(sql: &str) -> MysqlPacket {
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
        }
    }

    fn ok_packet() -> MysqlPacket {
        MysqlPacket {
            sequence_id: 1,
            payload: vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        }
    }
}
