use crate::dependency::termination::ObservedTermination;
use std::collections::VecDeque;
use std::time::Instant;

use anyhow::{Result, bail, ensure};

use crate::DependencyExchangeOutcome;
use crate::mysql::wire::continuation::MysqlPacketAssembler;
use crate::mysql::wire::{ClientCommand, MysqlPacket};
use crate::recorder::{MysqlExchangeEvent, MysqlResponseEvent};

use super::response::MysqlResponseTracker;
use super::semantic::{MysqlExchangeContext, MysqlSemanticTracker};
use traffic_protocol_mysql::response_progress::{ResponseBoundary, ResponseProgress};

const MAX_PENDING_QUERIES: usize = 64;
const MAX_PENDING_QUERY_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct MysqlQueryTracker {
    response: MysqlResponseTracker,
    semantic: MysqlSemanticTracker,
    pending_requests: VecDeque<PendingRequest>,
    pending_query_bytes: usize,
    server_message: MysqlPacketAssembler,
    output: Option<(u64, ResponseBoundary)>,
}

struct PendingRequest {
    query_sequence: u64,
    payload_bytes: usize,
    started: Instant,
    progress: ResponseProgress,
}

#[derive(Default)]
pub(super) struct MysqlQueryCompletion {
    response: Option<MysqlResponseEvent>,
    exchange: Option<MysqlExchangeEvent>,
    started: Option<Instant>,
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
            pending_requests: VecDeque::new(),
            pending_query_bytes: 0,
            server_message: MysqlPacketAssembler::default(),
            output: None,
        }
    }

    pub(super) fn database(&self) -> Option<&str> {
        self.semantic.database()
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending_requests.len()
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
    ) -> Result<()> {
        self.ensure_aligned()?;
        ensure!(
            self.pending_requests.len() < MAX_PENDING_QUERIES,
            "MySQL connection exceeded the {MAX_PENDING_QUERIES}-request pending FIFO limit"
        );
        let pending_query_bytes = self
            .pending_query_bytes
            .checked_add(packet.payload.len())
            .ok_or_else(|| anyhow::anyhow!("MySQL pending request byte count overflowed"))?;
        ensure!(
            pending_query_bytes <= MAX_PENDING_QUERY_BYTES,
            "MySQL connection exceeded the {MAX_PENDING_QUERY_BYTES}-byte pending request limit"
        );

        self.response.start_query(
            connection_id,
            query_sequence,
            command.command_name.clone(),
            client_addr.clone(),
        );
        self.semantic
            .start_query(connection_id, query_sequence, command, packet, client_addr);
        self.pending_requests.push_back(PendingRequest {
            query_sequence,
            payload_bytes: packet.payload.len(),
            progress: ResponseProgress::new(&command.command_name),
            started: self
                .semantic
                .pending_started_at()
                .expect("started MySQL semantic exchange"),
        });
        self.pending_query_bytes = pending_query_bytes;
        self.ensure_aligned()?;
        Ok(())
    }

    pub(super) fn observe_no_response_command(
        &mut self,
        command: &ClientCommand,
        packet: &MysqlPacket,
    ) {
        self.semantic.observe_no_response_command(command, packet);
    }

    pub(super) fn observe_server_packet(
        &mut self,
        packet: &MysqlPacket,
    ) -> Result<MysqlQueryCompletion> {
        let message = self.server_message.push(packet)?;
        self.output = message.as_deref().and_then(|message| {
            let pending = self.pending_requests.front_mut()?;
            Some((pending.query_sequence, pending.progress.observe(message)?))
        });
        if let Some(message) = &message {
            self.semantic.observe_packet(message);
        }
        let response = self.response.observe_packet(packet, message.as_deref());
        let exchange = response
            .as_ref()
            .and_then(|response| self.semantic.finish_from_response(response));
        self.complete(response, exchange)
    }

    pub(super) fn observe_delivery(&mut self, packet: &MysqlPacket) {
        self.semantic.observe_delivery(packet);
    }

    pub(super) fn take_output(&mut self) -> Option<(u64, ResponseBoundary)> {
        self.output.take()
    }

    pub(super) fn finish_active(&mut self, status: &str) -> Result<MysqlQueryCompletion> {
        if let Err(error) = self.server_message.finish() {
            self.semantic.observe_parse_warning(error.to_string());
        }
        let response = self.response.finish_active(status);
        let exchange = match response.as_ref() {
            Some(response) if !matches!(status, "client_terminated" | "server_terminated") => {
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
        self.complete(response, exchange)
    }

    pub(super) fn finish_all(&mut self, status: &str) -> Result<Vec<MysqlQueryCompletion>> {
        let mut completions = Vec::with_capacity(self.pending_requests.len());
        while !self.pending_requests.is_empty() {
            completions.push(self.finish_active(status)?);
        }
        self.ensure_aligned()?;
        Ok(completions)
    }

    fn complete(
        &mut self,
        response: Option<MysqlResponseEvent>,
        exchange: Option<MysqlExchangeEvent>,
    ) -> Result<MysqlQueryCompletion> {
        let mut completion = MysqlQueryCompletion::new(response, exchange);
        let (response_sequence, exchange_sequence) = completion.sequences();
        match (response_sequence, exchange_sequence) {
            (None, None) => {}
            (Some(response_sequence), Some(exchange_sequence))
                if response_sequence == exchange_sequence =>
            {
                let pending = self
                    .pending_requests
                    .pop_front()
                    .ok_or_else(|| anyhow::anyhow!("MySQL completion has no pending request"))?;
                completion.started = Some(pending.started);
                ensure!(
                    pending.query_sequence == response_sequence,
                    "MySQL FIFO sequence mismatch: pending={}, response={response_sequence}",
                    pending.query_sequence
                );
                self.pending_query_bytes = self
                    .pending_query_bytes
                    .checked_sub(pending.payload_bytes)
                    .ok_or_else(|| anyhow::anyhow!("MySQL pending request bytes underflowed"))?;
            }
            (Some(response_sequence), Some(exchange_sequence)) => bail!(
                "MySQL response/exchange sequence mismatch: response={response_sequence}, exchange={exchange_sequence}"
            ),
            (response_sequence, exchange_sequence) => bail!(
                "MySQL response/exchange FIFO diverged: response={response_sequence:?}, exchange={exchange_sequence:?}"
            ),
        }
        self.ensure_aligned()?;
        Ok(completion)
    }

    fn ensure_aligned(&self) -> Result<()> {
        ensure!(
            self.response.pending_len() == self.pending_requests.len()
                && self.semantic.pending_len() == self.pending_requests.len(),
            "MySQL pending FIFO diverged: requests={}, responses={}, exchanges={}",
            self.pending_requests.len(),
            self.response.pending_len(),
            self.semantic.pending_len()
        );
        Ok(())
    }
}

impl MysqlQueryCompletion {
    fn new(response: Option<MysqlResponseEvent>, exchange: Option<MysqlExchangeEvent>) -> Self {
        Self {
            response,
            exchange,
            started: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.response.is_none() && self.exchange.is_none()
    }

    pub(super) fn mark_delivered(&mut self) {
        if let Some(exchange) = self.exchange.as_mut() {
            exchange.response.wire_prefix.clear();
        }
    }

    pub(super) fn mark_terminated(&mut self, observed: ObservedTermination) {
        if self.started.is_some_and(|started| observed.at < started) {
            self.mark_capture_error("MySQL request began after the recorded termination; post-terminal capture is unsupported");
            return;
        }
        self.mark_client_terminated();
        if let Some(exchange) = self.exchange.as_mut() {
            exchange.outcome = DependencyExchangeOutcome::Terminated(observed.termination);
            exchange.timestamp = crate::dependency::termination::observed_wall_time(observed.at);
            if exchange
                .response
                .wire_prefix
                .iter()
                .any(|prefix| prefix.packet.truncated)
            {
                exchange
                    .parse_warnings
                    .push("delivered MySQL packet prefix exceeds recording limit".into());
            }
            exchange.response.status = if exchange.outcome.is_server_terminated() {
                "server_terminated"
            } else {
                "client_terminated"
            }
            .into();
            if let Some(started) = self.started {
                exchange.duration_ms = observed.at.duration_since(started).as_millis();
            }
            if exchange
                .response
                .wire_prefix
                .iter()
                .any(|prefix| prefix.offset_ms > exchange.duration_ms)
            {
                exchange.parse_warnings.push(
                    "bidirectional half-close sequence requires multiple termination observations"
                        .into(),
                );
            }
        }
    }

    pub(super) fn mark_capture_error(&mut self, reason: &str) {
        if let Some(exchange) = self.exchange.as_mut() {
            exchange.parse_warnings.push(reason.to_owned());
        }
    }

    pub(super) fn mark_engine_cleanup(&mut self) {
        if let Some(exchange) = self.exchange.as_mut() {
            exchange
                .parse_warnings
                .push("engine cleanup interrupted MySQL capture".into());
        }
    }

    pub(super) fn mark_unsupported_batch(&mut self) {
        if let Some(exchange) = self.exchange.as_mut() {
            exchange.parse_warnings.push("multiple in-flight MySQL commands share a termination; batch replay is unsupported".into());
        }
    }

    pub(super) fn reject_partial_write(&mut self) {
        if let Some(exchange) = self.exchange.as_mut() {
            exchange
                .parse_warnings
                .push("MySQL response write failed after an unknown delivery prefix".into());
        }
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
    use crate::mysql::wire::parse_client_command;

    #[test]
    fn completed_response_is_detached_before_the_next_query_starts() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());

        let first = query_packet("SET character_set_results = NULL");
        let first_command = parse_client_command(&first).unwrap();
        tracker
            .start_query(uuid::Uuid::nil(), 5, &first_command, &first, None)
            .unwrap();

        let ok = ok_packet();
        let first_completion = tracker.observe_server_packet(&ok).unwrap();
        assert_eq!(first_completion.sequences(), (Some(5), Some(5)));

        let second = query_packet("SET autocommit=1");
        let second_command = parse_client_command(&second).unwrap();
        tracker
            .start_query(uuid::Uuid::nil(), 6, &second_command, &second, None)
            .unwrap();

        let second_completion = tracker.observe_server_packet(&ok).unwrap();
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
        tracker
            .start_query(uuid::Uuid::nil(), 1, &command, &query, None)
            .unwrap();

        let ok = ok_packet();
        let mut completion = tracker.observe_server_packet(&ok).unwrap();
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

    #[test]
    fn consecutive_query_and_ping_complete_in_fifo_order() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());
        let query = query_packet("SELECT 2");
        let query_command = parse_client_command(&query).unwrap();
        tracker
            .start_query(uuid::Uuid::nil(), 10, &query_command, &query, None)
            .unwrap();
        let ping = MysqlPacket {
            sequence_id: 0,
            payload: vec![0x0e],
        };
        let ping_command = parse_client_command(&ping).unwrap();
        tracker
            .start_query(uuid::Uuid::nil(), 11, &ping_command, &ping, None)
            .unwrap();

        for packet in [
            server_packet(1, &[1]),
            server_packet(2, b"column"),
            server_packet(3, &[0xfe, 0, 0, 0, 0]),
            server_packet(4, &[1, b'2']),
        ] {
            assert!(tracker.observe_server_packet(&packet).unwrap().is_empty());
        }
        let eof = server_packet(5, &[0xfe, 0, 0, 0, 0]);
        let query_completion = tracker.observe_server_packet(&eof).unwrap();
        let (_, query_exchange) = query_completion.into_parts();
        let query_exchange = query_exchange.unwrap();
        assert_eq!(query_exchange.query_sequence, 10);
        assert_eq!(query_exchange.command, "COM_QUERY");
        assert_eq!(query_exchange.sql.as_deref(), Some("SELECT 2"));
        assert_eq!(query_exchange.response.status, "resultset");

        let ok = ok_packet();
        let ping_completion = tracker.observe_server_packet(&ok).unwrap();
        let (_, ping_exchange) = ping_completion.into_parts();
        let ping_exchange = ping_exchange.unwrap();
        assert_eq!(ping_exchange.query_sequence, 11);
        assert_eq!(ping_exchange.command, "COM_PING");
        assert!(ping_exchange.sql.is_none());
        assert_eq!(ping_exchange.response.status, "ok");
    }

    #[test]
    fn no_response_command_does_not_flush_pending_query() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());
        let query = query_packet("SELECT business_value");
        let query_command = parse_client_command(&query).unwrap();
        tracker
            .start_query(uuid::Uuid::nil(), 20, &query_command, &query, None)
            .unwrap();
        let close = MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x19], 7_u32.to_le_bytes().to_vec()].concat(),
        };
        let close_command = parse_client_command(&close).unwrap();

        tracker.observe_no_response_command(&close_command, &close);
        let ok = ok_packet();
        let completion = tracker.observe_server_packet(&ok).unwrap();
        assert_eq!(completion.sequences(), (Some(20), Some(20)));
    }

    #[test]
    fn connection_termination_finishes_every_pending_query_in_order() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());
        for (sequence, sql) in [(30, "SELECT first"), (31, "SELECT second")] {
            let query = query_packet(sql);
            let command = parse_client_command(&query).unwrap();
            tracker
                .start_query(uuid::Uuid::nil(), sequence, &command, &query, None)
                .unwrap();
        }

        let completions = tracker.finish_all("client_terminated").unwrap();
        assert_eq!(completions.len(), 2);
        assert_eq!(completions[0].sequences(), (Some(30), Some(30)));
        assert_eq!(completions[1].sequences(), (Some(31), Some(31)));
        for completion in completions {
            let (_, exchange) = completion.into_parts();
            let exchange = exchange.unwrap();
            assert_eq!(
                exchange.outcome,
                DependencyExchangeOutcome::ClientTerminated
            );
        }
    }

    #[test]
    fn pending_fifo_has_an_explicit_request_limit() {
        let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());
        let ping = MysqlPacket {
            sequence_id: 0,
            payload: vec![0x0e],
        };
        let command = parse_client_command(&ping).unwrap();
        for sequence in 1..=MAX_PENDING_QUERIES as u64 {
            tracker
                .start_query(uuid::Uuid::nil(), sequence, &command, &ping, None)
                .unwrap();
        }

        let error = tracker
            .start_query(
                uuid::Uuid::nil(),
                MAX_PENDING_QUERIES as u64 + 1,
                &command,
                &ping,
                None,
            )
            .expect_err("the pending FIFO limit must reject another request");
        assert!(error.to_string().contains("pending FIFO limit"));
    }

    fn query_packet(sql: &str) -> MysqlPacket {
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
        }
    }

    fn server_packet(sequence_id: u8, payload: &[u8]) -> MysqlPacket {
        MysqlPacket {
            sequence_id,
            payload: payload.to_vec(),
        }
    }

    fn ok_packet() -> MysqlPacket {
        MysqlPacket {
            sequence_id: 1,
            payload: vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        }
    }
}
