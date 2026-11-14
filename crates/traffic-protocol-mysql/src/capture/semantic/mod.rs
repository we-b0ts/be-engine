use std::collections::VecDeque;
use std::time::Instant;

use chrono::Utc;
#[cfg(test)]
use serde_json::Value;
use uuid::Uuid;

use crate::events::{MysqlExchangeEvent, MysqlResponseEvent};
use crate::semantic::MysqlWirePrefixPacket;
use crate::{ClientCommand, MysqlPacket};
use traffic_model::DependencyExchangeOutcome;
use traffic_model::capture::capture_body;

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::semantic::*;
use crate::semantic::{SemanticRequest, SemanticSession};
#[cfg(test)]
use crate::types::*;

const MAX_TERMINATION_PREFIX_PACKETS: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct MysqlSemanticTracker {
    session: SemanticSession,
    pending: VecDeque<ActiveExchange>,
    max_value_bytes: usize,
    context: MysqlExchangeContext,
}

#[derive(Debug, Clone, Default)]
pub struct MysqlExchangeContext {
    pub route_name: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub upstream_addr: Option<String>,
    pub username: Option<String>,
    pub database: Option<String>,
}

#[derive(Debug, Clone)]
struct ActiveExchange {
    connection_id: Uuid,
    query_sequence: u64,
    client_addr: Option<String>,
    native: SemanticRequest,
    started: Instant,
    request_started_at: chrono::DateTime<Utc>,
    wire_prefix: Vec<MysqlWirePrefixPacket>,
    wire_prefix_bytes: usize,
}

impl MysqlSemanticTracker {
    pub(crate) fn new(max_value_bytes: usize, context: MysqlExchangeContext) -> Self {
        Self {
            session: SemanticSession::new(max_value_bytes),
            pending: VecDeque::new(),
            max_value_bytes,
            context,
        }
    }

    pub(crate) fn start_query(
        &mut self,
        connection_id: Uuid,
        query_sequence: u64,
        command: &ClientCommand,
        packet: &MysqlPacket,
        client_addr: Option<String>,
    ) {
        let native = self.session.start_request(command, packet);
        self.pending.push_back(ActiveExchange {
            connection_id,
            query_sequence,
            client_addr,
            native,
            started: Instant::now(),
            request_started_at: Utc::now(),
            wire_prefix: Vec::new(),
            wire_prefix_bytes: 0,
        });
    }

    pub(crate) fn pending_started_at(&self) -> Option<Instant> {
        self.pending.back().map(|active| active.started)
    }

    pub(crate) fn observe_no_response_command(
        &mut self,
        command: &ClientCommand,
        packet: &MysqlPacket,
    ) {
        self.session.observe_no_response(command, packet);
    }

    pub(crate) fn observe_packet(&mut self, packet: &MysqlPacket) {
        if let Some(active) = self.pending.front_mut() {
            active.native.packets.push(packet.clone());
        }
    }

    pub(crate) fn observe_delivery(&mut self, packet: &MysqlPacket) {
        if let Some(active) = self.pending.front_mut() {
            if active
                .wire_prefix
                .last()
                .is_some_and(|prefix| prefix.packet.truncated)
            {
                return;
            }
            let remaining = if active.wire_prefix.len() < MAX_TERMINATION_PREFIX_PACKETS {
                self.max_value_bytes
                    .saturating_sub(active.wire_prefix_bytes)
            } else {
                0
            };
            let captured = capture_body(&packet.to_wire_bytes(), remaining);
            active.wire_prefix_bytes = active.wire_prefix_bytes.saturating_add(captured.stored_len);
            active.wire_prefix.push(MysqlWirePrefixPacket {
                offset_ms: active.started.elapsed().as_millis(),
                packet: captured,
            });
        }
    }

    pub(crate) fn observe_parse_warning(&mut self, warning: String) {
        if let Some(active) = self.pending.front_mut() {
            active.native.parse_warnings.push(warning);
        }
    }

    pub(crate) fn database(&self) -> Option<&str> {
        self.context.database.as_deref()
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn prepared_sql_for_packet(&self, packet: &MysqlPacket) -> Option<&str> {
        self.session.prepared_sql_for_packet(packet)
    }

    pub(crate) fn finish_from_response(
        &mut self,
        response: &MysqlResponseEvent,
    ) -> Option<MysqlExchangeEvent> {
        let confirmed_database = (response.status == "ok")
            .then_some(self.pending.front())
            .flatten()
            .filter(|active| active.native.command == "COM_INIT_DB")
            .and_then(|active| active.native.sql.clone());
        let exchange = self.finish_active(
            &response.status,
            response.error_code,
            response.error_message.clone(),
            Some(response.duration_ms),
        );
        if let Some(database) = confirmed_database {
            self.context.database = Some(database);
        }
        exchange
    }

    pub(crate) fn finish_active(
        &mut self,
        fallback_status: &str,
        error_code: Option<u16>,
        error_message: Option<String>,
        duration_ms: Option<u128>,
    ) -> Option<MysqlExchangeEvent> {
        let mut active = self.pending.pop_front()?;
        let status = fallback_status.to_string();
        let mut response =
            self.session
                .parse_response(&mut active.native, &status, error_code, error_message);
        response.wire_prefix = std::mem::take(&mut active.wire_prefix);
        let server_status_before = self.session.confirm_status(
            active.connection_id,
            active.query_sequence,
            &active.native,
            &response,
        );
        Some(MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: active.connection_id,
            query_sequence: active.query_sequence,
            timestamp: Utc::now(),
            request_started_at: active.request_started_at,
            client_addr: active.client_addr,
            route_name: self.context.route_name.clone(),
            target_host: self.context.target_host.clone(),
            target_port: self.context.target_port,
            target_addr: self.context.target_addr.clone(),
            upstream_addr: self.context.upstream_addr.clone(),
            username: self.context.username.clone(),
            database: self.context.database.clone(),
            command: active.native.command,
            sql: active.native.sql,
            statement_id: active.native.statement_id,
            params: active.native.params,
            server_status_before,
            response,
            outcome: if fallback_status == "client_terminated" {
                DependencyExchangeOutcome::ClientTerminated
            } else {
                DependencyExchangeOutcome::Response
            },
            duration_ms: duration_ms.unwrap_or_else(|| active.started.elapsed().as_millis()),
            parse_warnings: active.native.parse_warnings,
        })
    }
}
