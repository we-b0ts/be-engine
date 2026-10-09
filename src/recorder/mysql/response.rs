use std::collections::VecDeque;

use super::*;

pub(super) struct MysqlResponseTracker {
    pending: VecDeque<MysqlResponseBuilder>,
    max_payload_bytes: usize,
    record_raw_packets: bool,
}

struct MysqlResponseBuilder {
    connection_id: Uuid,
    query_sequence: u64,
    client_addr: Option<String>,
    command: String,
    started: Instant,
    status: String,
    phase: MysqlResponsePhase,
    packet_count: usize,
    packets: Vec<MysqlResponsePacket>,
    payload: Vec<u8>,
    payload_bytes: usize,
    error_code: Option<u16>,
    error_message: Option<String>,
    record_raw_packets: bool,
}

#[derive(Debug, Clone, Copy)]
enum MysqlResponsePhase {
    FirstPacket,
    ResultSet { eof_count: u8 },
    StmtPrepare { eof_count: u8, eof_needed: u8 },
}

impl MysqlResponseTracker {
    pub(super) fn new(max_payload_bytes: usize, record_raw_packets: bool) -> Self {
        Self {
            pending: VecDeque::new(),
            max_payload_bytes,
            record_raw_packets,
        }
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn start_query(
        &mut self,
        connection_id: Uuid,
        query_sequence: u64,
        command: String,
        client_addr: Option<String>,
    ) {
        self.pending.push_back(MysqlResponseBuilder {
            connection_id,
            query_sequence,
            client_addr,
            command,
            started: Instant::now(),
            status: "pending".to_string(),
            phase: MysqlResponsePhase::FirstPacket,
            packet_count: 0,
            packets: Vec::new(),
            payload: Vec::new(),
            payload_bytes: 0,
            error_code: None,
            error_message: None,
            record_raw_packets: self.record_raw_packets,
        });
    }

    pub(super) fn observe_packet(
        &mut self,
        packet: &MysqlPacket,
        message: Option<&MysqlPacket>,
    ) -> Option<MysqlResponseEvent> {
        let active = self.pending.front_mut()?;
        let complete = active.observe_packet(packet, message, self.max_payload_bytes);
        complete.then(|| self.finish_active("incomplete")).flatten()
    }

    pub(super) fn finish_active(&mut self, fallback_status: &str) -> Option<MysqlResponseEvent> {
        self.pending
            .pop_front()
            .map(|mut active| active.finish(fallback_status))
    }
}

impl MysqlResponseBuilder {
    fn observe_packet(
        &mut self,
        packet: &MysqlPacket,
        message: Option<&MysqlPacket>,
        max_payload_bytes: usize,
    ) -> bool {
        self.payload_bytes += packet.payload.len();
        self.packet_count += 1;
        if self.payload.len() < max_payload_bytes {
            let remaining = max_payload_bytes - self.payload.len();
            self.payload
                .extend_from_slice(&packet.payload[..packet.payload.len().min(remaining)]);
        }
        if self.record_raw_packets {
            let packet_kind = message.map_or_else(
                || "continuation".to_string(),
                |message| response_packet_kind(self.phase, &parse_server_packet(message)),
            );
            self.packets.push(MysqlResponsePacket {
                sequence_id: packet.sequence_id,
                packet_kind,
                payload_len: packet.payload.len(),
                payload: capture_body(&packet.payload, max_payload_bytes),
            });
        }

        // Continuation contents are data, even when they look like EOF or ERR.
        let Some(packet) = message else {
            return false;
        };
        let info = parse_server_packet(packet);
        self.error_code = self.error_code.or(info.error_code);
        if self.error_message.is_none() {
            self.error_message = info.error_message.clone();
        }

        if info.kind == "error" {
            self.status = "error".to_string();
            return true;
        }

        match self.phase {
            MysqlResponsePhase::FirstPacket => self.observe_first_packet(packet, &info),
            MysqlResponsePhase::ResultSet { eof_count } => {
                if info.kind == "eof" {
                    let eof_count = eof_count + 1;
                    if eof_count >= 2 {
                        self.status = "resultset".to_string();
                        true
                    } else {
                        self.phase = MysqlResponsePhase::ResultSet { eof_count };
                        false
                    }
                } else {
                    false
                }
            }
            MysqlResponsePhase::StmtPrepare {
                eof_count,
                eof_needed,
            } => {
                if info.kind == "eof" {
                    let eof_count = eof_count + 1;
                    if eof_count >= eof_needed {
                        self.status = "stmt_prepare".to_string();
                        true
                    } else {
                        self.phase = MysqlResponsePhase::StmtPrepare {
                            eof_count,
                            eof_needed,
                        };
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    fn observe_first_packet(&mut self, packet: &MysqlPacket, info: &ServerPacketInfo) -> bool {
        if self.command == "COM_STMT_PREPARE" && info.kind == "ok" {
            let eof_needed = parse_stmt_prepare_eof_count(&packet.payload);
            if eof_needed == 0 {
                self.status = "stmt_prepare".to_string();
                true
            } else {
                self.status = "stmt_prepare".to_string();
                self.phase = MysqlResponsePhase::StmtPrepare {
                    eof_count: 0,
                    eof_needed,
                };
                false
            }
        } else if info.kind == "ok" {
            self.status = "ok".to_string();
            true
        } else if info.kind == "eof" {
            self.status = "eof".to_string();
            true
        } else {
            self.status = "resultset".to_string();
            self.phase = MysqlResponsePhase::ResultSet { eof_count: 0 };
            false
        }
    }

    fn finish(&mut self, fallback_status: &str) -> MysqlResponseEvent {
        let status = if self.status == "pending" {
            fallback_status.to_string()
        } else {
            self.status.clone()
        };
        MysqlResponseEvent {
            id: Uuid::new_v4(),
            connection_id: self.connection_id,
            query_sequence: self.query_sequence,
            timestamp: Utc::now(),
            client_addr: self.client_addr.clone(),
            status,
            packet_count: self.packet_count,
            payload_bytes: self.payload_bytes,
            duration_ms: self.started.elapsed().as_millis(),
            error_code: self.error_code,
            error_message: self.error_message.clone(),
            payload: capture_body_with_original_len(&self.payload, self.payload_bytes),
            packets: self
                .record_raw_packets
                .then(|| std::mem::take(&mut self.packets)),
        }
    }
}

fn response_packet_kind(phase: MysqlResponsePhase, info: &ServerPacketInfo) -> String {
    if matches!(phase, MysqlResponsePhase::ResultSet { .. }) && info.kind == "ok" {
        "result_or_data".to_string()
    } else {
        info.kind.clone()
    }
}

fn parse_stmt_prepare_eof_count(payload: &[u8]) -> u8 {
    if payload.len() < 9 || payload.first() != Some(&0x00) {
        return 0;
    }
    let num_columns = u16::from_le_bytes([payload[5], payload[6]]);
    let num_params = u16::from_le_bytes([payload[7], payload[8]]);
    u8::from(num_params > 0) + u8::from(num_columns > 0)
}
