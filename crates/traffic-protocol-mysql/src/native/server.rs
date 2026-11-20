//! Classic greeting and CLIENT_SSL upgrade followed by finite native requests.
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use anyhow::{Context, Result, ensure};
use tokio::io::AsyncBufReadExt;
use traffic_protocol::connection::{
    ConnectionInfo, ConnectionIo, NativeFuture, ReplaySessionStep, RequestHost, RequestSession,
    ResponseFramer, ServerSession,
};
use traffic_protocol::output::OutputStream;

use super::response::ResponseMessage;
use crate::{
    MysqlPacket, message::RequestMessage, model::ResultRowEncoding, types::SERVER_STATUS_AUTOCOMMIT,
};
use traffic_model::recording::ProtocolRef;

pub(super) struct Server(pub ConnectionInfo);
static CONNECTION_ID: AtomicU32 = AtomicU32::new(1);
const IN_TRANSACTION: u16 = 0x0001;
const IN_READ_ONLY_TRANSACTION: u16 = 0x2000;
const TRANSACTION_STATUS: u16 = IN_TRANSACTION | IN_READ_ONLY_TRANSACTION;

impl ServerSession for Server {
    fn run(
        self: Box<Self>,
        mut io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            crate::write_packet(
                io.as_mut(),
                &crate::response::handshake_packet(CONNECTION_ID.fetch_add(1, Ordering::Relaxed)),
            )
            .await?;
            let mut login = read(io.as_mut(), self.0.max_frame_bytes)
                .await?
                .context("MySQL login missing")?;
            ensure!(
                login.sequence_id == 1 && login.payload.len() >= 32,
                "invalid MySQL login"
            );
            let mut identity = crate::parse_handshake_response(&login);
            if identity.tls_requested {
                ensure!(
                    login.payload.len() == 32,
                    "MySQL SSLRequest has an invalid size"
                );
                io = host.accept_tls(io, Vec::new()).await?;
                login = read(io.as_mut(), self.0.max_frame_bytes)
                    .await?
                    .context("MySQL TLS login missing")?;
                ensure!(
                    login.sequence_id == 2 && login.payload.len() > 32,
                    "invalid MySQL TLS login"
                );
                identity = crate::parse_handshake_response(&login);
            }
            ensure!(
                login.payload.len() > 32 && identity.username.is_some(),
                "invalid MySQL login identity"
            );
            ensure!(
                identity.capability_flags & crate::CLIENT_COMPRESS == 0,
                "MySQL compression is unavailable"
            );
            crate::write_packet(
                io.as_mut(),
                &MysqlPacket {
                    sequence_id: login.sequence_id.wrapping_add(1),
                    payload: crate::response::ok_payload(0, 0),
                },
            )
            .await?;
            let mut status = SERVER_STATUS_AUTOCOMMIT;
            let mut read_only = true;
            let mut snapshot_sensitive = false;
            let mut predecessor: Option<ProtocolRef> = None;
            let mut io = tokio::io::BufReader::new(io);
            while !io.fill_buf().await?.is_empty() {
                let _input = host.begin_input().await?;
                let packet = read(&mut io, self.0.max_frame_bytes)
                    .await?
                    .context("MySQL command ended before its frame")?;
                ensure!(
                    packet.sequence_id == 0,
                    "MySQL command sequence must begin at zero"
                );
                let command =
                    crate::parse_client_command(&packet).context("empty MySQL command")?;
                if command.command_name == "COM_QUIT" {
                    break;
                }
                let mut framer = Framer {
                    status,
                    sql: command.query.clone().unwrap_or_default(),
                    successful: false,
                    transaction: None,
                    requires_active: false,
                };
                if command.command_name == "COM_PING" {
                    crate::write_packet(
                        &mut io,
                        &MysqlPacket {
                            sequence_id: 1,
                            payload: crate::response::ok_payload_with_status(0, 0, status),
                        },
                    )
                    .await?;
                    continue;
                }
                ensure!(
                    matches!(command.command_name.as_str(), "COM_QUERY" | "COM_INIT_DB"),
                    "unsupported MySQL command {}",
                    command.command_name
                );
                if let Some(response) = session_response(
                    &command.command_name,
                    command.query.as_deref(),
                    identity.database.as_deref(),
                ) {
                    let mut output =
                        crate::output::response(&response, ResultRowEncoding::Text, status);
                    traffic_replay::output::deliver(&mut io, &mut output, None).await?;
                    continue;
                }
                let request = Arc::new(RequestMessage {
                    command: command.command_name.clone(),
                    sql: command.query.clone(),
                    params: None,
                    database: identity.database.clone(),
                    username: identity.username.clone(),
                });
                let sql = command.query.as_deref().unwrap_or_default();
                let control = (command.command_name == "COM_QUERY")
                    .then(|| {
                        safe_control(
                            sql,
                            status,
                            read_only && !snapshot_sensitive,
                            predecessor.is_some(),
                        )
                    })
                    .flatten();
                let target_session = RequestSession {
                    can_start: if starts_transaction(sql) {
                        status & TRANSACTION_STATUS == 0
                    } else {
                        status & IN_READ_ONLY_TRANSACTION == 0
                            && (status & SERVER_STATUS_AUTOCOMMIT == 0
                                || status & IN_TRANSACTION != 0)
                    },
                    after: predecessor.clone(),
                };
                let mut delivery = if let Some(next_status) = control {
                    match host
                        .try_execute_session_control(request, target_session)
                        .await?
                    {
                        Some(delivery) => delivery,
                        None => {
                            crate::write_packet(
                                &mut io,
                                &MysqlPacket {
                                    sequence_id: 1,
                                    payload: crate::response::ok_payload_with_status(
                                        0,
                                        0,
                                        next_status,
                                    ),
                                },
                            )
                            .await?;
                            status = next_status;
                            read_only = true;
                            continue;
                        }
                    }
                } else {
                    host.execute_in_session(request, target_session).await?
                };
                framer.transaction = match delivery.session_step() {
                    Some(ReplaySessionStep::Start) => Some(false),
                    Some(ReplaySessionStep::Continue { end, .. }) => Some(*end),
                    _ => None,
                };
                framer.requires_active = matches!(
                    delivery.session_step(),
                    Some(ReplaySessionStep::InTransaction)
                );
                let next = if framer.transaction == Some(false) {
                    let reference = delivery
                        .reference()
                        .context("MySQL transaction receipt missing")?;
                    delivery.retain_as_anchor();
                    Some(reference)
                } else {
                    None
                };
                delivery.write(&mut io, &mut framer).await?;
                if let Some(previous) = predecessor.take() {
                    host.forget_anchor(&previous);
                }
                predecessor = next;
                status = framer.status;
                snapshot_sensitive |=
                    framer.successful && crate::session_control::changes_snapshot_contract(sql);
                read_only = status & TRANSACTION_STATUS == 0
                    || (predecessor.is_none()
                        && read_only
                        && framer.successful
                        && (is_plain(sql, &["begin", "start transaction"])
                            || crate::session_control::read::classify(sql)
                                == crate::session_control::read::Effect::ReadOnly));
                if command.command_name == "COM_INIT_DB" && framer.successful {
                    identity.database = command.query;
                }
            }
            Ok(())
        })
    }
}

fn is_plain(sql: &str, commands: &[&str]) -> bool {
    let sql = sql.trim();
    let sql = sql.strip_suffix(';').unwrap_or(sql).trim_end();
    commands
        .iter()
        .any(|command| sql.eq_ignore_ascii_case(command))
}

fn starts_transaction(sql: &str) -> bool {
    let sql = sql.trim_start();
    if is_plain(sql, &["begin", "start transaction"]) {
        return true;
    }
    // Only a matched Source start can use this path. Non-plain starts never
    // receive local success because their transaction modes affect semantics.
    if !sql.get(..5).is_some_and(|prefix| {
        prefix.eq_ignore_ascii_case("start") || prefix.eq_ignore_ascii_case("begin")
    }) && !sql.starts_with(['/', '-', '#'])
    {
        return false;
    }
    crate::sql::tokens(sql).is_some_and(|tokens| match tokens.as_slice() {
        [start, transaction, ..] if start.is("start") => transaction.is("transaction"),
        [begin, ..] => begin.is("begin"),
        _ => false,
    })
}

fn safe_control(sql: &str, status: u16, read_only: bool, has_predecessor: bool) -> Option<u16> {
    if has_predecessor {
        return None;
    }
    let inactive = status & TRANSACTION_STATUS == 0;
    if (inactive || read_only) && is_plain(sql, &["commit", "rollback"]) {
        return Some(status & !TRANSACTION_STATUS);
    }
    if inactive {
        if let Some(enabled) = crate::autocommit::assignment(sql) {
            return Some(if enabled {
                status | SERVER_STATUS_AUTOCOMMIT
            } else {
                status & !SERVER_STATUS_AUTOCOMMIT
            });
        }
        if is_plain(sql, &["begin", "start transaction"]) {
            return Some(status | IN_TRANSACTION);
        }
    }
    None
}

fn session_response(
    command: &str,
    sql: Option<&str>,
    database: Option<&str>,
) -> Option<crate::recorded::RecordedMysqlResponse> {
    if command != "COM_QUERY" {
        return None;
    }
    let sql = sql?;
    if crate::maintenance::is_mysql_maintenance_exchange(command, Some(sql))
        || crate::session_setup::is_mysql_session_setup_sql(sql)
    {
        crate::builtin::builtin_response(sql, database)
    } else {
        None
    }
}

struct Framer {
    status: u16,
    sql: String,
    successful: bool,
    transaction: Option<bool>,
    requires_active: bool,
}
impl ResponseFramer for Framer {
    fn prepare_output(
        &mut self,
        mut output: Box<dyn OutputStream>,
    ) -> Result<Box<dyn OutputStream>> {
        use traffic_protocol::output::OutputBoundary;
        let chunk = output
            .next()?
            .context("MySQL response envelope is absent")?;
        ensure!(
            output.part_count() == 0
                && chunk.boundary == OutputBoundary::End
                && chunk.complete
                && output.next()?.is_none(),
            "MySQL response envelope has unexpected output boundaries"
        );
        let envelope: ResponseMessage = serde_json::from_slice(&chunk.bytes)?;
        let mode = |flags: u16| flags & (TRANSACTION_STATUS | SERVER_STATUS_AUTOCOMMIT);
        ensure!(
            self.transaction.is_some()
                || mode(self.status) == SERVER_STATUS_AUTOCOMMIT
                || envelope.source_status_before.map(mode) != Some(SERVER_STATUS_AUTOCOMMIT)
                || envelope.response.server_status.map(mode) != Some(SERVER_STATUS_AUTOCOMMIT)
                || crate::session_control::read::classify(&self.sql)
                    != crate::session_control::read::Effect::StateChange,
            "MySQL standalone Source operation requires an autocommitting Target session"
        );
        if matches!(envelope.response.status.as_str(), "ok" | "resultset") {
            self.successful = true;
            self.status = crate::session_status::after_response(
                self.status,
                &self.sql,
                envelope.response.server_status,
                envelope.source_status_before,
            );
        }
        if let Some(end) = self.transaction {
            ensure!(
                !end || self.successful,
                "MySQL transaction end was unsuccessful"
            );
            if end {
                self.status &= !TRANSACTION_STATUS;
            } else {
                self.status |= IN_TRANSACTION;
            }
        }
        if self.requires_active && self.successful {
            self.status |= IN_TRANSACTION;
        }
        envelope.into_output(self.status)
    }
}

async fn read(io: &mut dyn ConnectionIo, limit: usize) -> Result<Option<MysqlPacket>> {
    use tokio::io::AsyncReadExt;
    let mut header = [0; 4];
    if io.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    io.read_exact(&mut header[1..]).await?;
    let mut payload = Vec::new();
    let sequence_id = header[3];
    let mut sequence = sequence_id;
    loop {
        let size =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        ensure!(
            header[3] == sequence,
            "MySQL continuation sequence mismatch"
        );
        ensure!(
            size <= limit.saturating_sub(payload.len()),
            "MySQL request exceeds frame limit"
        );
        let offset = payload.len();
        payload.resize(offset + size, 0);
        io.read_exact(&mut payload[offset..]).await?;
        if size < crate::continuation::MAX_PACKET_PAYLOAD_LEN {
            return Ok(Some(MysqlPacket {
                sequence_id,
                payload,
            }));
        }
        sequence = sequence.wrapping_add(1);
        io.read_exact(&mut header).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_protocol::{
        message::{MessageEncoder, ProtocolMessage},
        output::OutputBoundary,
    };

    #[test]
    fn session_output_preserves_headers_rows_and_end_for_shared_delivery() {
        let response = ResponseMessage::new(
            serde_json::from_value(serde_json::json!({
                "status":"resultset",
                "columns":[{"name":"fixture","family":"integer","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":7}]]
            }))
            .unwrap(),
            None,
        )
        .unwrap();
        let values = response
            .project()
            .unwrap()
            .values
            .into_iter()
            .map(|(path, value)| (path, value.bytes))
            .collect();
        let mut framer = Framer {
            status: SERVER_STATUS_AUTOCOMMIT,
            sql: "SELECT 7 AS fixture".into(),
            successful: false,
            transaction: None,
            requires_active: false,
        };
        let mut output = framer
            .prepare_output(response.output(&values).unwrap())
            .unwrap();
        assert!(framer.successful);
        assert_eq!(output.part_count(), 1);
        let mut boundaries = Vec::new();
        while let Some(chunk) = output.next().unwrap() {
            if chunk.complete {
                boundaries.push(chunk.boundary);
            }
        }
        assert_eq!(
            boundaries,
            [
                OutputBoundary::Headers,
                OutputBoundary::Part,
                OutputBoundary::End
            ]
        );
    }
}
