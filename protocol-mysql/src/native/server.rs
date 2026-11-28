//! Classic greeting and CLIENT_SSL upgrade followed by finite native requests.
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use anyhow::{Context, Result, bail, ensure};
use tokio::io::AsyncBufReadExt;
use traffic_protocol::connection::{
    ConnectionInfo, ConnectionIo, NativeFuture, RejectedCommand, ReplaySessionStep, RequestHost,
    RequestSession, ResponseFramer, ServerSession,
};
use traffic_protocol::message::ProtocolMessage;
use traffic_protocol::output::OutputStream;

use super::{prepared::Statements, response::ResponseMessage};
use crate::{
    MysqlPacket,
    message::RequestMessage,
    model::{MysqlColumn, ResultRowEncoding},
    types::SERVER_STATUS_AUTOCOMMIT,
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
            let mut implicit_start_pending = false;
            let mut statements = Statements::default();
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
                let finite = matches!(command.command_name.as_str(), "COM_QUERY" | "COM_INIT_DB");
                let sql = command.query.as_deref().unwrap_or_default();
                let autocommit = status & (TRANSACTION_STATUS | SERVER_STATUS_AUTOCOMMIT)
                    == SERVER_STATUS_AUTOCOMMIT;
                let mut target_session = RequestSession {
                    can_start: if finite && starts_transaction(sql) {
                        status & TRANSACTION_STATUS == 0
                    } else {
                        status & IN_READ_ONLY_TRANSACTION == 0
                            && (status & SERVER_STATUS_AUTOCOMMIT == 0
                                || status & IN_TRANSACTION != 0)
                    },
                    after: predecessor.clone(),
                    autocommit,
                    autocommit_completion: false,
                    implicit_start_pending,
                    read_only_end_alternative: None,
                };
                let text_request = || RequestMessage {
                    command: command.command_name.clone(),
                    sql: command.query.clone(),
                    params: None,
                    database: identity.database.clone(),
                    username: identity.username.clone(),
                };
                let prepared = if host.event_session() {
                    match command.command_name.as_str() {
                        "COM_STMT_PREPARE" => {
                            ensure!(
                                packet.payload.len() < crate::continuation::MAX_PACKET_PAYLOAD_LEN,
                                "fragmented MySQL prepared SQL is unsupported"
                            );
                            let sql = std::str::from_utf8(&packet.payload[1..])?;
                            let request = RequestMessage {
                                sql: Some(sql.to_owned()),
                                ..text_request()
                            };
                            if statements
                                .prepare(&mut io, host.as_ref(), &target_session, status, request)
                                .await?
                            {
                                continue;
                            }
                            None
                        }
                        "COM_STMT_EXECUTE" => {
                            ensure!(
                                packet.payload.len() < crate::continuation::MAX_PACKET_PAYLOAD_LEN,
                                "fragmented MySQL prepared execution is unsupported"
                            );
                            Some(statements.execute(
                                &packet,
                                identity.database.clone(),
                                identity.username.clone(),
                            )?)
                        }
                        "COM_STMT_CLOSE" => {
                            statements.close(&packet)?;
                            continue;
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                if !finite && prepared.is_none() {
                    let reason = host
                        .reject_command(
                            RejectedCommand {
                                protocol_name: "MySQL",
                                received: &command.command_name,
                                observation: serde_json::to_vec(&serde_json::json!({
                                    "command": command.command_name,
                                    "sql": command.query,
                                }))?,
                            },
                            target_session,
                        )
                        .await?;
                    if command.expects_server_response() {
                        // MySQL numbers the error immediately after the last
                        // frame of the incoming command, including continuations.
                        let continuation_frames =
                            packet.payload.len() / crate::continuation::MAX_PACKET_PAYLOAD_LEN;
                        crate::write_packet(
                            &mut io,
                            &MysqlPacket {
                                sequence_id: packet
                                    .sequence_id
                                    .wrapping_add(continuation_frames as u8)
                                    .wrapping_add(1),
                                payload: crate::response::err_payload(1105, &reason),
                            },
                        )
                        .await?;
                    }
                    bail!("{reason}");
                }
                if !implicit_start_pending
                    && let Some(response) = session_response(
                        &command.command_name,
                        command.query.as_deref(),
                        identity.database.as_deref(),
                    )
                {
                    let mut output =
                        crate::output::response(&response, ResultRowEncoding::Text, status);
                    traffic_replay::output::deliver(&mut io, &mut output, None).await?;
                    continue;
                }
                let (request, prepared_columns, prepared_sql): (Arc<dyn ProtocolMessage>, _, _) =
                    if let Some((execution, columns)) = prepared {
                        let sql = execution.request.sql.clone();
                        (Arc::new(execution), Some(columns), sql)
                    } else {
                        let request = text_request();
                        if host.event_session()
                            && predecessor.is_some()
                            && command.command_name == "COM_QUERY"
                        {
                            target_session.read_only_end_alternative =
                                read_only_end_alternative(&request, sql);
                        }
                        (Arc::new(request), None, None)
                    };
                let sql = prepared_sql.as_deref().unwrap_or(sql);
                let mut framer = Framer {
                    status,
                    sql: sql.to_owned(),
                    successful: false,
                    transaction: None,
                    requires_active: false,
                    prepared_columns,
                };
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
                let database = identity.database.as_deref().filter(|_| {
                    host.event_session()
                        && !implicit_start_pending
                        && command.command_name == "COM_QUERY"
                        && is_database_observation(sql)
                });
                let mut delivery = if let Some(database) = database {
                    if let Some(delivery) = host
                        .try_execute_driver_observation(request, target_session)
                        .await?
                    {
                        delivery
                    } else {
                        let response: crate::recorded::RecordedMysqlResponse =
                            crate::builtin::single_string_result("DATABASE()", database);
                        let mut output =
                            crate::output::response(&response, ResultRowEncoding::Text, status);
                        traffic_replay::output::deliver(&mut io, &mut output, None).await?;
                        continue;
                    }
                } else if let Some(next_status) = control {
                    let defer_begin = host.event_session()
                        && is_plain(sql, &["begin", "start transaction"])
                        && host.can_defer_transaction_start(request.as_ref()).await?;
                    let delivery = if defer_begin {
                        None
                    } else {
                        host.try_execute_session_control(request, target_session)
                            .await?
                    };
                    match delivery {
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
                            implicit_start_pending = defer_begin;
                            continue;
                        }
                    }
                } else {
                    host.execute_in_session(request, target_session).await?
                };
                let completes_in_autocommit = autocommit
                    && delivery.session_step() == Some(&ReplaySessionStep::AutocommitWrite);
                framer.transaction = match delivery.session_step() {
                    Some(ReplaySessionStep::Start | ReplaySessionStep::ImplicitStart) => {
                        Some(false)
                    }
                    Some(ReplaySessionStep::AutocommitWrite) if !completes_in_autocommit => {
                        Some(false)
                    }
                    Some(ReplaySessionStep::Continue { end, .. }) => Some(*end),
                    Some(
                        ReplaySessionStep::ReadOnlyEnd { .. }
                        | ReplaySessionStep::AutocommitCommit { .. },
                    ) => Some(true),
                    _ => None,
                };
                ensure!(
                    !implicit_start_pending
                        || delivery.session_step() == Some(&ReplaySessionStep::ImplicitStart),
                    "MySQL explicit BEGIN was not followed by the recorded implicit transaction start"
                );
                framer.requires_active = matches!(
                    delivery.session_step(),
                    Some(ReplaySessionStep::InTransaction)
                );
                let mut next = if framer.transaction == Some(false) || completes_in_autocommit {
                    let reference = delivery
                        .reference()
                        .context("MySQL transaction receipt missing")?;
                    delivery.retain_as_anchor();
                    Some(reference)
                } else {
                    None
                };
                delivery.write(&mut io, &mut framer).await?;
                if completes_in_autocommit {
                    ensure!(framer.successful, "MySQL autocommit write was unsuccessful");
                    let after = next
                        .take()
                        .context("MySQL autocommit delivery receipt missing")?;
                    let commit = RequestMessage {
                        command: "COM_QUERY".into(),
                        sql: Some("COMMIT".into()),
                        params: None,
                        database: identity.database.clone(),
                        username: identity.username.clone(),
                    };
                    host.complete_autocommit(Arc::new(commit), after.clone())
                        .await?;
                    host.forget_anchor(&after);
                }
                implicit_start_pending = false;
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
            ensure!(
                !implicit_start_pending,
                "MySQL connection closed before its recorded implicit transaction start"
            );
            Ok(())
        })
    }
}

fn read_only_end_alternative(
    request: &RequestMessage,
    sql: &str,
) -> Option<Arc<dyn ProtocolMessage>> {
    let alternate = if is_plain(sql, &["commit"]) {
        "ROLLBACK"
    } else if is_plain(sql, &["rollback"]) {
        "COMMIT"
    } else {
        return None;
    };
    Some(Arc::new(RequestMessage {
        sql: Some(alternate.into()),
        ..request.clone()
    }))
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

fn is_database_observation(sql: &str) -> bool {
    !["/*", "--", "#"].iter().any(|marker| sql.contains(marker))
        && crate::values::normalize_sql(sql) == "select database()"
}

struct Framer {
    status: u16,
    sql: String,
    successful: bool,
    transaction: Option<bool>,
    requires_active: bool,
    prepared_columns: Option<Arc<[MysqlColumn]>>,
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
        let encoding = if let Some(columns) = &self.prepared_columns {
            ensure!(
                envelope.response.status == "error"
                    || envelope.response.columns.as_slice() == columns.as_ref(),
                "MySQL execution response metadata differs from the prepared statement"
            );
            ResultRowEncoding::Binary
        } else {
            ResultRowEncoding::Text
        };
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
        envelope.into_output(self.status, encoding)
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
        connection::{OutputIo, RecordedExchange, ResponseDelivery},
        message::{MessageEncoder, ProtocolMessage},
        output::OutputBoundary,
    };
    use traffic_replay::rules::{ExactRules, RuleRuntime};

    struct ProvisionalStartHost;

    impl RequestHost for ProvisionalStartHost {
        fn event_session(&self) -> bool {
            true
        }

        fn can_defer_transaction_start<'a>(
            &'a self,
            request: &'a dyn ProtocolMessage,
        ) -> NativeFuture<'a, bool> {
            Box::pin(async move {
                let request = request
                    .as_any()
                    .unwrap()
                    .downcast_ref::<RequestMessage>()
                    .unwrap();
                assert_eq!(request.sql.as_deref(), Some("BEGIN"));
                Ok(true)
            })
        }

        fn execute_in_session(
            &self,
            request: Arc<dyn ProtocolMessage>,
            session: RequestSession,
        ) -> NativeFuture<'_, Box<dyn traffic_protocol::connection::ResponseDelivery>> {
            Box::pin(async move {
                assert!(
                    session.implicit_start_pending && session.can_start && session.after.is_none()
                );
                let request = request
                    .as_any()
                    .unwrap()
                    .downcast_ref::<RequestMessage>()
                    .unwrap();
                assert_eq!(request.sql.as_deref(), Some("SELECT DATABASE()"));
                bail!("unmatched transaction start")
            })
        }

        fn execute(
            &self,
            _: Arc<dyn ProtocolMessage>,
        ) -> NativeFuture<'_, Box<dyn traffic_protocol::connection::ResponseDelivery>> {
            unreachable!("MySQL requests use the native session port")
        }
    }

    async fn connect(
        host: Arc<dyn RequestHost>,
    ) -> Result<(tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>)> {
        let info = ConnectionInfo {
            endpoint: traffic_protocol::connection::Endpoint {
                host: "mysql.test".into(),
                port: 3306,
            },
            client_addr: None,
            upstream_addr: None,
            max_frame_bytes: 4096,
        };
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(Box::new(Server(info)).run(Box::new(server), host));
        crate::read_packet(&mut client).await?.unwrap();
        let mut login = vec![0; 32];
        login[..4].copy_from_slice(&crate::types::CLIENT_PROTOCOL_41.to_le_bytes());
        login.extend_from_slice(b"user\0\0");
        crate::write_packet(
            &mut client,
            &MysqlPacket {
                sequence_id: 1,
                payload: login,
            },
        )
        .await?;
        crate::read_packet(&mut client).await?.unwrap();
        query(&mut client, "BEGIN").await?;
        let begin = crate::read_packet(&mut client).await?.unwrap();
        assert_eq!(
            begin.payload,
            crate::response::ok_payload_with_status(
                0,
                0,
                SERVER_STATUS_AUTOCOMMIT | IN_TRANSACTION
            )
        );
        Ok((client, task))
    }

    async fn query(client: &mut tokio::io::DuplexStream, sql: &str) -> std::io::Result<()> {
        let mut payload = vec![3];
        payload.extend_from_slice(sql.as_bytes());
        crate::write_packet(
            client,
            &MysqlPacket {
                sequence_id: 0,
                payload,
            },
        )
        .await
    }

    #[tokio::test]
    async fn provisional_begin_forces_the_next_sql_through_matching_on_its_connection() -> Result<()>
    {
        let (mut client, task) = connect(Arc::new(ProvisionalStartHost)).await?;
        query(&mut client, "SELECT DATABASE()").await?;
        assert_eq!(
            task.await?.unwrap_err().to_string(),
            "unmatched transaction start"
        );
        assert!(crate::read_packet(&mut client).await?.is_none());
        Ok(())
    }

    struct LockedReadHost {
        exchanges: [RecordedExchange; 2],
        steps: std::collections::BTreeMap<usize, ReplaySessionStep>,
    }

    impl RequestHost for LockedReadHost {
        fn event_session(&self) -> bool {
            true
        }

        fn can_defer_transaction_start<'a>(
            &'a self,
            request: &'a dyn ProtocolMessage,
        ) -> NativeFuture<'a, bool> {
            ProvisionalStartHost.can_defer_transaction_start(request)
        }

        fn execute_in_session(
            &self,
            request: Arc<dyn ProtocolMessage>,
            session: RequestSession,
        ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
            Box::pin(async move {
                let index = if session.implicit_start_pending {
                    ensure!(
                        session.can_start && session.after.is_none(),
                        "lock requires a fresh provisional start"
                    );
                    0
                } else {
                    ensure!(
                        session.after.as_ref() == Some(&self.exchanges[0].reference),
                        "rollback requires the delivered lock receipt"
                    );
                    1
                };
                let exchange = &self.exchanges[index];
                let expected = ExactRules::prepare(exchange.request().unwrap(), &())?;
                ensure!(
                    ExactRules::compare(&expected, request.as_ref(), (), &())?,
                    "unmatched recorded lock or rollback"
                );
                Ok(Box::new(LockedReadDelivery(
                    exchange.response.clone(),
                    exchange.reference.clone(),
                    self.steps[&index].clone(),
                )) as Box<dyn ResponseDelivery>)
            })
        }

        fn execute(
            &self,
            _: Arc<dyn ProtocolMessage>,
        ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
            unreachable!("MySQL requests use the native session port")
        }
    }

    struct LockedReadDelivery(Arc<dyn MessageEncoder>, ProtocolRef, ReplaySessionStep);

    impl ResponseDelivery for LockedReadDelivery {
        fn reference(&self) -> Option<ProtocolRef> {
            Some(self.1.clone())
        }
        fn session_step(&self) -> Option<&ReplaySessionStep> {
            Some(&self.2)
        }
        fn write<'a>(
            self: Box<Self>,
            io: &'a mut dyn OutputIo,
            framer: &'a mut dyn ResponseFramer,
        ) -> NativeFuture<'a, ()> {
            Box::pin(async move {
                let values = self
                    .0
                    .project()?
                    .values
                    .into_iter()
                    .map(|(path, value)| (path, value.bytes))
                    .collect();
                let mut output = framer.prepare_output(self.0.output(&values)?)?;
                traffic_replay::output::deliver(io, output.as_mut(), None).await
            })
        }
    }

    #[tokio::test]
    async fn provisional_begin_delivers_the_locked_read_and_requires_the_recorded_rollback()
    -> Result<()> {
        use super::super::{Native, tests::locked_rollback_source};
        use traffic_protocol::connection::NativeProtocol;
        let mut source = locked_rollback_source();
        for event in &mut source {
            event["database"] = serde_json::Value::Null;
        }
        let steps = Native
            .prepare_event_session(&source.iter().enumerate().collect::<Vec<_>>())?
            .steps;
        let sql = source[0]["sql"].as_str().unwrap();
        for ending in ["ROLLBACK", "COMMIT"] {
            let exchanges = source
                .each_ref()
                .map(|event| Native.recorded_exchange(event).unwrap().unwrap());
            let (mut client, task) = connect(Arc::new(LockedReadHost {
                exchanges,
                steps: steps.clone(),
            }))
            .await?;
            query(&mut client, sql).await?;
            for _ in 0..3 {
                crate::read_packet(&mut client).await?.unwrap();
            }
            assert_eq!(
                crate::read_packet(&mut client).await?.unwrap().payload,
                [1, b'7']
            );
            let tail = crate::read_packet(&mut client).await?.unwrap();
            assert_eq!(
                tail.payload,
                crate::response::eof_payload_with_status(SERVER_STATUS_AUTOCOMMIT | IN_TRANSACTION)
            );
            query(&mut client, ending).await?;
            if ending == "ROLLBACK" {
                let end = crate::read_packet(&mut client).await?.unwrap();
                assert_eq!(
                    end.payload,
                    crate::response::ok_payload_with_status(0, 0, SERVER_STATUS_AUTOCOMMIT)
                );
                tokio::io::AsyncWriteExt::shutdown(&mut client).await?;
                task.await??;
            } else {
                assert_eq!(
                    task.await?.unwrap_err().to_string(),
                    "unmatched recorded lock or rollback"
                );
                assert!(crate::read_packet(&mut client).await?.is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn database_observation_is_only_the_exact_connection_metadata_query() {
        assert!(is_database_observation("SELECT DATABASE();"));
        assert!(!is_database_observation("SELECT DATABASE() AS schema_name"));
        assert!(!is_database_observation(
            "SELECT DATABASE() FROM application_table"
        ));
        assert!(!is_database_observation("SELECT DATABASE(); COMMIT"));
        assert!(!is_database_observation("COMMIT"));
    }

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
            prepared_columns: None,
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
