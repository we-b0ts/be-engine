//! Native command dispatch and physical prepared-statement lifetime.
use anyhow::Result;
use traffic_protocol::connection::ConnectionIo;

use super::{Directive, Request, ServerHost, Session, requests};
use crate::{MysqlPacket, MysqlSession, model::ResultRowEncoding};

pub async fn serve<H: ServerHost>(
    io: &mut dyn ConnectionIo,
    decoder: &mut MysqlSession,
    host: &H,
    session: &mut Session<H::SessionContext>,
) -> Result<()> {
    loop {
        let Some(packet) = crate::read_packet_with_session(io, decoder.as_mut()).await? else {
            crate::diagnostics::client_eof();
            return Ok(());
        };
        session.request_started = tokio::time::Instant::now();
        let Some(command) = crate::parse_client_command(&packet) else {
            continue;
        };
        crate::diagnostics::request(&packet, &command.command_name);
        if host.stopping().await? {
            session.control.reset()?;
            return Ok(());
        }
        let request = Request {
            command: &command.command_name,
            sql: command.query.as_deref(),
            params: None,
        };
        let directive = match request.command {
            "COM_QUIT" => Directive::Close,
            "COM_PING" | "COM_INIT_DB" => requests::control(io, host, session, request).await?,
            "COM_QUERY" => {
                requests::query(io, host, session, request, ResultRowEncoding::Text).await?
            }
            "COM_STMT_PREPARE" => {
                requests::prepare(io, host, session, request.sql.unwrap_or_default()).await?
            }
            "COM_STMT_EXECUTE" => requests::execute(io, host, session, &packet).await?,
            "COM_STMT_CLOSE" => {
                match crate::values::read_u32_le(&packet.payload, 1) {
                    Some(statement_id) => {
                        session.statements.remove(&statement_id);
                        host.statement_closed(session).await?;
                    }
                    None => {
                        host.unsupported(
                            session,
                            request,
                            "COM_STMT_CLOSE packet missing statement id",
                        )
                        .await?;
                    }
                }
                Directive::Continue
            }
            other => {
                host.unsupported(session, request, "unsupported MySQL command")
                    .await?;
                let mut output = crate::output::packet(MysqlPacket {
                    sequence_id: 1,
                    payload: crate::response::err_payload(
                        1105,
                        &format!("unsupported replay command {other}"),
                    ),
                });
                traffic_replay::output::deliver(io, &mut output, None).await?;
                Directive::Continue
            }
        };
        if directive == Directive::Close {
            return Ok(());
        }
    }
}
