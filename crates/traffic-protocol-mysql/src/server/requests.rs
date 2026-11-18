//! Native statement and session controls delegate complete request selection.
use anyhow::Result;
use traffic_protocol::connection::ConnectionIo;

use super::{Directive, Request, ServerHost, Session};
use crate::{MysqlPacket, builtin::builtin_response, model::ResultRowEncoding, output};

pub async fn query<H: ServerHost>(
    io: &mut dyn ConnectionIo,
    host: &H,
    session: &mut Session<H::SessionContext>,
    request: Request<'_>,
    encoding: ResultRowEncoding,
) -> Result<Directive> {
    let selected = host.select(session, request).await?;
    if let Some(delivery) = selected.delivery {
        return host.deliver(io, session, delivery, encoding).await;
    }
    let sql = request.sql.unwrap_or_default();
    if let Some(response) = builtin_response(sql, session.database.as_deref()) {
        let previous_status = session.status_flags;
        host.before_builtin(session, &selected.context, request, &response);
        let mut output = output::response(&response, encoding, session.status_flags);
        traffic_replay::output::deliver(io, &mut output, None).await?;
        host.builtin_delivered(session, &selected.context, request, Some(previous_status))
            .await?;
        return Ok(Directive::Continue);
    }
    let reason = if request.command == "COM_STMT_EXECUTE" {
        "no recorded semantic dependency matched this prepared SQL and params"
    } else {
        "no recorded semantic dependency matched this SQL"
    };
    host.unmatched(session, Some(&selected.context), request, reason)
        .await?;
    Ok(Directive::Close)
}

pub(super) async fn prepare<H: ServerHost>(
    io: &mut dyn ConnectionIo,
    host: &H,
    session: &mut Session<H::SessionContext>,
    sql: &str,
) -> Result<Directive> {
    let request = Request {
        command: "COM_STMT_PREPARE",
        sql: Some(sql),
        params: None,
    };
    let selected = host.select(session, request).await?;
    if let Some(delivery) = selected.delivery {
        return host
            .deliver(io, session, delivery, ResultRowEncoding::Text)
            .await;
    }
    let metadata = host
        .statement_metadata(session, &selected.context, sql)
        .await?;
    if metadata.columns.is_empty() && crate::values::looks_like_select(sql) {
        host.warning(format!(
            "COM_STMT_PREPARE for `{sql}` has no recorded result column metadata"
        ))
        .await?;
    }
    let statement_id = session.next_statement_id;
    session.next_statement_id += 1;
    session.statements.insert(
        statement_id,
        crate::model::PreparedStatement {
            sql: sql.to_string(),
            param_count: metadata.param_count,
            last_param_types: Vec::new(),
        },
    );
    let mut output = output::prepare(statement_id, &metadata, session.status_flags);
    traffic_replay::output::deliver(io, &mut output, None).await?;
    Ok(Directive::Continue)
}

pub(super) async fn execute<H: ServerHost>(
    io: &mut dyn ConnectionIo,
    host: &H,
    session: &mut Session<H::SessionContext>,
    packet: &MysqlPacket,
) -> Result<Directive> {
    let parsed = crate::prepared::parse_stmt_execute(packet, &session.statements);
    let Some(statement) = session.statements.get(&parsed.statement_id).cloned() else {
        host.unmatched(
            session,
            None,
            Request {
                command: "COM_STMT_EXECUTE",
                sql: None,
                params: parsed.params.as_deref(),
            },
            "COM_STMT_EXECUTE referenced an unknown replay statement id",
        )
        .await?;
        return Ok(Directive::Close);
    };
    if let Some(param_types) = parsed.param_types
        && let Some(statement) = session.statements.get_mut(&parsed.statement_id)
    {
        statement.last_param_types = param_types;
    }
    for warning in parsed.warnings {
        host.warning(warning).await?;
    }
    query(
        io,
        host,
        session,
        Request {
            command: "COM_STMT_EXECUTE",
            sql: Some(&statement.sql),
            params: parsed.params.as_deref(),
        },
        ResultRowEncoding::Binary,
    )
    .await
}

pub(super) async fn control<H: ServerHost>(
    io: &mut dyn ConnectionIo,
    host: &H,
    session: &mut Session<H::SessionContext>,
    request: Request<'_>,
) -> Result<Directive> {
    let selected = host.select(session, request).await?;
    if let Some(delivery) = selected.delivery {
        let (outcome, response) = H::response(&delivery);
        let successful = outcome == traffic_model::DependencyExchangeOutcome::Response
            && response.status == "ok";
        let directive = host
            .deliver(io, session, delivery, ResultRowEncoding::Text)
            .await?;
        if directive == Directive::Continue && successful && request.command == "COM_INIT_DB" {
            session.database = request.sql.map(ToOwned::to_owned);
        }
        return Ok(directive);
    }
    if request.command == "COM_INIT_DB" {
        session.database = request.sql.map(ToOwned::to_owned);
    }
    crate::diagnostics::response_kind("control_ok", Some(session.status_flags));
    let mut output = output::packet(MysqlPacket {
        sequence_id: 1,
        payload: crate::response::ok_payload_with_status(0, 0, session.status_flags),
    });
    traffic_replay::output::deliver(io, &mut output, None).await?;
    host.builtin_delivered(session, &selected.context, request, None)
        .await?;
    Ok(Directive::Continue)
}
