//! Bind native MySQL serving to shared admission, evidence and delivery owners.
use super::*;
use traffic_protocol::connection::NativeFuture;
use traffic_protocol_mysql::server::{Request, Selection, ServerHost};

pub(super) struct Host {
    pub(super) state: Arc<Mutex<ReplayState>>,
}

impl ServerHost for Host {
    type SessionContext = SessionState;
    type RequestContext = admission::RequestSelection;
    type Delivery = MatchedExchange;
    type Evidence = crate::dependency_index::RecordRef;

    fn stopping(&self) -> NativeFuture<'_, bool> {
        Box::pin(async {
            let state = self.state.lock().await;
            Ok(state.target_session_stopped
                || state.async_case_quiescing()
                || state
                    .active_case_id
                    .as_ref()
                    .is_some_and(|case| state.target_stop_prepared.contains(case)))
        })
    }

    fn response(
        delivery: &MatchedExchange,
    ) -> (crate::DependencyExchangeOutcome, &RecordedMysqlResponse) {
        (delivery.record.outcome, &delivery.record.response)
    }

    fn select<'a>(
        &'a self,
        session: &'a ReplaySession,
        request: Request<'a>,
    ) -> NativeFuture<'a, Selection<MatchedExchange, admission::RequestSelection>> {
        Box::pin(async move {
            let mut selected = admission::match_request(
                &self.state,
                session,
                request.command,
                request.sql,
                request.params,
            )
            .await;
            if let Some(reason) = selected.terminal_reason {
                return Err(anyhow!(reason));
            }
            if !matches!(request.command, "COM_PING" | "COM_INIT_DB")
                && let Some(reason) = selected.recorded_rejection.take()
            {
                return Err(anyhow!(reason));
            }
            Ok(Selection {
                delivery: selected.matched.take(),
                context: selected,
            })
        })
    }

    fn deliver<'a>(
        &'a self,
        io: &'a mut dyn MysqlReplayIo,
        session: &'a mut ReplaySession,
        delivery: MatchedExchange,
        encoding: ResultRowEncoding,
    ) -> NativeFuture<'a, SessionDirective> {
        Box::pin(deliver_matched(
            io,
            self.state.clone(),
            session,
            delivery,
            encoding,
        ))
    }

    fn statement_metadata<'a>(
        &'a self,
        session: &'a ReplaySession,
        context: &'a admission::RequestSelection,
        sql: &'a str,
    ) -> NativeFuture<'a, Arc<StatementMetadata>> {
        Box::pin(async move {
            Ok(self.state.lock().await.statement_metadata_in_case(
                context.case_id.as_deref(),
                &session.identity(),
                sql,
            ))
        })
    }

    fn before_builtin(
        &self,
        session: &mut ReplaySession,
        context: &admission::RequestSelection,
        request: Request<'_>,
        response: &RecordedMysqlResponse,
    ) {
        session.observe_response(
            request.sql.unwrap_or_default(),
            response,
            context.case_id.as_deref(),
            None,
        );
    }

    fn builtin_delivered<'a>(
        &'a self,
        session: &'a mut ReplaySession,
        context: &'a admission::RequestSelection,
        request: Request<'a>,
        previous_status: Option<u16>,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let reason = match request.command {
                "COM_QUERY" => "driver/session query handled by replay server",
                "COM_STMT_EXECUTE" => "prepared driver/session query handled by replay server",
                _ => "driver/session command handled by replay server",
            };
            let mut state = self.state.lock().await;
            let identity = session.identity();
            state.record_builtin_observed_in_case(
                context.case_id.as_deref(),
                &identity,
                request.command,
                request.sql,
                reason,
                context.event_index,
                context.observation_id.as_deref(),
            );
            if let Some(before) = previous_status {
                let sql = request.sql.unwrap_or_default();
                if matches!(
                    normalize_sql(sql).as_str(),
                    "begin" | "start transaction" | "commit" | "rollback"
                ) {
                    session.context.savepoints = Default::default();
                }
                let after = session.status_flags;
                state.observe_mysql_transaction(
                    &mut session.context.transaction_witness,
                    super::transaction_equivalence::Delivery {
                        command: request.command,
                        params: request.params,
                        sql,
                        index: None,
                        successful: true,
                        before,
                        after,
                    },
                    None,
                    context.case_id.as_deref(),
                    &identity,
                );
            }
            Ok(())
        })
    }

    fn unmatched<'a>(
        &'a self,
        session: &'a ReplaySession,
        context: Option<&'a admission::RequestSelection>,
        request: Request<'a>,
        reason: &'a str,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let case = match context {
                Some(context) => {
                    state
                        .protocols
                        .mysql
                        .isolation
                        .reject_connection(session.context.transaction_witness.connection());
                    context.case_id.clone()
                }
                None => session.request_case(&state, None),
            };
            state.record_unmatched_in_case(
                case.as_deref(),
                &session.identity(),
                request.command,
                request.sql,
                request.params,
                reason,
            );
            if let Some(context) = context
                && let Some(report) = state.protocols.mysql.events.unmatched_queries.last_mut()
            {
                report.target_observation_id = context.observation_id.clone();
                report.target_event_index = context.event_index;
            }
            Ok(())
        })
    }

    fn unsupported<'a>(
        &'a self,
        session: &'a ReplaySession,
        request: Request<'a>,
        reason: &'a str,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let case = session.request_case(&state, None);
            state.record_unsupported_in_case(
                case.as_deref(),
                &session.identity(),
                request.command,
                request.sql,
                request.params,
                reason,
            );
            Ok(())
        })
    }

    fn statement_closed<'a>(&'a self, session: &'a ReplaySession) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let case = session.request_case(&state, None);
            state.record_builtin_in_case(
                case.as_deref(),
                &session.identity(),
                "COM_STMT_CLOSE",
                None,
                "prepared statement closed without a server response",
            );
            Ok(())
        })
    }

    fn warning(&self, warning: String) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            self.state.lock().await.record_metadata_warning(warning);
            Ok(())
        })
    }
}
