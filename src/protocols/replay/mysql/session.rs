//! Application ownership and semantic commits around native MySQL sessions.
use super::*;

#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) fast_response_timing: bool,
    pub(super) transaction_scope: super::transaction_scope::Scope,
    pub(crate) savepoints: super::savepoints::Bindings,
    pub(crate) transaction_witness: super::transaction_equivalence::Witness,
}

pub(crate) type ReplaySession = traffic_protocol_mysql::server::Session<SessionState>;
pub(crate) use traffic_protocol_mysql::server::Directive as SessionDirective;

pub(crate) trait ReplaySessionExt {
    fn request_case(&self, state: &ReplayState, sql: Option<&str>) -> Option<String>;
    fn observe_response(
        &mut self,
        sql: &str,
        response: &RecordedMysqlResponse,
        case: Option<&str>,
        source_before: Option<u16>,
    );
}

impl ReplaySessionExt for ReplaySession {
    fn request_case(&self, state: &ReplayState, sql: Option<&str>) -> Option<String> {
        self.context
            .transaction_scope
            .case(state.active_case_id.as_deref(), sql)
    }

    fn observe_response(
        &mut self,
        sql: &str,
        response: &RecordedMysqlResponse,
        case: Option<&str>,
        source_before: Option<u16>,
    ) {
        if !matches!(response.status.as_str(), "ok" | "resultset") {
            return;
        }
        let before = self.status_flags;
        self.status_flags = traffic_protocol_mysql::session_status::after_response(
            before,
            sql,
            response.server_status,
            source_before,
        );
        let after = self.status_flags;
        self.context
            .transaction_scope
            .observe(before, after, sql, case);
    }
}

pub(super) async fn deliver_matched(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    mut matched: MatchedExchange,
    row_encoding: ResultRowEncoding,
) -> Result<SessionDirective> {
    let _delivery = matched.claim.guard();
    matched.claim.wait_sequence_delivery().await?;
    if let Some(owner) = &matched.hypothesis_owner
        && let Err(error) = owner.await_hypotheses_durable().await
    {
        state.lock().await.fail_exchange(
            &matched,
            &session.identity(),
            "hypothesis evidence persistence failed",
        );
        return Err(error);
    }
    if matched.record.lifecycle_cleanup {
        match super::lifecycle::deliver(
            stream,
            &state,
            &matched,
            session.request_started,
            row_encoding,
            session.context.fast_response_timing,
        )
        .await
        {
            Ok(()) => {
                matched.claim.publish_wire();
                ensure!(
                    state.lock().await.complete_exchange(&matched),
                    "MySQL cleanup claim was cancelled before completion"
                );
                return Ok(SessionDirective::Close);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .fail_exchange(&matched, &session.identity(), &error.to_string());
                return Err(error);
            }
        }
    }
    if matched.timing.outcome().is_client_terminated()
        || matched.timing.outcome().is_server_terminated()
    {
        let result = super::termination::deliver(
            stream,
            &matched,
            &session.control,
            session.request_started,
            row_encoding,
            session.context.fast_response_timing,
        )
        .await;
        match result {
            Ok(_) => {
                matched.claim.publish_wire();
                ensure!(
                    state.lock().await.complete_exchange(&matched),
                    "MySQL termination claim was cancelled before completion"
                );
                if matched.timing.outcome().termination().is_some_and(|end| {
                    end.side == crate::dependency::TerminationSide::Server
                        && end.kind == crate::dependency::TerminationKind::Eof
                }) {
                    let mut probe = [0_u8; 1];
                    if matches!(tokio::io::AsyncReadExt::read(stream, &mut probe).await, Ok(count) if count > 0)
                    {
                        state.lock().await.record_unmatched_in_case(
                            matched.report.case_id.as_deref(),
                            &session.identity(),
                            &matched.report.command,
                            matched.report.sql.as_deref(),
                            matched.report.params.as_deref(),
                            "client sent another MySQL request after recorded server EOF",
                        );
                        crate::replay::retain_connection(stream).await;
                    }
                }
                return Ok(SessionDirective::Close);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .fail_exchange(&matched, &session.identity(), &error.to_string());
                crate::replay::retain_connection(stream).await;
                return Err(error);
            }
        }
    }

    matched
        .timing
        .delay_response_from_request(
            session.request_started,
            session.context.fast_response_timing,
        )
        .await;
    let rendered_at = Utc::now();
    let mut delivered_identities = None;
    if let Some(prepared) = &matched.value_delivery {
        match prepared.render(rendered_at) {
            Ok((response, identities)) => {
                matched.record.response = response;
                delivered_identities = identities;
            }
            Err(error) => {
                state.lock().await.fail_exchange(
                    &matched,
                    &session.identity(),
                    &format!("SQL response contract: {error:#}"),
                );
                return Err(error);
            }
        }
    }
    let target_status_before = session.status_flags;
    session.observe_response(
        matched.record.sql.as_deref().unwrap_or_default(),
        &matched.record.response,
        matched.report.case_id.as_deref(),
        matched.record.server_status_before,
    );
    if matches!(matched.record.response.status.as_str(), "ok" | "resultset")
        && let Some(owner) = &matched.transaction_owner
        && session.context.transaction_scope.confirm(owner).is_err()
    {
        matched.report.case_id = session.context.transaction_scope.case(None, None);
        let error = "MySQL transaction contains conflicting Case and Global ownership evidence";
        state
            .lock()
            .await
            .fail_exchange(&matched, &session.identity(), error);
        return Err(anyhow!(error));
    }
    if let Err(error) = super::response::write_response_ordered(
        stream,
        &matched.record.response,
        row_encoding,
        session.status_flags,
        matched.claim.sequence(),
    )
    .await
    {
        state.lock().await.fail_exchange(
            &matched,
            &session.identity(),
            &format!("failed to deliver recorded MySQL response: {error}"),
        );
        return Err(error);
    }
    matched.claim.publish_wire();
    // These are facts about bytes already flushed to the native client. Another
    // connection may immediately copy them while the async report mutex is held.
    // Their success/error still enters the shared terminal transaction below.
    let copy_commit = if let Some(prepared) = &matched.time_copy_delivery {
        prepared.commit_after_wire(
            matched.report.case_id.as_deref(),
            &session.identity(),
            &matched.record.response,
            matched.report.sql.as_deref(),
        )
    } else {
        Ok(())
    };
    let mut replay = state.lock().await;
    let policy_owner = replay
        .replay_policy
        .as_ref()
        .map(|policy| policy.request_contracts.clone());
    let completed = replay.finish_mysql_exchange(&matched, || {
        copy_commit?;
        if let Some(prepared) = &matched.value_delivery {
            prepared.commit(
                policy_owner
                    .as_ref()
                    .context("MySQL response contract owner is unavailable")?,
                &matched.record.response,
                rendered_at,
                delivered_identities,
            )?;
        }
        Ok(())
    })?;
    ensure!(
        completed,
        "MySQL response claim was cancelled before completion"
    );
    session.context.savepoints.observe(
        &matched.record,
        matched.report.sql.as_deref().unwrap_or_default(),
    );
    let identity = session.identity();
    let after = session.status_flags;
    replay.observe_mysql_transaction(
        &mut session.context.transaction_witness,
        super::transaction_equivalence::Delivery {
            command: &matched.report.command,
            params: matched.report.params.as_deref(),
            sql: matched.report.sql.as_deref().unwrap_or_default(),
            index: Some(matched.index),
            successful: matches!(matched.record.response.status.as_str(), "ok" | "resultset"),
            before: target_status_before,
            after,
        },
        matched
            .request_observed_at
            .map(|requested_at| (&matched.record.response, requested_at, rendered_at)),
        matched.report.case_id.as_deref(),
        &identity,
    );
    Ok(SessionDirective::Continue)
}
