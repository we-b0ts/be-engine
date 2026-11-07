//! MySQL native hooks use the common observation/selection engine without waits.
//! Transaction, isolation, savepoint and optional-end decisions remain native.
use super::*;
use crate::replay::admission::{
    RequestAdmission,
    request::{DependencyRequestAdapter, execute},
};

pub(super) struct RequestSelection {
    pub(super) matched: Option<MatchedExchange>,
    pub(super) case_id: Option<String>,
    pub(super) observation_id: Option<String>,
    pub(super) event_index: Option<usize>,
    pub(super) recorded_rejection: Option<String>,
    pub(super) terminal_reason: Option<&'static str>,
}

struct NativeRequest<'a> {
    session: &'a mut ReplaySession,
    command: &'a str,
    sql: Option<&'a str>,
    params: Option<&'a [RecordedMysqlValue]>,
    case: Option<String>,
    observation: Option<RequestAdmission>,
    recorded_rejection: Option<String>,
    terminal_reason: std::cell::Cell<Option<&'static str>>,
}

impl DependencyRequestAdapter for NativeRequest<'_> {
    type Matched = MatchedExchange;
    type Error = &'static str;

    fn observe_once(&mut self, state: &mut ReplayState) -> RequestAdmission {
        let business = matches!(self.command, "COM_QUERY" | "COM_STMT_EXECUTE");
        self.case = self
            .session
            .request_case(state, business.then_some(self.sql).flatten());
        let observation = state.observe_mysql_request(
            self.case.as_deref(),
            &self.session.identity(),
            self.command,
            self.sql,
            self.params,
        );
        self.observation = Some(observation.clone());
        observation
    }

    fn try_select(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
    ) -> std::result::Result<MatchedExchange, &'static str> {
        let identity = self.session.identity();
        if matches!(self.command, "COM_PING" | "COM_INIT_DB") {
            return state
                .match_mysql_control(self.case.as_deref(), &identity, self.command, self.sql)
                .ok_or("no finite MySQL control candidate");
        }
        let transaction = matches!(self.command, "COM_QUERY" | "COM_STMT_EXECUTE").then(|| {
            matcher::TransactionMatch {
                savepoints: &self.session.savepoints,
                preferred_end: self.sql.and_then(|sql| {
                    state
                        .mysql
                        .transaction_equivalence
                        .preferred_end(&self.session.transaction_witness, sql)
                }),
                status_flags: self.session.status_flags,
                connection: self.session.transaction_witness.connection(),
                has_active_transaction: self.session.transaction_witness.has_active_transaction(),
                can_defer_first: self.session.transaction_witness.can_defer_first(),
                deferred_prefix: self
                    .session
                    .deferred_prefix
                    .as_ref()
                    .and_then(|first| first.matched.deferred_prefix),
            }
        });
        let unmatched_before = state.mysql.events.unmatched_queries.len();
        let selected = state.select_mysql_exchange(
            self.case.as_deref(),
            &identity,
            self.command,
            self.sql,
            self.params,
            transaction,
            observation,
        );
        self.recorded_rejection = state
            .mysql
            .events
            .unmatched_queries
            .get(unmatched_before)
            .map(|query| query.reason.clone());
        if selected.is_none()
            && self.recorded_rejection.is_none()
            && transaction.is_some_and(|context| context.deferred_prefix.is_some())
        {
            let reason = "MySQL next statement did not identify the reserved transaction prefix";
            state.record_unmatched_in_case(
                self.case.as_deref(),
                &identity,
                self.command,
                self.sql,
                self.params,
                reason,
            );
            self.recorded_rejection = Some(reason.into());
        }
        selected.ok_or("no finite MySQL semantic candidate")
    }

    fn interrupted(&self, reason: &'static str) -> &'static str {
        self.terminal_reason.set(Some(reason));
        reason
    }

    fn on_selected(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
        matched: &mut MatchedExchange,
    ) -> std::result::Result<(), &'static str> {
        matched.report.target_event_index = observation.event_index;
        if matches!(self.command, "COM_QUERY" | "COM_STMT_EXECUTE")
            && let Some(first) = self.session.deferred_prefix.take()
            && let Err(error) = state.bind_mysql_prefix(*first, matched.index, self.session)
        {
            let reason = error.to_string();
            state.fail_exchange(matched, &self.session.identity(), &reason);
            self.recorded_rejection = Some(reason);
            return Err("MySQL transaction prefix confirmation failed");
        }
        Ok(())
    }
    // No wait_dependency override: MySQL keeps its existing native constraints,
    // without importing another protocol's lane barriers. A rejected finite
    // candidate may still have a genuine native builtin/prepare response; the
    // protocol response owner resolves that before publishing unmatched evidence.
}

pub(super) async fn match_request(
    shared: &Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    command: &str,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> RequestSelection {
    let mut adapter = NativeRequest {
        session,
        command,
        sql,
        params,
        case: None,
        observation: None,
        recorded_rejection: None,
        terminal_reason: std::cell::Cell::new(None),
    };
    let matched = execute(shared, &mut adapter, tokio::time::Instant::now())
        .await
        .ok();
    let observation = adapter.observation;
    RequestSelection {
        matched,
        case_id: adapter.case,
        event_index: observation
            .as_ref()
            .and_then(|observation| observation.event_index),
        recorded_rejection: adapter.recorded_rejection,
        terminal_reason: adapter.terminal_reason.get(),
        observation_id: observation
            .as_ref()
            .and_then(|observation| {
                observation
                    .observation_id
                    .filter(|_| observation.observation_retained)
            })
            .map(|id| {
                crate::policy_evidence::target_observation_id(
                    &id.to_string(),
                    crate::policy::Surface::DependencyRequest,
                    crate::policy_evidence::TargetRole::IndependentTargetObservation,
                )
            }),
    }
}
