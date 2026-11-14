//! MySQL native hooks use the common observation/selection engine.
//! Transaction, isolation, savepoint and optional-end decisions remain native.
use super::*;
use crate::replay::admission::{
    RequestAdmission,
    request::{DependencyRequestAdapter, WaitDependency, execute},
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
    session: &'a ReplaySession,
    command: &'a str,
    sql: Option<&'a str>,
    params: Option<&'a [RecordedMysqlValue]>,
    case: Option<String>,
    observation: Option<RequestAdmission>,
    recorded_rejection: Option<String>,
    terminal_reason: std::cell::Cell<Option<&'static str>>,
    isolation_deadline: tokio::time::Instant,
}

impl DependencyRequestAdapter<ReplayState> for NativeRequest<'_> {
    type Matched = MatchedExchange;
    type Error = &'static str;
    fn sequence_request_bytes(&self) -> Option<usize> {
        let params = self
            .params
            .into_iter()
            .flatten()
            .map(|value| {
                value.kind.len()
                    + value.raw.as_ref().map_or(0, |raw| raw.data.len())
                    + value
                        .value
                        .as_ref()
                        .map_or(0, |value| value.as_str().map_or(32, str::len))
            })
            .sum::<usize>();
        Some(self.command.len() + self.sql.map_or(0, str::len) + params)
    }

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
        if self.command == "COM_PING" {
            return Err("MySQL ping is handled by the replay server");
        }
        let identity = self.session.identity();
        if self.command == "COM_INIT_DB" {
            return state
                .match_mysql_control(self.case.as_deref(), &identity, self.command, self.sql)
                .ok_or("no finite MySQL control candidate");
        }
        if self.command == "COM_STMT_PREPARE"
            && !state
                .mysql
                .has_finite_prepare(self.case.as_deref(), &identity)
        {
            return Err("no finite MySQL prepare candidate");
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
                witness: &self.session.transaction_witness,
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
        selected.ok_or("no finite MySQL semantic candidate")
    }

    fn interrupted(&self, reason: &'static str) -> &'static str {
        self.terminal_reason.set(Some(reason));
        reason
    }
    fn sequence_wait_allowed(&self, _state: &ReplayState, error: &Self::Error) -> bool {
        self.recorded_rejection.is_none()
            && !matches!(
                *error,
                "MySQL ping is handled by the replay server"
                    | "no finite MySQL prepare candidate"
                    | "no finite MySQL control candidate"
            )
            && !self.sql.is_some_and(|sql| {
                super::session_setup::is_mysql_session_setup_sql(sql)
                    && builtin_response(sql, self.session.database.as_deref()).is_some()
            })
    }

    fn on_selected(
        &mut self,
        _state: &mut ReplayState,
        observation: &RequestAdmission,
        matched: &mut MatchedExchange,
    ) -> std::result::Result<(), &'static str> {
        matched.report.target_event_index = observation.event_index;
        Ok(())
    }
    fn wait_dependency<'a>(
        &self,
        state: &'a ReplayState,
        _observation: &RequestAdmission,
        _error: &Self::Error,
    ) -> Option<WaitDependency<'a>> {
        (self.recorded_rejection.is_none()
            && matches!(self.command, "COM_QUERY" | "COM_STMT_EXECUTE")
            && state.mysql.isolation.waiting_for_prior(
                self.session.transaction_witness.connection(),
                &SessionContext(&state.mysql.exchanges),
            )
            && self
                .sql
                .is_some_and(|sql| super::transaction_scope::is_business(&normalize_sql(sql))))
        .then(|| WaitDependency::changed(&state.mysql.lifecycle).until(self.isolation_deadline))
    }
}

pub(super) async fn match_request(
    shared: &Arc<Mutex<ReplayState>>,
    session: &ReplaySession,
    command: &str,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> RequestSelection {
    let isolation_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut adapter = NativeRequest {
        session,
        command,
        sql,
        params,
        case: None,
        observation: None,
        recorded_rejection: None,
        terminal_reason: std::cell::Cell::new(None),
        isolation_deadline,
    };
    let matched = execute(shared, &mut adapter, isolation_deadline).await.ok();
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
