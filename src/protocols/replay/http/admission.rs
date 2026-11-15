//! HTTP observations join the framework's bounded request admission loop.
use super::*;
use crate::replay::admission::{
    RequestAdmission,
    request::{self, DependencyRequestAdapter},
};

struct HttpRequest<'a> {
    request: contracts::RequestView<'a>,
    host: Option<&'a str>,
    admission: &'a mut ingress::Admission,
    unmatched_before: usize,
    unsupported_before: usize,
    dirty_before: bool,
    waitable: bool,
}

impl DependencyRequestAdapter<ReplayState> for HttpRequest<'_> {
    type Matched = std::result::Result<RecordedHttpExchange, HttpReplayMatchError>;
    type Error = HttpReplayMatchError;

    fn sequence_request_bytes(&self) -> Option<usize> {
        Some(
            self.request.body.len()
                + self.request.uri.to_string().len()
                + self
                    .request
                    .headers
                    .iter()
                    .map(|(name, values)| {
                        name.len() + values.iter().map(String::len).sum::<usize>()
                    })
                    .sum::<usize>(),
        )
    }

    fn observe_once(&mut self, state: &mut ReplayState) -> RequestAdmission {
        RequestAdmission::capture(
            state,
            None,
            Some(self.request.started_at),
            self.request.observation_id,
            false,
        )
    }

    fn try_select(
        &mut self,
        state: &mut ReplayState,
        _observation: &RequestAdmission,
    ) -> std::result::Result<Self::Matched, Self::Error> {
        if state.async_case_quiescing() {
            return Ok(Err(HttpReplayMatchError::Blackhole));
        }
        self.unmatched_before = state.protocols.http_events.unmatched.len();
        self.unsupported_before = state.protocols.http_events.unsupported.len();
        self.dirty_before = self
            .admission
            .case_id()
            .is_some_and(|case| state.protocols.http_events.dirty_case_ids.contains(case));
        let result = state.match_http_request_admitted(
            self.request.scheme,
            self.request.target,
            self.request.method,
            self.request.uri,
            self.host,
            self.request.body,
            self.request.headers,
            self.request.started_at,
            Some(self.admission),
        );
        self.waitable = state.protocols.http_events.unmatched.len() > self.unmatched_before
            && state.protocols.http_events.unsupported.len() == self.unsupported_before;
        match result {
            Err(error @ HttpReplayMatchError::BadGateway(_)) => Err(error),
            result => Ok(result),
        }
    }

    fn interrupted(&self, reason: &'static str) -> Self::Error {
        HttpReplayMatchError::BadGateway(reason.into())
    }

    fn sequence_wait_allowed(&self, _state: &ReplayState, _error: &Self::Error) -> bool {
        self.waitable
    }

    fn on_sequence_wait(&mut self, state: &mut ReplayState) {
        state
            .protocols
            .http_events
            .unmatched
            .truncate(self.unmatched_before);
        if !self.dirty_before
            && let Some(case) = self.admission.case_id()
        {
            state.protocols.http_events.dirty_case_ids.remove(case);
        }
    }

    fn on_selected(
        &mut self,
        _state: &mut ReplayState,
        _observation: &RequestAdmission,
        _matched: &mut Self::Matched,
    ) -> std::result::Result<(), Self::Error> {
        self.admission.complete();
        Ok(())
    }

    fn on_rejected(
        &mut self,
        state: &mut ReplayState,
        _observation: &RequestAdmission,
        error: &Self::Error,
    ) {
        self.admission.complete();
        if let HttpReplayMatchError::BadGateway(reason) = error {
            if state.protocols.http_events.unmatched.len() == self.unmatched_before {
                state.record_unmatched_http_for(
                    self.admission.case_id().map(str::to_owned),
                    self.request.scheme,
                    self.request.target,
                    self.request.method,
                    self.request.uri,
                    reason.clone(),
                );
            }
            if let Some(event) = state.protocols.http_events.unmatched.last_mut() {
                event.reason = reason.clone();
                event.request_fingerprint = Some(cross_case::request_fingerprint(
                    &self.request.uri.to_string(),
                    self.request.body,
                    self.request.headers,
                ));
            }
        }
    }
}

pub(super) async fn select<'a>(
    state: &Arc<Mutex<ReplayState>>,
    request: contracts::RequestView<'a>,
    host: Option<&'a str>,
    admission: &'a mut ingress::Admission,
) -> std::result::Result<RecordedHttpExchange, HttpReplayMatchError> {
    let mut adapter = HttpRequest {
        request,
        host,
        admission,
        unmatched_before: 0,
        unsupported_before: 0,
        dirty_before: false,
        waitable: false,
    };
    request::execute(
        state,
        &mut adapter,
        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .await?
}

pub(super) async fn wait_output(state: &Arc<Mutex<ReplayState>>, index: usize) -> Result<()> {
    let claim = state
        .lock()
        .await
        .protocols
        .http_sequence_claims
        .get(&index)
        .cloned();
    if let Some(claim) = claim {
        claim
            .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(30))
            .await?;
    }
    Ok(())
}
