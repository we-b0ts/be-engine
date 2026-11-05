//! A single owner closes transports, preserves disconnect dependencies and publishes.

use super::SessionRef;
use crate::interaction::{lifecycle::LifecycleDecision, model::Protocol};
use crate::recorder::http::case::{
    CaseRequestRecord, CaseResponseRecord, finalize_owned_http_case, interaction_invalidation,
};
use crate::recorder::{CaseInvalidation, HeaderMapSnapshot, capture_case_body, redact_headers};
use crate::{ActiveCaseGuard, AppState};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use hyper::HeaderMap;
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

pub(super) struct RequestMeta {
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub uri: String,
    pub api_pattern: String,
    pub headers: HeaderMapSnapshot,
    pub raw_headers: HeaderMap,
    pub body: Bytes,
    pub client_addr: Option<String>,
}

#[derive(Debug)]
struct PrimaryFinalizationFailure(CaseInvalidation);

impl std::fmt::Display for PrimaryFinalizationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.message)
    }
}

impl std::error::Error for PrimaryFinalizationFailure {}

fn stop_failed_recording(session: &SessionRef) {
    session.state.begin_case_quiescing();
    session
        .state
        .inner
        .interactions
        .source_stop
        .send_replace(true);
}

pub(super) fn spawn(
    session: SessionRef,
    guard: impl Into<Arc<ActiveCaseGuard>>,
    meta: RequestMeta,
) {
    let guard = guard.into();
    let publication = session
        .state
        .inner
        .active_cases
        .register_case_publication(session.case.id)
        .expect("interaction retains its active case guard");
    session
        .state
        .inner
        .interactions
        .active
        .lock()
        .expect("interaction sessions poisoned")
        .insert(session.case.id, Arc::downgrade(&session));
    tokio::spawn(async move {
        let _guard = guard;
        if let Err(error) = run(&session, meta, &publication).await {
            let mut failure = error
                .downcast_ref::<PrimaryFinalizationFailure>()
                .map(|failure| failure.0.clone())
                .unwrap_or_else(|| {
                    CaseInvalidation::new(
                        "interaction_finalization_failed",
                        "interaction evidence could not be finalized",
                    )
                });
            let detail = error
                .chain()
                .filter(|cause| !cause.is::<PrimaryFinalizationFailure>())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(": ");
            failure
                .message
                .push_str(&format!("; finalization error: {detail}"));
            let _ = session
                .state
                .recorder()
                .fail_case_with_context(
                    &session.case,
                    failure.reason,
                    failure.message,
                    failure.context,
                )
                .await;
            stop_failed_recording(&session);
            tracing::warn!(%error, case_id = %session.case.id, "interaction finalization failed");
        }
        session
            .state
            .inner
            .interactions
            .active
            .lock()
            .expect("interaction sessions poisoned")
            .remove(&session.case.id);
    });
}

async fn run(
    session: &SessionRef,
    meta: RequestMeta,
    publication: &crate::active_case::CasePublication,
) -> anyhow::Result<()> {
    let protocol = session
        .observation
        .lock()
        .expect("interaction observation poisoned")
        .protocol();
    super::diagnostics::phase(session.case.id, protocol, "observing");
    super::diagnostics::waiting(session);
    let mut progress = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let reason = loop {
        if let Some(reason) = session.closing() {
            break reason;
        }
        let (decision, deadline) = {
            let observation = session
                .observation
                .lock()
                .expect("interaction observation poisoned");
            (
                observation.decision(session.now()),
                observation.next_deadline_ms(),
            )
        };
        match decision {
            LifecycleDecision::Close(reason) | LifecycleDecision::Fail(reason) => {
                session.request_close(reason);
                break reason;
            }
            _ => {}
        }
        let wake = Instant::from_std(session.started) + Duration::from_millis(deadline);
        tokio::select! {
            _ = sleep_until(wake) => {},
            _ = session.changed.notified() => {},
            _ = progress.tick() => super::diagnostics::waiting(session),
        }
    };
    session.request_close(reason);
    super::diagnostics::phase(session.case.id, protocol, "transport_cleanup_started");
    let (protocol, policy) = {
        let observation = session
            .observation
            .lock()
            .expect("interaction observation poisoned");
        (observation.protocol(), observation.policy().clone())
    };
    let cleanup_deadline = Instant::now() + Duration::from_millis(policy.cleanup_timeout_ms);
    let transport = async {
        if protocol == Protocol::SocketIo
            && !session.upgraded.load(Ordering::SeqCst)
            && super::query(&session.original_uri, "transport").as_deref() == Some("polling")
        {
            super::polling::close(session).await?;
        }
        while session.active_io.load(Ordering::SeqCst) != 0 {
            tokio::select! { _ = session.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(25)) => {} }
        }
        Ok::<_, anyhow::Error>(())
    };
    let transport_clean = matches!(
        tokio::time::timeout_at(cleanup_deadline, transport).await,
        Ok(Ok(()))
    ) && !session.transport_failed.load(Ordering::SeqCst);
    super::diagnostics::phase(session.case.id, protocol, "transport_cleanup_completed");
    if !transport_clean {
        for transport in session
            .transports
            .lock()
            .expect("interaction transports poisoned")
            .iter()
        {
            transport.abort();
        }
        tokio::task::yield_now().await;
    }
    let (finished_observation, observed_at, pending) = {
        let observation = session
            .observation
            .lock()
            .expect("interaction observation poisoned");
        let elapsed = session.now();
        (
            observation.finish(reason, elapsed, transport_clean),
            elapsed,
            observation.pending(),
        )
    };
    let client_disconnect_closed = reason == crate::interaction::model::EndReason::TransportError
        && super::recovery::client_disconnect_closed(
            session,
            session
                .state
                .active_case_invalidation(session.case.id)
                .as_ref(),
        );
    if !finished_observation
        .as_ref()
        .is_ok_and(|(_, output)| output.end.clean || client_disconnect_closed)
    {
        // The supervisor stops Source, then keeps Recorder and this case guard
        // alive until disconnect dependencies and failed evidence are written.
        stop_failed_recording(session);
    }
    // A streamed primary body is not a JSON response-condition document.
    session
        .state
        .select_case_response_observation(session.case.id, None);
    let stream_tail_deadline = session
        .state
        .inner
        .active_cases
        .stream_tail_deadline(session.case.id);
    let observation_deadline = stream_tail_deadline;
    // Transport cleanup keeps its own short budget. Dependency observation has
    // the primary request's absolute deadline and the same bounded writer drain.
    super::diagnostics::phase(session.case.id, protocol, "dependency_drain_started");
    let client_abort = finished_observation
        .as_ref()
        .ok()
        .and_then(|(input, output)| {
            output.end.interrupted_by_client().then(|| {
                let end = input.actions.last().expect("observed client transport end");
                session.started + Duration::from_millis(end.offset_ms)
            })
        });
    let drain = if let Some(aborted) = client_abort {
        session
            .state
            .inner
            .active_cases
            .observe_client_abort_tail(session.case.id, aborted)
            .await;
        session
            .state
            .drain_active_case_dependencies(session.case.id)
            .await
    } else if observation_deadline.is_some() {
        // This operation owns both its absolute observation limit and the
        // bounded drain measured from actual admission closure. An outer timer
        // must not cancel its close/report/publication handoff between phases.
        session
            .state
            .drain_active_case_dependencies(session.case.id)
            .await
    } else {
        match tokio::time::timeout_at(
            cleanup_deadline,
            session
                .state
                .drain_active_case_dependencies(session.case.id),
        )
        .await
        {
            Ok(drain) => drain,
            Err(_) => Some(CaseInvalidation::new(
                "interaction_cleanup_timeout",
                "interaction dependency collection exceeded the cleanup deadline",
            )),
        }
    };
    super::diagnostics::phase(session.case.id, protocol, "dependency_drain_completed");
    let dependencies_drained = drain.is_none();
    let invalidation = session
        .state
        .active_case_invalidation(session.case.id)
        .or(drain)
        .or_else(|| {
            (!transport_clean).then(|| {
                CaseInvalidation::new(
                    "interaction_transport_cleanup_timeout",
                    "interaction transport cleanup did not finish within the cleanup deadline",
                )
            })
        });
    // Even an unpublishable partial frame retains admitted dependencies until
    // their evidence is written. A decoder failure cannot move staging early.
    let (input, mut output) = match finished_observation {
        Ok(finished) => finished,
        Err(error) => {
            let mut commit = publication.begin().await;
            let mut failure = interaction_invalidation(
                reason,
                observed_at,
                &pending,
                commit.invalidation.clone(),
                invalidation,
            )
            .unwrap_or_else(|| {
                CaseInvalidation::new(
                    "interaction_finalization_failed",
                    "interaction evidence could not be finalized",
                )
            });
            failure
                .message
                .push_str(&format!("; finalization error: {error:#}"));
            let context = PrimaryFinalizationFailure(failure.clone());
            let result = session
                .state
                .recorder()
                .fail_case_with_context(
                    &session.case,
                    failure.reason,
                    failure.message,
                    failure.context,
                )
                .await;
            commit.finalized = true;
            return result.map_err(|error| error.context(context));
        }
    };
    let continue_after_failure = (output.end.clean || client_disconnect_closed)
        && dependencies_drained
        && super::recovery::can_continue(session, invalidation.as_ref());
    if invalidation.is_some() {
        output.end.clean = false;
    }
    if !output.end.clean && !continue_after_failure {
        stop_failed_recording(session);
    }
    let response = session
        .response
        .lock()
        .expect("interaction response poisoned")
        .clone();
    let config = session.state.config();
    let status = response.as_ref().map(|(status, _)| *status);
    let headers = response
        .as_ref()
        .map(|(_, headers)| redact_headers(headers, &config.recording.redact_headers));
    super::diagnostics::phase(session.case.id, protocol, "publication_started");
    finalize_owned_http_case(
        session.state.recorder(),
        publication,
        &session.case,
        CaseRequestRecord {
            timestamp: meta.timestamp,
            client_addr: meta.client_addr,
            method: meta.method,
            uri: meta.uri,
            api_pattern: Some(meta.api_pattern),
            authority: meta
                .raw_headers
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            matched_rule: Some(session.case.rule_name.clone()),
            upstream: session.upstream.clone(),
            headers: meta.headers,
            body: capture_case_body(
                &meta.body,
                config.recording.max_body_bytes,
                config.recording.decoded_body_limit(),
                Some(&meta.raw_headers),
            ),
            sse_observation: None,
            interaction: Some(input),
        },
        CaseResponseRecord {
            timestamp: Utc::now(),
            matched_rule: Some(session.case.rule_name.clone()),
            upstream: session.upstream.clone(),
            status,
            headers,
            body: Some(capture_case_body(
                b"",
                config.recording.max_body_bytes,
                config.recording.decoded_body_limit(),
                None,
            )),
            duration_ms: session.started.elapsed().as_millis(),
            error: None,
            sse_observation: None,
            interaction: Some(output),
        },
        invalidation.clone(),
    )
    .await?;
    super::diagnostics::phase(session.case.id, protocol, "publication_completed");
    {
        // Publication owns lease-loss ordering even when the primary transport
        // ended cleanly. A loss before its commit fails publication and requires
        // Source isolation; a loss after that commit cannot revoke it.
        let commit = publication.begin().await;
        if commit.invalidation.is_some() {
            stop_failed_recording(session);
        } else if continue_after_failure {
            if super::recovery::can_continue(session, invalidation.as_ref()) {
                tracing::warn!(case_id = %session.case.id,
                reason = invalidation.as_ref().map(|failure| failure.reason.as_str()),
                "failed streaming case finalized; continuing recording after dependency drain");
            } else {
                stop_failed_recording(session);
            }
        }
    }
    let mut sessions = session
        .state
        .inner
        .interactions
        .by_sid
        .lock()
        .expect("interaction sessions poisoned");
    sessions.retain(|_, active| active.case.id != session.case.id);
    Ok(())
}

impl AppState {
    pub(crate) fn close_interactions(&self) {
        self.inner.interactions.source_stop.send_replace(true);
        for session in self
            .inner
            .interactions
            .active
            .lock()
            .expect("interaction sessions poisoned")
            .values()
            .filter_map(std::sync::Weak::upgrade)
        {
            session.request_close(crate::interaction::model::EndReason::TransportError);
        }
    }
    pub(crate) async fn wait_for_interaction_source_stop(&self) {
        let mut requested = self.inner.interactions.source_stop.subscribe();
        loop {
            if *requested.borrow_and_update() {
                return;
            }
            if requested.changed().await.is_err() {
                return;
            }
        }
    }
}
