//! HTTP response streams use semantic messages, independent of network chunking.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use tokio::time::{Duration, Instant, sleep_until};
mod transport;

use super::{HttpClient, ReplayResponse, elapsed_ms};
use crate::http::response_headers;
use crate::interaction::{
    lifecycle::{InteractionLifecycle, LifecycleDecision},
    model::{
        CloseObservation, EndReason, HttpStreamMode, InputActionKind, InputTranscript, OutputEvent,
        OutputObservation, TRANSCRIPT_VERSION,
    },
    stream::{StreamDecoder, StreamMessage},
};

pub(super) async fn execute_with_feedback(
    _client: &HttpClient,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
    body_limit: usize,
    mut dependency_failure: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<ReplayResponse> {
    transcript.validate()?;
    let subscription = transcript.http_stream_mode == HttpStreamMode::Subscription;
    ensure!(
        !subscription || request.method() == hyper::Method::GET,
        "HTTP subscription input requires a GET request"
    );
    let close_timing = client_close_timing(transcript)?;
    let started = Instant::now();
    let started_at = chrono::Utc::now();
    let mut client_close = close_timing
        .and_then(|timing| match timing {
            ClientCloseTiming::Absolute(offset) => Some(offset),
            ClientCloseTiming::AfterCompletion(_) => None,
        })
        .map(|offset| {
            started
                .checked_add(Duration::from_millis(offset))
                .context("recorded HTTP client close exceeds the monotonic clock range")
        })
        .transpose()?;
    let mut lifecycle = InteractionLifecycle::new(transcript.policy.clone(), 0)?;
    if !subscription {
        lifecycle.begin(0, 0)?;
    }
    let head_budget = header_timeout
        .min(Duration::from_millis(transcript.policy.request_timeout_ms))
        .min(Duration::from_millis(transcript.policy.max_duration_ms));
    let head_deadline = started + head_budget;
    let head_deadline = client_close.map_or(head_deadline, |close| close.min(head_deadline));
    let (response, transport) = tokio::select! {
        biased;
        _=crate::dependency::execution::rejected(&mut dependency_failure)=>return Err(crate::dependency::execution::UnmatchedDependency {observed_status:None}.into()),
        response=tokio::time::timeout_at(head_deadline,transport::request(request))=>response.context("recorded stream response headers timed out")?.context("recorded stream request failed")?,
    };
    ensure!(
        client_close.is_none_or(|close| Instant::now() < close),
        "recorded HTTP client closed before Target response headers"
    );
    let status = response.status();
    ensure!(
        crate::interaction::stream::response_protocol(response.headers())
            == Some(transcript.protocol),
        "Target stream protocol differs from response content type"
    );
    ensure!(
        response
            .headers()
            .get("content-encoding")
            .is_none_or(|value| value.as_bytes().eq_ignore_ascii_case(b"identity")),
        "recorded stream requires an uncompressed Target response"
    );
    let headers = response_headers::snapshot_standard(response.headers());
    if subscription {
        lifecycle.activity(elapsed_ms(started));
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    let mut events = Vec::new();
    let mut decoder = StreamDecoder::new(transcript.protocol, transcript.policy.max_message_bytes)?;
    let (reason, transport_clean) = loop {
        if dependency_failure
            .as_ref()
            .is_some_and(|failure| *failure.borrow())
        {
            break (EndReason::DependencyFailure, false);
        }
        let now = elapsed_ms(started);
        let lifecycle_deadline = started + Duration::from_millis(lifecycle.next_deadline_ms());
        if client_close.is_some_and(|close| close <= lifecycle_deadline && Instant::now() >= close)
        {
            break (EndReason::ClientClose, true);
        }
        match lifecycle.decision(now) {
            LifecycleDecision::Close(reason) => break (reason, true),
            LifecycleDecision::Fail(reason) => break (reason, false),
            _ => {}
        }
        let deadline =
            client_close.map_or(lifecycle_deadline, |close| close.min(lifecycle_deadline));
        let frame = tokio::select! {
            biased;
            _ = async { match dependency_failure.as_mut() {
                Some(failure) => {let _=failure.changed().await;},
                None => std::future::pending::<()>().await,
            } } => {
                if dependency_failure.as_ref().is_some_and(|failure|*failure.borrow()) {break (EndReason::DependencyFailure,false);}
                dependency_failure=None;
                continue;
            }
            _ = sleep_until(deadline) => continue,
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else {
            let tail = decoder.finish()?;
            observe(
                tail,
                transcript,
                &mut lifecycle,
                &mut events,
                elapsed_ms(started),
            )?;
            if lifecycle.is_pending(0) {
                lifecycle.complete(0, elapsed_ms(started))?;
            }
            break (EndReason::ServerEof, true);
        };
        let frame = frame.context("failed to read recorded stream response body")?;
        if let Ok(data) = frame.into_data() {
            ensure!(
                bytes.len().saturating_add(data.len()) <= body_limit
                    && bytes.len().saturating_add(data.len()) <= transcript.policy.max_total_bytes,
                "recorded stream response body exceeds configured limit"
            );
            bytes.extend_from_slice(&data);
            let was_pending = lifecycle.is_pending(0);
            observe(
                decoder.feed(&data)?,
                transcript,
                &mut lifecycle,
                &mut events,
                elapsed_ms(started),
            )?;
            if was_pending
                && !lifecycle.is_pending(0)
                && let Some(ClientCloseTiming::AfterCompletion(gap_ms)) = close_timing
            {
                // Source proves this close followed its terminal message. Bind
                // to actual Target completion and preserve the recorded gap.
                client_close = Some(
                    Instant::now()
                        .checked_add(Duration::from_millis(gap_ms))
                        .context("recorded HTTP close gap exceeds the monotonic clock range")?,
                );
            }
        }
    };
    let partial_message = if matches!(
        reason,
        EndReason::ClientClose | EndReason::DependencyFailure
    ) {
        decoder.partial_message()
    } else {
        decoder.validate_boundary()?;
        None
    };
    if let Some(partial) = &partial_message {
        lifecycle.record_message(partial.decode()?.len())?;
    }
    if matches!(
        reason,
        EndReason::ClientClose | EndReason::DependencyFailure
    ) {
        // HTTP/1 FIN permits the server to finish its response. This semantic
        // cancellation needs a connection end on its own dedicated transport.
        transport.cancel()?;
    }
    drop(body);
    let mut end = lifecycle.end_observation(reason, elapsed_ms(started), transport_clean);
    end.partial_message = partial_message;
    if reason == EndReason::ClientClose {
        end.close = Some(CloseObservation {
            code: None,
            reason: String::new(),
        });
    }
    Ok(ReplayResponse {
        started_at,
        status,
        headers,
        body: Bytes::from(bytes),
        observation: OutputObservation {
            version: TRANSCRIPT_VERSION,
            protocol: transcript.protocol,
            events,
            end,
        },
    })
}

#[cfg(test)]
async fn execute(
    client: &HttpClient,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
    body_limit: usize,
) -> Result<ReplayResponse> {
    execute_with_feedback(
        client,
        request,
        transcript,
        header_timeout,
        body_limit,
        None,
    )
    .await
}

#[derive(Clone, Copy)]
enum ClientCloseTiming {
    Absolute(u64),
    AfterCompletion(u64),
}

fn client_close_timing(transcript: &InputTranscript) -> Result<Option<ClientCloseTiming>> {
    match transcript.actions.as_slice() {
        [] => Ok(None),
        [action] => {
            ensure!(
                matches!(&action.action, InputActionKind::Close { code: None, reason } if reason.is_empty())
                    && action.sequence == 1
                    && action.ack_ref.is_none()
                    && !action.compressible_gap,
                "HTTP stream input supports only an uncompressed empty client close action"
            );
            let timing = match (action.after.as_slice(), action.gap_start_ms) {
                ([], None) => ClientCloseTiming::Absolute(action.offset_ms),
                ([0], Some(start)) if start <= action.offset_ms => {
                    ClientCloseTiming::AfterCompletion(if transcript.policy.preserve_input_timing {
                        action.offset_ms - start
                    } else {
                        0
                    })
                }
                _ => anyhow::bail!("HTTP client close has an invalid completion barrier"),
            };
            Ok(Some(timing))
        }
        _ => anyhow::bail!("HTTP stream input supports at most one client close action"),
    }
}

fn observe(
    messages: Vec<StreamMessage>,
    transcript: &InputTranscript,
    lifecycle: &mut InteractionLifecycle,
    events: &mut Vec<OutputEvent>,
    now: u64,
) -> Result<()> {
    for message in messages {
        lifecycle.record_message(message.message.decode()?.len())?;
        if !message.heartbeat {
            lifecycle.activity(now);
        }
        if message.is_terminal_for(transcript.protocol, &transcript.policy.stream_terminal)?
            && lifecycle.is_pending(0)
        {
            lifecycle.complete(0, now)?;
        }
        events.push(OutputEvent {
            sequence: events.len() as u64,
            offset_ms: now,
            message: message.message,
            heartbeat: message.heartbeat,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
