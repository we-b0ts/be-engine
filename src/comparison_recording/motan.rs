use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use motan_codec::inspect_request;
use motan_protocol::{Frame, FrameDecoder, Limits, MessageKind, ProtocolVersion, ResponseKind};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use super::model::{
    ComparisonRecordingCase, ComparisonRecordingRequest, ComparisonRecordingResponse,
};
use super::runtime::{ComparisonRecordingRuntime, UpstreamRole, update_upstream_counts};
use super::upstream::{UpstreamCapture, UpstreamErrorKind, request_body_capture};
use crate::gateway::motan::{rules, transport};
use crate::recorder::{HeaderMapSnapshot, capture_case_body};

pub(super) async fn run_listener(
    listener: TcpListener,
    runtime: ComparisonRecordingRuntime,
) -> Result<()> {
    let max_connections = runtime.motan_gateway.max_connections;
    let connections = std::sync::Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut tasks = JoinSet::new();
    info!(
        listen = %runtime.motan_gateway.listen,
        baseline = %runtime.motan_gateway.matched_upstream,
        candidate = %runtime.candidate_motan_upstream,
        "Motan comparison gateway listening"
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept Motan comparison client")?;
                let Ok(connection_permit) = connections.clone().try_acquire_owned() else {
                    runtime.store.summary().update(|counts| counts.overloaded += 1).await;
                    drop(stream);
                    continue;
                };
                let runtime = runtime.clone();
                tasks.spawn(async move {
                    let _connection_permit = connection_permit;
                    if let Err(error) = handle_connection(stream, peer.to_string(), runtime).await {
                        warn!(%peer, %error, "Motan comparison connection ended with error");
                    }
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    warn!(%error, "Motan comparison connection task failed");
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: String,
    runtime: ComparisonRecordingRuntime,
) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("failed to configure Motan comparison TCP_NODELAY")?;
    let limits = limits(&runtime);
    let mut decoder = FrameDecoder::new(limits)?;
    while let Some(request) = transport::read_frame(&mut stream, &mut decoder, limits).await? {
        runtime
            .store
            .summary()
            .update(|counts| counts.received += 1)
            .await;
        if request.kind != MessageKind::Request {
            bail!("Motan comparison client sent a response frame");
        }
        let envelope = match inspect_request(&request) {
            Ok(envelope) => envelope,
            Err(error) => {
                runtime
                    .store
                    .summary()
                    .update(|counts| counts.unmatched += 1)
                    .await;
                warn!(%peer, %error, "Motan comparison request identity is malformed");
                transport::write_fixed_response(&mut stream, &request, limits).await?;
                continue;
            }
        };
        if envelope.heartbeat {
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        }
        let Some(matched) = rules::evaluate_request(&runtime.motan_gateway.rules, &envelope) else {
            runtime
                .store
                .summary()
                .update(|counts| counts.unmatched += 1)
                .await;
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        };
        let api_pattern = format!("/rpc/{}", rules::api_directory(&matched.descriptor));
        let motan_method = "MOTAN".parse().expect("MOTAN is a valid HTTP token");
        let motan_uri = api_pattern
            .parse()
            .expect("generated Motan API path is valid");
        if !runtime.recording_apis.is_empty()
            && !runtime
                .recording_apis
                .iter()
                .any(|api| api.matches(&motan_method, &motan_uri))
        {
            runtime
                .store
                .summary()
                .update(|counts| counts.excluded += 1)
                .await;
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        }
        if !runtime.ready.load(std::sync::atomic::Ordering::Acquire) {
            runtime
                .store
                .summary()
                .update(|counts| counts.not_ready += 1)
                .await;
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        }
        let Ok(permit) = runtime.active_case_permits.clone().try_acquire_owned() else {
            runtime
                .store
                .summary()
                .update(|counts| counts.overloaded += 1)
                .await;
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        };
        let Some(reservation) = runtime
            .store
            .try_reserve(
                &format!("MOTAN {api_pattern}"),
                runtime.motan_gateway.max_cases_per_api,
            )
            .await
        else {
            drop(permit);
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        };
        runtime
            .store
            .summary()
            .update(|counts| {
                counts.matched += 1;
                counts.dual_dispatched += 1;
            })
            .await;
        let request_record = ComparisonRecordingRequest {
            protocol: "motan",
            timestamp: Utc::now(),
            client_addr: Some(peer.clone()),
            method: "MOTAN".to_string(),
            uri: api_pattern.clone(),
            authority: None,
            matched_rule: matched.rule_name.clone(),
            api_pattern: api_pattern.clone(),
            headers: HeaderMapSnapshot::new(),
            body: request_body_capture(request.raw(), false, Some(request.raw().len())),
            protocol_version: Some(protocol_version(request.version)),
            request_id: Some(request.request_id),
            api_key: Some(matched.descriptor.api_key.clone()),
        };

        let baseline = fetch(&runtime, &request, &runtime.motan_gateway.matched_upstream).await;
        update_upstream_counts(&runtime, UpstreamRole::Baseline, &baseline.capture).await;
        // Preserve what `write_downstream` needs from the baseline before
        // `baseline.capture.record` is moved into the case below. `response` is
        // cloned (an `Option<Frame>`); `error_kind` is `Copy`.
        let baseline_response = baseline.response.clone();
        let baseline_error_kind = baseline.capture.error_kind;
        let candidate = fetch(&runtime, &request, &runtime.candidate_motan_upstream).await;
        update_upstream_counts(&runtime, UpstreamRole::Candidate, &candidate.capture).await;
        let baseline_recheck = if runtime.comparison_recording.baseline_recheck {
            let capture = fetch(&runtime, &request, &runtime.motan_gateway.matched_upstream).await;
            update_upstream_counts(&runtime, UpstreamRole::BaselineRecheck, &capture.capture).await;
            Some(capture)
        } else {
            None
        };
        runtime
            .store
            .summary()
            .update(|counts| counts.dual_completed += 1)
            .await;
        runtime
            .store
            .summary()
            .api_update(&format!("MOTAN {api_pattern}"), |counts| {
                counts.last_observed_at = Some(Utc::now());
                counts.last_baseline_status = baseline.capture.record.status;
                counts.last_candidate_status = candidate.capture.record.status;
                counts.last_baseline_error = baseline.capture.record.error.clone();
                counts.last_candidate_error = candidate.capture.record.error.clone();
                counts.last_baseline_recheck_status = baseline_recheck
                    .as_ref()
                    .and_then(|value| value.capture.record.status);
                counts.last_baseline_recheck_error = baseline_recheck
                    .as_ref()
                    .and_then(|value| value.capture.record.error.clone());
            })
            .await;
        let case = ComparisonRecordingCase {
            id: Uuid::new_v4(),
            group: matched.directory,
            request: request_record,
            baseline: baseline.capture.record,
            candidate: candidate.capture.record,
            baseline_recheck: baseline_recheck.map(|value| value.capture.record),
        };
        if let Err(error) = runtime.store.publish(&case, reservation).await {
            warn!(%error, case_id = %case.id, "failed to publish Motan comparison case");
        }
        drop(permit);
        // Return the baseline response only after the case is published and the
        // active-case permit is released. This aligns the Motan path with the
        // HTTP path (`run_dual` sends the baseline back after `drop(permit)`):
        // the managed input driver treats a received response as "the previous
        // case finished", so responding earlier would let the next serialized
        // request arrive before the permit is freed, causing it to be dropped as
        // `overloaded` under `max_in_flight == 1`. `baseline_response` and
        // `baseline_error_kind` were saved before `baseline.capture.record`
        // moved into the case above.
        write_downstream_response(
            &mut stream,
            &request,
            baseline_response,
            baseline_error_kind,
            limits,
        )
        .await?;
    }
    Ok(())
}

struct MotanCapture {
    capture: UpstreamCapture,
    response: Option<Frame>,
}

async fn fetch(
    runtime: &ComparisonRecordingRuntime,
    request: &Frame,
    upstream: &str,
) -> MotanCapture {
    let started = Instant::now();
    let result = transport::forward_request(
        request,
        upstream,
        Duration::from_millis(runtime.motan_gateway.connect_timeout_ms),
        Duration::from_millis(runtime.comparison_recording.upstream_timeout_ms),
        limits(runtime),
    )
    .await;
    match result {
        Ok(response) => {
            let (status, rpc_status, body, response_version, serialization) =
                match response.as_ref() {
                    Some(frame) => {
                        let kind = frame.response_kind().unwrap_or(ResponseKind::Other(0));
                        (
                            Some(status_code(kind)),
                            Some(kind.as_str()),
                            capture_case_body(
                                &frame.body,
                                runtime.config.recording.max_body_bytes,
                                runtime.config.recording.decoded_body_limit(),
                                None,
                            ),
                            frame.version,
                            frame.serialization,
                        )
                    }
                    None => (
                        Some(204),
                        Some("oneway"),
                        capture_case_body(&[], 0, 0, None),
                        request.version,
                        request.serialization,
                    ),
                };
            MotanCapture {
                capture: UpstreamCapture {
                    record: ComparisonRecordingResponse {
                        version: 1,
                        timestamp: Utc::now(),
                        upstream: upstream.to_string(),
                        status,
                        headers: None,
                        body: Some(body),
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                        protocol_version: Some(protocol_version(response_version)),
                        serialization,
                        rpc_status,
                    },
                    downstream: None,
                    error_kind: None,
                },
                response,
            }
        }
        Err(error) => MotanCapture {
            capture: super::upstream::failed_capture(
                upstream,
                started.elapsed().as_millis(),
                error.to_string(),
                UpstreamErrorKind::Request,
            ),
            response: None,
        },
    }
}

async fn write_downstream_response(
    stream: &mut TcpStream,
    request: &Frame,
    response: Option<Frame>,
    error_kind: Option<UpstreamErrorKind>,
    limits: Limits,
) -> Result<()> {
    if let Some(response) = response {
        transport::write_frame(stream, &response).await
    } else if request.flags.oneway() && error_kind.is_none() {
        Ok(())
    } else {
        transport::write_fixed_response(stream, request, limits).await?;
        Ok(())
    }
}

fn limits(runtime: &ComparisonRecordingRuntime) -> Limits {
    Limits {
        max_frame_bytes: runtime.motan_gateway.max_frame_bytes,
        max_metadata_bytes: runtime.motan_gateway.max_frame_bytes,
        max_body_bytes: runtime.motan_gateway.max_frame_bytes,
    }
}

fn protocol_version(version: ProtocolVersion) -> &'static str {
    match version {
        ProtocolVersion::Motan1 => "motan1",
        ProtocolVersion::Motan2 => "motan2",
    }
}

fn status_code(kind: ResponseKind) -> u16 {
    match kind {
        ResponseKind::Normal => 200,
        ResponseKind::Value => 201,
        ResponseKind::Void => 204,
        ResponseKind::Attachment => 206,
        ResponseKind::Exception => 500,
        ResponseKind::Other(_) => 520,
    }
}
