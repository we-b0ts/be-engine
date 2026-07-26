use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use chrono::Utc;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use super::model::{ComparisonRecordingCase, ComparisonRecordingRequest};
use super::store::{ComparisonRecordingStore, Reservation};
use super::tasks::BackgroundTasks;
use super::upstream::{
    LimitedBodyError, ResponseDisposition, UpstreamCapture, UpstreamErrorKind, body_capture,
    collect_limited, collect_unlimited, downstream_response, fetch_upstream, run_ready_probe,
};
use crate::config::{AppConfig, ComparisonRecordingConfig, HttpGatewayConfig};
use crate::gateway::http::rules::{
    RuleDecision, evaluate_request, request_authority, resolve_case_group,
};
use crate::gateway::http::transport::{GatewayBody, simple_response};
use crate::recorder::redact_headers;
use crate::recording_api::{RecordingApi, validate_selection};

#[derive(Debug, Clone, Default)]
pub struct ComparisonRecordingRunOptions {
    pub run_id: Option<String>,
    pub duration: Option<Duration>,
    pub recording_apis: Vec<RecordingApi>,
}

#[derive(Clone)]
pub(super) struct ComparisonRecordingRuntime {
    pub(super) config: Arc<AppConfig>,
    pub(super) comparison_recording: ComparisonRecordingConfig,
    pub(super) baseline_upstream: String,
    pub(super) gateway: HttpGatewayConfig,
    pub(super) recording_apis: Vec<RecordingApi>,
    pub(super) client: crate::ProxyClient,
    pub(super) store: ComparisonRecordingStore,
    pub(super) ready: Arc<AtomicBool>,
    pub(super) ready_notify: Arc<Notify>,
    permits: Arc<Semaphore>,
    background: BackgroundTasks,
}

pub async fn run(config: AppConfig, run_id: Option<String>) -> Result<()> {
    run_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id,
            ..ComparisonRecordingRunOptions::default()
        },
    )
    .await
}

pub async fn run_with_duration(
    config: AppConfig,
    run_id: Option<String>,
    duration: Option<Duration>,
) -> Result<()> {
    run_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id,
            duration,
            ..ComparisonRecordingRunOptions::default()
        },
    )
    .await
}

pub async fn run_with_options(
    config: AppConfig,
    options: ComparisonRecordingRunOptions,
) -> Result<()> {
    let ComparisonRecordingRunOptions {
        run_id,
        duration,
        recording_apis,
    } = options;
    ensure!(
        duration.is_none_or(|duration| !duration.is_zero()),
        "comparison recording duration must be greater than zero"
    );
    config
        .validate_comparison_recording()
        .context("invalid comparison recording configuration")?;
    validate_selection(&recording_apis, &config.http_gateway.rules)
        .context("invalid comparison recording API selection")?;
    let comparison_recording = config.comparison_recording.clone().context(
        "record-comparison command requires a [comparison_recording] configuration section",
    )?;
    let baseline_upstream = comparison_recording
        .baseline_upstream(&config.http_gateway)
        .to_string();
    let run_id = run_id.unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());
    validate_run_id(&run_id)?;
    let store = ComparisonRecordingStore::create(
        &config.comparison_recording_output_dir(),
        &run_id,
        recording_apis.iter().map(ToString::to_string).collect(),
    )
    .await?;
    let gateway = config.http_gateway.clone();
    let listener = TcpListener::bind(gateway.listen).await.with_context(|| {
        format!(
            "failed to bind comparison recording gateway {}",
            gateway.listen
        )
    })?;
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let runtime = ComparisonRecordingRuntime {
        config: Arc::new(config),
        comparison_recording: comparison_recording.clone(),
        baseline_upstream: baseline_upstream.clone(),
        gateway: gateway.clone(),
        recording_apis,
        client,
        store,
        ready: Arc::new(AtomicBool::new(!gateway.ready.enabled)),
        ready_notify: Arc::new(Notify::new()),
        permits: Arc::new(Semaphore::new(comparison_recording.max_in_flight)),
        background: BackgroundTasks::new(),
    };
    if runtime.ready.load(Ordering::Acquire) {
        runtime.store.summary().set_ready().await;
    }
    let ready_task = gateway
        .ready
        .enabled
        .then(|| tokio::spawn(run_ready_probe(runtime.clone())));
    let summary_task = tokio::spawn(run_summary_flush(runtime.clone()));
    let duration_wait = wait_for_duration(runtime.clone(), duration);
    tokio::pin!(duration_wait);
    info!(
        listen = %gateway.listen,
        baseline = %baseline_upstream,
        candidate = %comparison_recording.candidate_upstream,
        run_id,
        "comparison recording gateway listening"
    );

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break;
            }
            _ = &mut duration_wait => {
                info!("comparison recording duration elapsed");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) =
                    accepted.context("failed to accept comparison recording client")?;
                let runtime = runtime.clone();
                connections.spawn(async move {
                    let service = service_fn(move |request| {
                        let runtime = runtime.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                handle_request(request, runtime, Some(peer.to_string())).await,
                            )
                        }
                    });
                    if let Err(error) = hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        warn!(%error, "comparison recording client connection ended with error");
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    warn!(%error, "comparison recording client connection task failed");
                }
            }
        }
    }
    drop(listener);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(task) = ready_task {
        task.abort();
        let _ = task.await;
    }
    summary_task.abort();
    let _ = summary_task.await;
    runtime
        .background
        .drain(Duration::from_millis(
            comparison_recording.upstream_timeout_ms.saturating_mul(
                if comparison_recording.baseline_recheck {
                    3
                } else {
                    2
                },
            ),
        ))
        .await;
    runtime.store.fail_unfinished().await?;
    runtime.store.summary().finish().await?;
    Ok(())
}

async fn wait_for_duration(runtime: ComparisonRecordingRuntime, duration: Option<Duration>) {
    let Some(duration) = duration else {
        std::future::pending::<()>().await;
        return;
    };
    while !runtime.ready.load(Ordering::Acquire) {
        let notified = runtime.ready_notify.notified();
        if runtime.ready.load(Ordering::Acquire) {
            break;
        }
        notified.await;
    }
    info!(
        duration_seconds = duration.as_secs_f64(),
        "comparison recording duration started"
    );
    tokio::time::sleep(duration).await;
}

async fn handle_request(
    request: Request<Incoming>,
    runtime: ComparisonRecordingRuntime,
    client_addr: Option<String>,
) -> Response<GatewayBody> {
    runtime
        .store
        .summary()
        .update(|counts| counts.received += 1)
        .await;
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let authority = request_authority(&uri, &headers);
    let recording_api_pattern = runtime
        .recording_apis
        .iter()
        .find(|api| api.matches(&method, &uri))
        .map(|api| api.path_pattern().to_string());
    let decision = evaluate_request(
        &runtime.gateway.exclude_rules,
        &runtime.gateway.rules,
        &method,
        &uri,
        &headers,
    );
    let matched = match decision {
        RuleDecision::Matched(rule)
            if runtime.recording_apis.is_empty() || recording_api_pattern.is_some() =>
        {
            Some(rule)
        }
        RuleDecision::Matched(_) => {
            runtime
                .store
                .summary()
                .update(|counts| counts.excluded += 1)
                .await;
            None
        }
        RuleDecision::Excluded { .. } => {
            runtime
                .store
                .summary()
                .update(|counts| counts.excluded += 1)
                .await;
            None
        }
        RuleDecision::Unmatched => {
            runtime
                .store
                .summary()
                .update(|counts| counts.unmatched += 1)
                .await;
            None
        }
    };
    let permit = if matched.is_some() && runtime.ready.load(Ordering::Acquire) {
        match runtime.permits.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                runtime
                    .store
                    .summary()
                    .update(|counts| counts.overloaded += 1)
                    .await;
                None
            }
        }
    } else {
        if matched.is_some() {
            runtime
                .store
                .summary()
                .update(|counts| counts.not_ready += 1)
                .await;
        }
        None
    };

    let mirrored = matched.is_some() && permit.is_some();
    let body_result = if mirrored {
        collect_limited(
            request.into_body(),
            runtime.comparison_recording.max_request_bytes,
        )
        .await
    } else {
        collect_unlimited(request.into_body()).await
    };
    let body = match body_result {
        Ok(body) => body,
        Err(LimitedBodyError::TooLarge) => {
            runtime
                .store
                .summary()
                .update(|counts| counts.request_too_large += 1)
                .await;
            return simple_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "comparison recording request body too large",
            );
        }
        Err(LimitedBodyError::Read(error)) => {
            return simple_response(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };

    let Some(rule) = matched else {
        runtime
            .store
            .summary()
            .update(|counts| counts.baseline_only += 1)
            .await;
        return forward_baseline(&runtime, &method, &uri, &headers, body).await;
    };
    let Some(permit) = permit else {
        runtime
            .store
            .summary()
            .update(|counts| counts.baseline_only += 1)
            .await;
        return forward_baseline(&runtime, &method, &uri, &headers, body).await;
    };
    runtime
        .store
        .summary()
        .update(|counts| {
            counts.matched += 1;
            counts.dual_dispatched += 1;
        })
        .await;
    runtime
        .store
        .summary()
        .set_in_flight(
            runtime
                .comparison_recording
                .max_in_flight
                .saturating_sub(runtime.permits.available_permits()),
        )
        .await;

    let group = recording_api_pattern.as_ref().map_or_else(
        || resolve_case_group(&uri, &rule.case_path_patterns),
        |pattern| resolve_case_group(&uri, std::slice::from_ref(pattern)),
    );
    let limit = runtime.gateway.case_limits.limit_for(&group.pattern);
    let reservation = runtime
        .store
        .try_reserve(&rule.name, &group.pattern, limit)
        .await;
    let request_record = ComparisonRecordingRequest {
        timestamp: Utc::now(),
        client_addr,
        method: method.to_string(),
        uri: uri.to_string(),
        authority,
        matched_rule: rule.name.clone(),
        api_pattern: group.pattern.clone(),
        headers: redact_headers(&headers, &runtime.config.recording.redact_headers),
        body: body_capture(&body, false, Some(body.len())),
    };
    let (sender, receiver) = oneshot::channel();
    let task_runtime = runtime.clone();
    runtime.background.spawn(async move {
        run_dual(
            task_runtime,
            method,
            uri,
            headers,
            body,
            rule.name,
            group.directory,
            group.pattern,
            request_record,
            reservation,
            permit,
            sender,
        )
        .await;
    });
    match receiver.await {
        Ok(capture) => downstream_response(&capture),
        Err(_) => simple_response(
            StatusCode::BAD_GATEWAY,
            "baseline comparison recording task failed",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_dual(
    runtime: ComparisonRecordingRuntime,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    rule: String,
    group: String,
    pattern: String,
    request: ComparisonRecordingRequest,
    reservation: Option<Reservation>,
    _permit: OwnedSemaphorePermit,
    baseline_sender: oneshot::Sender<UpstreamCapture>,
) {
    let baseline = fetch_upstream(
        &runtime,
        &runtime.baseline_upstream,
        &method,
        &uri,
        &headers,
        body.clone(),
        ResponseDisposition::Downstream,
    )
    .await;
    update_upstream_counts(&runtime, UpstreamRole::Baseline, &baseline).await;
    let _ = baseline_sender.send(baseline.clone());

    let candidate = fetch_upstream(
        &runtime,
        &runtime.comparison_recording.candidate_upstream,
        &method,
        &uri,
        &headers,
        body.clone(),
        ResponseDisposition::CaptureOnly,
    )
    .await;
    update_upstream_counts(&runtime, UpstreamRole::Candidate, &candidate).await;

    let baseline_recheck = if runtime.comparison_recording.baseline_recheck {
        let capture = fetch_upstream(
            &runtime,
            &runtime.baseline_upstream,
            &method,
            &uri,
            &headers,
            body,
            ResponseDisposition::CaptureOnly,
        )
        .await;
        update_upstream_counts(&runtime, UpstreamRole::BaselineRecheck, &capture).await;
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
        .api_update(&rule, &pattern, |counts| {
            counts.last_observed_at = Some(Utc::now());
            counts.last_baseline_status = baseline.record.status;
            counts.last_candidate_status = candidate.record.status;
            counts.last_baseline_error = baseline.record.error.clone();
            counts.last_candidate_error = candidate.record.error.clone();
            counts.last_baseline_recheck_status = baseline_recheck
                .as_ref()
                .and_then(|capture| capture.record.status);
            counts.last_baseline_recheck_error = baseline_recheck
                .as_ref()
                .and_then(|capture| capture.record.error.clone());
        })
        .await;
    if let Some(reservation) = reservation {
        let case = ComparisonRecordingCase {
            id: Uuid::new_v4(),
            rule,
            group,
            pattern,
            request,
            baseline: baseline.record,
            candidate: candidate.record,
            baseline_recheck: baseline_recheck.map(|capture| capture.record),
        };
        if let Err(error) = runtime.store.publish(&case, reservation).await {
            warn!(
                %error,
                case_id = %case.id,
                "failed to publish comparison recording case"
            );
        }
    }
    runtime
        .store
        .summary()
        .set_in_flight(
            runtime
                .comparison_recording
                .max_in_flight
                .saturating_sub(runtime.permits.available_permits())
                .saturating_sub(1),
        )
        .await;
}

async fn forward_baseline(
    runtime: &ComparisonRecordingRuntime,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<GatewayBody> {
    let capture = fetch_upstream(
        runtime,
        &runtime.baseline_upstream,
        method,
        uri,
        headers,
        body,
        ResponseDisposition::Downstream,
    )
    .await;
    update_upstream_counts(runtime, UpstreamRole::Baseline, &capture).await;
    downstream_response(&capture)
}

#[derive(Clone, Copy)]
enum UpstreamRole {
    Baseline,
    Candidate,
    BaselineRecheck,
}

async fn update_upstream_counts(
    runtime: &ComparisonRecordingRuntime,
    role: UpstreamRole,
    capture: &UpstreamCapture,
) {
    runtime
        .store
        .summary()
        .update(|counts| match (role, capture.error_kind) {
            (UpstreamRole::Baseline, None) => counts.baseline_success += 1,
            (UpstreamRole::Baseline, Some(UpstreamErrorKind::ResponseTooLarge)) => {
                counts.baseline_error += 1;
                counts.baseline_response_too_large += 1;
            }
            (UpstreamRole::Baseline, Some(_)) => counts.baseline_error += 1,
            (UpstreamRole::Candidate, None) => counts.candidate_success += 1,
            (UpstreamRole::Candidate, Some(UpstreamErrorKind::ResponseTooLarge)) => {
                counts.candidate_error += 1;
                counts.candidate_response_too_large += 1;
            }
            (UpstreamRole::Candidate, Some(_)) => counts.candidate_error += 1,
            (UpstreamRole::BaselineRecheck, None) => counts.baseline_recheck_success += 1,
            (UpstreamRole::BaselineRecheck, Some(UpstreamErrorKind::ResponseTooLarge)) => {
                counts.baseline_recheck_error += 1;
                counts.baseline_recheck_response_too_large += 1;
            }
            (UpstreamRole::BaselineRecheck, Some(_)) => counts.baseline_recheck_error += 1,
        })
        .await;
}

async fn run_summary_flush(runtime: ComparisonRecordingRuntime) {
    let mut interval = tokio::time::interval(Duration::from_millis(
        runtime.comparison_recording.summary_flush_interval_ms,
    ));
    loop {
        interval.tick().await;
        if let Err(error) = runtime.store.summary().flush().await {
            warn!(%error, "failed to flush comparison recording run summary");
        }
    }
}

fn validate_run_id(run_id: &str) -> Result<()> {
    anyhow::ensure!(
        run_id.len() == 14
            && run_id.bytes().all(|byte| byte.is_ascii_digit())
            && chrono::NaiveDateTime::parse_from_str(run_id, "%Y%m%d%H%M%S").is_ok(),
        "comparison recording run ID must be a valid 14-digit UTC timestamp"
    );
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
            _ = hangup.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
