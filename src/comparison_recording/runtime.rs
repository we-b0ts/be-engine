use std::path::PathBuf;
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
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use super::model::{ComparisonRecordingCase, ComparisonRecordingRequest};
use super::order::{ComparisonDispatchSchedule, UpstreamDispatchOrder};
use super::store::{ComparisonRecordingStore, Reservation};
use super::tasks::BackgroundTasks;
use super::upstream::{
    LimitedBodyError, ResponseDisposition, UpstreamCapture, UpstreamErrorKind, collect_limited,
    downstream_response, fetch_upstream, request_body_capture, run_motan_ready_probe,
    run_ready_probe,
};
use crate::config::{AppConfig, ComparisonRecordingConfig, HttpGatewayConfig, MotanGatewayConfig};
use crate::gateway::http::rules::{
    RuleDecision, evaluate_request, request_authority, resolve_case_group,
};
use crate::gateway::http::transport::{GatewayBody, build_fixed_response, simple_response};
use crate::recording_api::{RecordingApi, validate_selection};
use crate::recording_completion::RecordingCompletionReason;
use crate::recording_control::{
    RecordingControlServer, RecordingInputCompletion, RecordingLifecycle, RecordingListener,
};
use crate::request_headers::RequestHeaderCapture;

#[derive(Debug, Clone, Default)]
pub struct ComparisonRecordingRunOptions {
    pub run_id: Option<String>,
    pub duration: Option<Duration>,
    pub recording_apis: Vec<RecordingApi>,
    pub control_socket: Option<PathBuf>,
}

#[derive(Clone)]
pub(super) struct ComparisonRecordingRuntime {
    pub(super) config: Arc<AppConfig>,
    pub(super) comparison_recording: ComparisonRecordingConfig,
    pub(super) baseline_upstream: String,
    pub(super) gateway: HttpGatewayConfig,
    pub(super) motan_gateway: MotanGatewayConfig,
    pub(super) candidate_motan_upstream: String,
    pub(super) recording_apis: Vec<RecordingApi>,
    pub(super) client: crate::ProxyClient,
    pub(super) store: ComparisonRecordingStore,
    pub(super) ready: Arc<AtomicBool>,
    pub(super) ready_notify: Arc<Notify>,
    pub(super) recording_lifecycle: RecordingLifecycle,
    request_header_capture: RequestHeaderCapture,
    pub(super) active_case_permits: Arc<Semaphore>,
    pub(super) dispatch_schedule: Arc<ComparisonDispatchSchedule>,
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
        control_socket,
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
    ensure!(
        !config.motan_gateway.enabled || comparison_recording.candidate_motan_upstream.is_some(),
        "comparison recording with motan_gateway.enabled requires comparison_recording.candidate_motan_upstream"
    );
    let request_header_capture = RequestHeaderCapture::from_environment(
        &config.recording.encrypt_request_headers,
        &config.recording.redact_headers,
    )
    .context("failed to initialize comparison request header protection")?;
    let baseline_upstream = comparison_recording
        .baseline_upstream(&config.http_gateway)
        .to_string();
    let run_id = run_id.unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());
    validate_run_id(&run_id)?;
    let recording_api_limits = recording_apis
        .iter()
        .map(|api| {
            (
                api.to_string(),
                if api.method().as_str() == "MOTAN" {
                    config.motan_gateway.max_cases_per_api
                } else {
                    config
                        .http_gateway
                        .per_api_case_limits
                        .limit_for(api.path_pattern())
                },
            )
        })
        .collect();
    let gateway = config.http_gateway.clone();
    let listener = if gateway.enabled {
        Some(
            crate::tcp_listener::bind_with_diagnostic(
                gateway.listen,
                format!(
                    "failed to bind comparison recording gateway {}",
                    gateway.listen
                ),
            )
            .await?,
        )
    } else {
        None
    };
    let motan_gateway = config.motan_gateway.clone();
    let motan_listener = if motan_gateway.enabled {
        Some(
            crate::tcp_listener::bind_with_diagnostic(
                motan_gateway.listen,
                format!(
                    "failed to bind Motan comparison gateway {}",
                    motan_gateway.listen
                ),
            )
            .await?,
        )
    } else {
        None
    };
    let store = ComparisonRecordingStore::create(
        &config.comparison_recording_output_dir(),
        &run_id,
        recording_api_limits,
    )
    .await?;
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let recording_lifecycle = RecordingLifecycle::for_comparison_gateway(
        gateway.enabled,
        gateway.ready.enabled,
        motan_gateway.enabled,
    );
    if listener.is_some() {
        recording_lifecycle.mark_listener_ready(RecordingListener::HttpGateway);
    }
    if motan_listener.is_some() {
        recording_lifecycle.mark_listener_ready(RecordingListener::MotanGateway);
    }
    let candidate_motan_upstream = comparison_recording
        .candidate_motan_upstream
        .clone()
        .unwrap_or_default();
    let dispatch_schedule = Arc::new(ComparisonDispatchSchedule::randomized()?);
    let initially_ready = !(gateway.enabled && gateway.ready.enabled || motan_gateway.enabled);
    let runtime = ComparisonRecordingRuntime {
        config: Arc::new(config),
        comparison_recording: comparison_recording.clone(),
        baseline_upstream: baseline_upstream.clone(),
        gateway: gateway.clone(),
        motan_gateway,
        candidate_motan_upstream,
        recording_apis,
        client,
        store,
        ready: Arc::new(AtomicBool::new(initially_ready)),
        ready_notify: Arc::new(Notify::new()),
        recording_lifecycle: recording_lifecycle.clone(),
        request_header_capture,
        active_case_permits: Arc::new(Semaphore::new(comparison_recording.max_in_flight)),
        dispatch_schedule,
        background: BackgroundTasks::new(),
    };
    if runtime.ready.load(Ordering::Acquire) {
        runtime.store.summary().set_ready().await;
    }
    let (control_server, input_completion) = match control_socket {
        Some(path) => {
            let (server, input_completion) =
                RecordingControlServer::start_for_comparison(recording_lifecycle, path).await?;
            (Some(server), Some(input_completion))
        }
        None => (None, None),
    };
    let mut ready_tasks = JoinSet::new();
    if gateway.enabled && gateway.ready.enabled {
        ready_tasks.spawn(run_ready_probe(runtime.clone()));
    }
    if runtime.motan_gateway.enabled {
        ready_tasks.spawn(run_motan_ready_probe(runtime.clone()));
    }
    let summary_task = tokio::spawn(run_summary_flush(runtime.clone()));
    let motan_listener = async {
        match motan_listener {
            Some(listener) => super::motan::run_listener(listener, runtime.clone()).await,
            None => std::future::pending::<Result<()>>().await,
        }
    };
    tokio::pin!(motan_listener);
    let duration_wait = wait_for_duration(runtime.clone(), duration);
    tokio::pin!(duration_wait);
    let case_limit_completion = runtime.store.wait_for_explicit_api_case_limit();
    tokio::pin!(case_limit_completion);
    let input_completion = wait_for_input_completion(input_completion);
    tokio::pin!(input_completion);
    info!(
        http_listen = gateway.enabled.then_some(gateway.listen).map(tracing::field::display),
        motan_listen = runtime.motan_gateway.enabled.then_some(runtime.motan_gateway.listen).map(tracing::field::display),
        baseline = %baseline_upstream,
        candidate = %comparison_recording.candidate_upstream,
        run_id,
        "comparison recording gateway listening"
    );

    let mut connections = JoinSet::new();
    let completion_reason = loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break RecordingCompletionReason::ShutdownSignal;
            }
            result = &mut motan_listener => {
                result.context("Motan comparison listener stopped")?;
                unreachable!("Motan comparison listener returned successfully")
            }
            Some(result) = ready_tasks.join_next(), if !ready_tasks.is_empty() => {
                result.context("comparison readiness task failed")?;
            }
            _ = &mut duration_wait => {
                info!("comparison recording duration elapsed");
                break RecordingCompletionReason::DurationElapsed;
            }
            _ = &mut case_limit_completion => {
                info!("every explicitly selected comparison API reached its case limit");
                break RecordingCompletionReason::PerApiCaseLimitReached;
            }
            completion = &mut input_completion => {
                match completion {
                    Ok(completion) => {
                        let published = runtime.store.summary().published().await;
                        if completion.delivered != published {
                            runtime.store.summary().record_error(format!(
                                "managed comparison input delivered {} request template(s), but {published} comparison case(s) were published",
                                completion.delivered,
                            )).await;
                        }
                        info!(
                            delivered = completion.delivered,
                            published,
                            "managed comparison finite input exhausted"
                        );
                        break RecordingCompletionReason::InputExhausted;
                    }
                    Err(error) => {
                        runtime.store.summary().record_error(format!(
                            "comparison input completion control failed: {error:#}"
                        )).await;
                        break RecordingCompletionReason::ShutdownSignal;
                    }
                }
            }
            accepted = accept_optional(&listener) => {
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
    };
    drop(listener);
    runtime.recording_lifecycle.mark_stopping();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    ready_tasks.abort_all();
    while ready_tasks.join_next().await.is_some() {}
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
    let finalization_result = async {
        runtime.store.fail_unfinished().await?;
        runtime.store.summary().finish(completion_reason).await
    }
    .await;
    let control_result = match control_server {
        Some(server) => server.shutdown().await,
        None => Ok(()),
    };
    finalization_result?;
    control_result
}

async fn accept_optional(
    listener: &Option<tokio::net::TcpListener>,
) -> Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(listener) => listener
            .accept()
            .await
            .context("failed to accept comparison recording client"),
        None => std::future::pending().await,
    }
}

impl ComparisonRecordingRuntime {
    pub(super) async fn mark_upstream_ready(&self, listener: RecordingListener) {
        if !self.recording_lifecycle.mark_upstream_ready(listener) {
            return;
        }
        if !self.ready.swap(true, Ordering::AcqRel) {
            self.store.summary().set_ready().await;
            self.recording_lifecycle.mark_source_ready();
            self.ready_notify.notify_waiters();
            info!("all enabled comparison upstream probes succeeded");
        }
    }
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

async fn wait_for_input_completion(
    receiver: Option<watch::Receiver<Option<RecordingInputCompletion>>>,
) -> Result<RecordingInputCompletion> {
    let Some(mut receiver) = receiver else {
        return std::future::pending::<Result<RecordingInputCompletion>>().await;
    };
    loop {
        if let Some(completion) = *receiver.borrow_and_update() {
            return Ok(completion);
        }
        receiver
            .changed()
            .await
            .context("comparison recording input completion channel closed")?;
    }
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
        match runtime.active_case_permits.clone().try_acquire_owned() {
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

    let Some(rule) = matched else {
        return fixed_response(&runtime).await;
    };
    let Some(permit) = permit else {
        return fixed_response(&runtime).await;
    };
    let group = recording_api_pattern.as_ref().map_or_else(
        || resolve_case_group(&uri, &runtime.gateway.case_path_patterns),
        |pattern| resolve_case_group(&uri, std::slice::from_ref(pattern)),
    );
    let limit = runtime
        .gateway
        .per_api_case_limits
        .limit_for(&group.pattern);
    let recording_api = format!("{method} {}", group.pattern);
    let Some(reservation) = runtime.store.try_reserve(&recording_api, limit).await else {
        return fixed_response(&runtime).await;
    };

    let body_result =
        collect_limited(request.into_body(), runtime.config.recording.max_body_bytes).await;
    let body = match body_result {
        Ok(body) => body,
        Err(LimitedBodyError::TooLarge) => {
            runtime.store.release(reservation).await;
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
            runtime.store.release(reservation).await;
            return simple_response(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };

    let protected_headers = match runtime.request_header_capture.capture(&headers) {
        Ok(headers) => headers,
        Err(error) => {
            runtime.store.release(reservation).await;
            warn!(error = %error, "failed to protect comparison request headers");
            return simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to protect recorded request headers",
            );
        }
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
                .saturating_sub(runtime.active_case_permits.available_permits()),
        )
        .await;

    let request_record = ComparisonRecordingRequest {
        protocol: "http",
        timestamp: Utc::now(),
        client_addr,
        method: method.to_string(),
        uri: uri.to_string(),
        authority,
        matched_rule: rule.name.clone(),
        api_pattern: group.pattern.clone(),
        headers: protected_headers,
        body: request_body_capture(&body, false, Some(body.len())),
        protocol_version: None,
        request_id: None,
        api_key: None,
    };
    let (sender, receiver) = oneshot::channel();
    let task_runtime = runtime.clone();
    let dispatch_order = runtime.dispatch_schedule.next();
    runtime.background.spawn(async move {
        run_dual(
            task_runtime,
            method,
            uri,
            headers,
            body,
            group.directory,
            group.pattern,
            request_record,
            reservation,
            permit,
            sender,
            dispatch_order,
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
    group: String,
    pattern: String,
    request: ComparisonRecordingRequest,
    reservation: Reservation,
    permit: OwnedSemaphorePermit,
    baseline_sender: oneshot::Sender<UpstreamCapture>,
    dispatch_order: UpstreamDispatchOrder,
) {
    let recording_api = format!("{method} {pattern}");
    let (baseline, candidate) = match dispatch_order {
        UpstreamDispatchOrder::BaselineThenCandidate => {
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
            (baseline, candidate)
        }
        UpstreamDispatchOrder::CandidateThenBaseline => {
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
            (baseline, candidate)
        }
    };

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
        .api_update(&recording_api, |counts| {
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
    let case = ComparisonRecordingCase {
        id: Uuid::new_v4(),
        group,
        request,
        baseline: baseline.record.clone(),
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
    drop(permit);
    runtime
        .store
        .summary()
        .set_in_flight(
            runtime
                .comparison_recording
                .max_in_flight
                .saturating_sub(runtime.active_case_permits.available_permits()),
        )
        .await;
    let _ = baseline_sender.send(baseline);
}

async fn fixed_response(runtime: &ComparisonRecordingRuntime) -> Response<GatewayBody> {
    runtime
        .store
        .summary()
        .update(|counts| counts.fixed_response += 1)
        .await;
    build_fixed_response(
        runtime
            .gateway
            .fixed_response
            .as_ref()
            .expect("validated comparison fixed response configuration"),
    )
}

#[derive(Clone, Copy)]
pub(super) enum UpstreamRole {
    Baseline,
    Candidate,
    BaselineRecheck,
}

pub(super) async fn update_upstream_counts(
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
