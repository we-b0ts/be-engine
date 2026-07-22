mod model;
mod store;
mod summary;
mod upstream;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use self::model::{CompareCase, CompareRequestRecord};
use self::store::{CompareStore, Reservation};
use self::upstream::{
    LimitedBodyError, ResponseDisposition, UpstreamCapture, UpstreamErrorKind, body_capture,
    collect_limited, collect_unlimited, downstream_response, fetch_upstream, run_ready_probe,
};
use crate::VerifiedApiExcludesConfig;
use crate::config::{AppConfig, CompareConfig, HttpGatewayConfig};
use crate::gateway::http::rules::{
    RuleDecision, evaluate_request, request_authority, resolve_case_group,
};
use crate::gateway::http::transport::{GatewayBody, simple_response};
use crate::recorder::redact_headers;

#[derive(Clone)]
struct CompareRuntime {
    config: Arc<AppConfig>,
    compare: CompareConfig,
    gateway: HttpGatewayConfig,
    client: crate::ProxyClient,
    store: CompareStore,
    ready: Arc<AtomicBool>,
    permits: Arc<Semaphore>,
    background: BackgroundTasks,
}

type BackgroundFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

enum BackgroundCommand {
    Spawn(BackgroundFuture),
    Shutdown(Duration, oneshot::Sender<()>),
}

#[derive(Clone)]
struct BackgroundTasks {
    sender: mpsc::UnboundedSender<BackgroundCommand>,
}

impl BackgroundTasks {
    fn new() -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    Some(command) = receiver.recv() => match command {
                        BackgroundCommand::Spawn(task) => {
                            tasks.spawn(task);
                        }
                        BackgroundCommand::Shutdown(timeout, done) => {
                            drain_join_set(&mut tasks, timeout).await;
                            let _ = done.send(());
                            return;
                        }
                    },
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                        if let Err(error) = result {
                            warn!(%error, "compare background task failed");
                        }
                    }
                    else => return,
                }
            }
        });
        Self { sender }
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        if self
            .sender
            .send(BackgroundCommand::Spawn(Box::pin(task)))
            .is_err()
        {
            warn!("compare background task rejected because tracker stopped");
        }
    }

    async fn drain(&self, timeout: Duration) {
        let (done, completed) = oneshot::channel();
        if self
            .sender
            .send(BackgroundCommand::Shutdown(timeout, done))
            .is_ok()
        {
            let _ = completed.await;
        }
    }
}

async fn drain_join_set(tasks: &mut JoinSet<()>, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(error))) => warn!(%error, "compare background task failed"),
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                warn!("timed out draining compare background tasks; remaining tasks aborted");
            }
        }
    }
}

pub async fn run(config: AppConfig, run_id: Option<String>) -> Result<()> {
    config
        .validate_compare()
        .context("invalid compare configuration")?;
    let compare = config
        .compare
        .clone()
        .context("compare command requires a [compare] configuration section")?;
    let run_id = run_id.unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());
    validate_run_id(&run_id)?;
    let store = CompareStore::create(&config.recording.output_dir, &run_id).await?;
    let gateway = config.http_gateway.clone();
    let listener = TcpListener::bind(gateway.listen)
        .await
        .with_context(|| format!("failed to bind compare gateway {}", gateway.listen))?;
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let runtime = CompareRuntime {
        config: Arc::new(config),
        compare: compare.clone(),
        gateway: gateway.clone(),
        client,
        store,
        ready: Arc::new(AtomicBool::new(!gateway.ready.enabled)),
        permits: Arc::new(Semaphore::new(compare.max_in_flight)),
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
    info!(
        listen = %gateway.listen,
        baseline = %compare.baseline_upstream,
        candidate = %compare.candidate_upstream,
        run_id,
        "online compare recorder listening"
    );

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept compare client")?;
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
                        warn!(%error, "compare client connection ended with error");
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    warn!(%error, "compare client connection task failed");
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
        .drain(Duration::from_millis(compare.upstream_timeout_ms))
        .await;
    runtime.store.fail_unfinished().await?;
    runtime.store.summary().finish().await?;
    Ok(())
}

async fn handle_request(
    request: Request<Incoming>,
    runtime: CompareRuntime,
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
    let decision = evaluate_request(
        &VerifiedApiExcludesConfig::default(),
        &runtime.gateway.exclude_rules,
        &runtime.gateway.rules,
        &method,
        &uri,
        &headers,
    );
    let matched = match decision {
        RuleDecision::Matched(rule) => Some(rule),
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
        collect_limited(request.into_body(), runtime.compare.max_request_bytes).await
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
                "compare request body too large",
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
                .compare
                .max_in_flight
                .saturating_sub(runtime.permits.available_permits()),
        )
        .await;

    let group = resolve_case_group(&uri, &rule.case_path_patterns);
    let limit = runtime.gateway.case_limits.limit_for(&group.pattern);
    let reservation = runtime
        .store
        .try_reserve(&rule.name, &group.pattern, limit)
        .await;
    let request_record = CompareRequestRecord {
        timestamp: Utc::now(),
        client_addr,
        method: method.to_string(),
        uri: uri.to_string(),
        authority,
        matched_rule: rule.name.clone(),
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
        Err(_) => simple_response(StatusCode::BAD_GATEWAY, "baseline compare task failed"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_dual(
    runtime: CompareRuntime,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    rule: String,
    group: String,
    pattern: String,
    request: CompareRequestRecord,
    reservation: Option<Reservation>,
    _permit: OwnedSemaphorePermit,
    baseline_sender: oneshot::Sender<UpstreamCapture>,
) {
    let baseline_request = fetch_upstream(
        &runtime,
        &runtime.compare.baseline_upstream,
        &method,
        &uri,
        &headers,
        body.clone(),
        ResponseDisposition::Downstream,
    );
    let candidate_request = fetch_upstream(
        &runtime,
        &runtime.compare.candidate_upstream,
        &method,
        &uri,
        &headers,
        body,
        ResponseDisposition::CaptureOnly,
    );
    tokio::pin!(baseline_request, candidate_request);
    let mut baseline = None;
    let mut candidate = None;
    let mut baseline_sender = Some(baseline_sender);
    while baseline.is_none() || candidate.is_none() {
        tokio::select! {
            capture = &mut baseline_request, if baseline.is_none() => {
                update_upstream_counts(&runtime, true, &capture).await;
                if let Some(sender) = baseline_sender.take() {
                    let _ = sender.send(capture.clone());
                }
                baseline = Some(capture);
            }
            capture = &mut candidate_request, if candidate.is_none() => {
                update_upstream_counts(&runtime, false, &capture).await;
                candidate = Some(capture);
            }
        }
    }
    let baseline = baseline.expect("baseline compare request completed");
    let candidate = candidate.expect("candidate compare request completed");
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
        })
        .await;
    if let Some(reservation) = reservation {
        let case = CompareCase {
            id: Uuid::new_v4(),
            rule,
            group,
            pattern,
            request,
            baseline: baseline.record,
            candidate: candidate.record,
        };
        if let Err(error) = runtime.store.publish(&case, reservation).await {
            warn!(%error, case_id = %case.id, "failed to publish online compare case");
        }
    }
    runtime
        .store
        .summary()
        .set_in_flight(
            runtime
                .compare
                .max_in_flight
                .saturating_sub(runtime.permits.available_permits())
                .saturating_sub(1),
        )
        .await;
}

async fn forward_baseline(
    runtime: &CompareRuntime,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<GatewayBody> {
    let capture = fetch_upstream(
        runtime,
        &runtime.compare.baseline_upstream,
        method,
        uri,
        headers,
        body,
        ResponseDisposition::Downstream,
    )
    .await;
    update_upstream_counts(runtime, true, &capture).await;
    downstream_response(&capture)
}

async fn update_upstream_counts(
    runtime: &CompareRuntime,
    baseline: bool,
    capture: &UpstreamCapture,
) {
    runtime
        .store
        .summary()
        .update(|counts| match (baseline, capture.error_kind) {
            (true, None) => counts.baseline_success += 1,
            (true, Some(UpstreamErrorKind::ResponseTooLarge)) => {
                counts.baseline_error += 1;
                counts.baseline_response_too_large += 1;
            }
            (true, Some(_)) => counts.baseline_error += 1,
            (false, None) => counts.candidate_success += 1,
            (false, Some(UpstreamErrorKind::ResponseTooLarge)) => {
                counts.candidate_error += 1;
                counts.candidate_response_too_large += 1;
            }
            (false, Some(_)) => counts.candidate_error += 1,
        })
        .await;
}

async fn run_summary_flush(runtime: CompareRuntime) {
    let mut interval = tokio::time::interval(Duration::from_millis(
        runtime.compare.summary_flush_interval_ms,
    ));
    loop {
        interval.tick().await;
        if let Err(error) = runtime.store.summary().flush().await {
            warn!(%error, "failed to flush compare run summary");
        }
    }
}

fn validate_run_id(run_id: &str) -> Result<()> {
    anyhow::ensure!(
        run_id.len() == 14
            && run_id.bytes().all(|byte| byte.is_ascii_digit())
            && chrono::NaiveDateTime::parse_from_str(run_id, "%Y%m%d%H%M%S").is_ok(),
        "compare run ID must be a valid 14-digit UTC timestamp"
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
