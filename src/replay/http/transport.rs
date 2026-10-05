//! HTTP/TLS connection lifetime and delivery.
use super::*;
use crate::http::termination::{ClientTermination, ObservedClientIo};

pub(in crate::replay) async fn handle_http_replay_connection(
    stream: TcpStream,
    _peer_addr: std::net::SocketAddr,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    match target.protocol {
        ReplayProtocol::Http => serve_http_io(stream, target, state).await,
        ReplayProtocol::Https => {
            let server_config = ca.server_config_for_host(&target.host)?;
            let tls = TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .with_context(|| {
                    format!("HTTPS replay TLS handshake failed for {}", target.host)
                })?;
            serve_http_io(tls, target, state).await
        }
        ReplayProtocol::Auto
        | ReplayProtocol::Mysql
        | ReplayProtocol::Redis
        | ReplayProtocol::Memcached
        | ReplayProtocol::Kafka
        | ReplayProtocol::Motan => Err(anyhow!("HTTP replay received a non-HTTP target")),
    }
}

async fn serve_http_io<T>(io: T, target: ReplayTarget, state: Arc<Mutex<ReplayState>>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let termination = ClientTermination::default();
    let io = ObservedClientIo::new(io, termination.clone());
    let (deadline_tx, deadline_rx) = tokio::sync::watch::channel(None);
    let pending = Arc::new(std::sync::Mutex::new(None));
    let service_pending = pending.clone();
    let service_state = state.clone();
    let service = service_fn(move |request| {
        handle_http_request(
            request,
            target.clone(),
            service_state.clone(),
            service_pending.clone(),
            deadline_tx.clone(),
        )
    });
    let result = {
        let connection =
            hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(io), service);
        tokio::pin!(connection);
        tokio::select! {
            result = &mut connection => result.context("failed to serve HTTP replay connection"),
            _ = wait_for_deadline(deadline_rx) => Err(anyhow!("client did not terminate HTTP dependency connection within recorded timing window")),
        }
    };
    let exchange = pending
        .lock()
        .expect("HTTP pending termination poisoned")
        .take();
    if let Some(exchange) = exchange {
        let completion = match termination.observed_at() {
            Some(ended) => exchange.timing.validate_client_termination(
                tokio::time::Instant::from_std(ended).saturating_duration_since(exchange.started),
            ),
            None => Err(anyhow!(
                "client did not terminate HTTP dependency connection within recorded timing window"
            )),
        };
        let completed = completion.is_ok();
        state
            .lock()
            .await
            .finish_http_termination(exchange, completion);
        if completed {
            return Ok(());
        }
    }
    result
}

async fn wait_for_deadline(
    mut receiver: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
) {
    loop {
        let deadline = *receiver.borrow_and_update();
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline).await;
            return;
        }
        if receiver.changed().await.is_err() {
            pending::<()>().await;
        }
    }
}

async fn handle_http_request(
    request: Request<Incoming>,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    pending_exchange: Arc<std::sync::Mutex<Option<termination::PendingHttpTermination>>>,
    deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let started = tokio::time::Instant::now();
    let request_started_at = Utc::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let headers = request_headers::capture(request.headers());
    let body = match request.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("failed to read replay request body: {error}"),
            ));
        }
    };
    let scheme = match target.protocol {
        ReplayProtocol::Https => HttpReplayScheme::Https,
        _ => HttpReplayScheme::Http,
    };
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    let matched = {
        let mut state = state.lock().await;
        let unmatched_before = state.http_events.unmatched.len();
        let result = state.match_http_request(
            scheme,
            &target_key,
            &method,
            &uri,
            host.as_deref(),
            &body,
            &headers,
            request_started_at,
        );
        if state.http_events.unmatched.len() > unmatched_before
            && let Some(event) = state.http_events.unmatched.last_mut()
        {
            event.request_fingerprint = Some(cross_case::request_fingerprint(
                &uri.to_string(),
                &body,
                &headers,
            ));
        }
        result
    };
    let record = match matched {
        Ok(record) => record,
        Err(HttpReplayMatchError::ClientTerminated(mut exchange)) => {
            exchange.started = started;
            deadline.send_replace(Some(exchange.timing.termination_deadline(exchange.started)));
            *pending_exchange
                .lock()
                .expect("HTTP pending termination poisoned") = Some(*exchange);
            return pending::<Result<Response<Full<Bytes>>, Infallible>>().await;
        }
        Err(HttpReplayMatchError::Blackhole) => {
            return pending::<Result<Response<Full<Bytes>>, Infallible>>().await;
        }
        Err(HttpReplayMatchError::BadGateway(reason)) => {
            return Ok(error_response(StatusCode::BAD_GATEWAY, &reason));
        }
    };
    let response = response_from_record(record)
        .unwrap_or_else(|error| error_response(StatusCode::BAD_GATEWAY, &error.to_string()));
    Ok(response)
}
