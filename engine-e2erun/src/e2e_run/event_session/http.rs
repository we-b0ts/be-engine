//! Independently launched primary HTTP exchanges across one Source timeline.

mod response;
#[cfg(test)]
mod tests;

use std::{collections::HashMap, io::ErrorKind, path::Path};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Request, body::Incoming, client::conn::http1, header, http};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::{
    net::TcpStream,
    task::JoinHandle,
    time::{Duration, Instant},
};
use traffic_model::session::ENGINE_SHUTDOWN_CANCEL_REASON;
use uuid::Uuid;

use super::super::model::ResolvedProjectConfig;
use crate::{
    primary_protocol::assertion::ResponseAssertionRuntime, request_rules::RequestRuleRuntime,
};
use response::{Response, Verification, snapshot_headers};

pub(super) struct Http<'a> {
    config: &'a ResolvedProjectConfig,
    source: &'a Path,
    rules: RequestRuleRuntime,
    assertions: ResponseAssertionRuntime,
    exchanges: HashMap<Uuid, Exchange>,
    ready_probe_seen: bool,
}

impl<'a> Http<'a> {
    pub(super) fn new(
        config: &'a ResolvedProjectConfig,
        source: &'a Path,
        target_root: &Path,
    ) -> Result<Self> {
        Ok(Self {
            config,
            source,
            rules: RequestRuleRuntime::load(target_root, &config.replay_policy)?,
            assertions: ResponseAssertionRuntime::load(&config.replay_policy)?,
            exchanges: HashMap::new(),
            ready_probe_seen: false,
        })
    }

    pub(super) fn ready_probe_seen(&self) -> bool {
        self.ready_probe_seen
    }

    pub(super) fn prepare(&self, request: &Value) -> Result<PreparedRequest> {
        let sent_at = Utc::now();
        let outbound = crate::recorded_request::prepare_session_request(
            &self.config.target_http_origin,
            request,
            self.source,
            &self.rules,
            sent_at,
        )
        .context("could not prepare recorded primary HTTP request")?;
        let headers = snapshot_headers(outbound.headers());
        Ok(PreparedRequest {
            outbound,
            headers,
            sent_at,
        })
    }

    pub(super) fn start(
        &mut self,
        id: Uuid,
        request: Value,
        prepared: PreparedRequest,
    ) -> Result<()> {
        ensure!(
            !self.exchanges.contains_key(&id),
            "duplicate primary HTTP request"
        );
        let PreparedRequest {
            outbound,
            headers,
            sent_at,
        } = prepared;
        let probe = request["_session_probe"].as_bool() == Some(true);
        let timeout = if probe {
            self.config.target_startup_timeout
        } else {
            self.config.target_request_timeout
        };
        let deadline = Instant::now() + timeout;
        let task = tokio::spawn(request_target(outbound, deadline, probe));
        self.exchanges.insert(
            id,
            Exchange {
                request,
                headers,
                sent_at,
                deadline,
                probe,
                incoming: Some(task),
                response: None,
            },
        );
        Ok(())
    }

    pub(super) async fn headers(&mut self, id: Uuid, expected: Value) -> Result<()> {
        let exchange = self
            .exchanges
            .get_mut(&id)
            .context("response has no primary request")?;
        let incoming = exchange
            .incoming
            .take()
            .context("duplicate primary response headers")?;
        let response = join(incoming, exchange.deadline).await?;
        let actual = response.response.status().as_u16();
        let expected_status = expected["status"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .context("recorded primary response has no HTTP status")?;
        ensure!(
            expected_status == actual,
            "primary HTTP status differs (expected {expected_status}, observed {actual})"
        );
        if exchange.probe && actual == self.config.target_readiness_status {
            self.ready_probe_seen = true;
        }
        let response = Response::begin(expected, response, self.config.target_max_response_bytes)?;
        response.verify_headers(Verification {
            id,
            request: &exchange.request,
            request_headers: &exchange.headers,
            request_sent_at: exchange.sent_at,
            source: self.source,
            policy: &self.config.replay_policy,
            assertions: &self.assertions,
        })?;
        exchange.response = Some(response);
        Ok(())
    }

    pub(super) async fn part(&mut self, id: Uuid, part: u64, expected: &[u8]) -> Result<()> {
        let exchange = self
            .exchanges
            .get_mut(&id)
            .context("response part has no primary request")?;
        let response = exchange
            .response
            .as_mut()
            .context("response part preceded HTTP headers")?;
        tokio::time::timeout_at(exchange.deadline, response.part(part, expected))
            .await
            .context("Target primary HTTP body did not arrive before its deadline")?
    }

    pub(super) async fn trailers(&mut self, id: Uuid, expected: Value) -> Result<()> {
        let exchange = self
            .exchanges
            .get_mut(&id)
            .context("response trailers have no primary request")?;
        let response = exchange
            .response
            .as_mut()
            .context("response trailers preceded HTTP headers")?;
        tokio::time::timeout_at(exchange.deadline, response.trailers(expected))
            .await
            .context("Target primary HTTP trailers did not arrive before their deadline")?
    }

    pub(super) async fn end(&mut self, id: Uuid) -> Result<()> {
        let mut exchange = self
            .exchanges
            .remove(&id)
            .context("response end has no primary request")?;
        let mut response = exchange
            .response
            .take()
            .context("response end preceded HTTP headers")?;
        tokio::time::timeout_at(exchange.deadline, response.end())
            .await
            .context("Target primary HTTP response did not end before its deadline")??;
        response.verify(Verification {
            id,
            request: &exchange.request,
            request_headers: &exchange.headers,
            request_sent_at: exchange.sent_at,
            source: self.source,
            policy: &self.config.replay_policy,
            assertions: &self.assertions,
        })
    }

    pub(super) fn admits_disconnect(&self, id: Uuid) -> Result<()> {
        ensure!(
            self.exchanges.contains_key(&id),
            "driver disconnect has no primary request"
        );
        Ok(())
    }

    pub(super) async fn cancel(&mut self, id: Uuid, reason: &str) -> Result<()> {
        let mut exchange = self
            .exchanges
            .remove(&id)
            .context("cancellation has no primary request")?;
        match reason {
            "client_cancelled" | ENGINE_SHUTDOWN_CANCEL_REASON => Ok(()),
            "source_request_failed" => {
                let incoming = exchange
                    .incoming
                    .take()
                    .context("request failure followed response headers")?;
                let result = tokio::time::timeout_at(exchange.deadline, wait_task(incoming))
                    .await
                    .context("Target primary request remained pending instead of failing")??;
                ensure!(
                    result.is_err(),
                    "Target returned HTTP headers instead of the recorded request failure"
                );
                Ok(())
            }
            "source_response_reset" => {
                let response = exchange
                    .response
                    .as_mut()
                    .context("response reset has no observed HTTP headers")?;
                tokio::time::timeout_at(exchange.deadline, response.expect_reset())
                    .await
                    .context("Target response remained pending instead of resetting")?
            }
            "source_response_timeout" => {
                let result = if let Some(response) = exchange.response.as_mut() {
                    tokio::time::timeout_at(exchange.deadline, response.end())
                        .await
                        .is_err()
                } else {
                    let incoming = exchange
                        .incoming
                        .take()
                        .context("missing pending HTTP request")?;
                    tokio::time::timeout_at(exchange.deadline, wait_task(incoming))
                        .await
                        .is_err()
                };
                ensure!(result, "Target response did not time out as recorded");
                Ok(())
            }
            _ => bail!("unsupported primary cancellation reason"),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.exchanges.is_empty()
    }
}

pub(super) struct PreparedRequest {
    outbound: Request<Full<Bytes>>,
    headers: response::Headers,
    sent_at: DateTime<Utc>,
}

struct Exchange {
    request: Value,
    headers: response::Headers,
    sent_at: DateTime<Utc>,
    deadline: Instant,
    probe: bool,
    incoming: Option<JoinHandle<Result<Opened>>>,
    response: Option<Response>,
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if let Some(task) = &self.incoming {
            task.abort();
        }
    }
}

struct Opened {
    response: http::Response<Incoming>,
    connection: Connection,
}

struct Connection(JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn join(task: JoinHandle<Result<Opened>>, deadline: Instant) -> Result<Opened> {
    tokio::time::timeout_at(deadline, wait_task(task))
        .await
        .context("Target primary HTTP response headers timed out")??
}

async fn wait_task(task: JoinHandle<Result<Opened>>) -> Result<Result<Opened>> {
    let abort = task.abort_handle();
    struct Abort(tokio::task::AbortHandle);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _abort = Abort(abort);
    task.await
        .context("Target primary HTTP request task failed")
}

async fn request_target(
    mut request: Request<Full<Bytes>>,
    deadline: Instant,
    probe: bool,
) -> Result<Opened> {
    let uri = request.uri();
    let host = uri
        .host()
        .context("Target primary HTTP URI has no host")?
        .to_owned();
    let port = uri.port_u16().unwrap_or(80);
    let host_header = uri
        .authority()
        .context("Target primary HTTP URI has no authority")?
        .as_str()
        .parse()?;
    let path = uri
        .path_and_query()
        .context("Target primary HTTP URI has no path")?
        .as_str()
        .parse()?;
    *request.uri_mut() = path;
    request.headers_mut().insert(header::HOST, host_header);
    let stream = loop {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(stream) => break stream,
            Err(error)
                if probe
                    && error.kind() == ErrorKind::ConnectionRefused
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error).context("Target primary HTTP connection failed"),
        }
    };
    stream.set_nodelay(true)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    let connection = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .context("Target primary HTTP request failed")?;
    Ok(Opened {
        response,
        connection,
    })
}
