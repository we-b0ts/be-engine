//! Bind each pooled physical connection to independent upstream observations.
use crate::dependency::{
    TerminationSide,
    termination::{ConnectionTermination, ObservedIo, ObservedTermination},
};
use anyhow::{Context as _, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, Uri, body::Incoming};
use hyper_rustls::{HttpsConnector, MaybeHttpsStream};
use hyper_util::{
    client::legacy::connect::{Connected, Connection, HttpConnector, capture_connection},
    rt::TokioIo,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tower_service::Service;

#[derive(Clone, Debug, Default)]
pub(crate) struct UpstreamTermination(pub(crate) ConnectionTermination);

impl UpstreamTermination {
    pub(crate) fn observed_since(&self, started: Instant) -> Option<ObservedTermination> {
        self.0
            .peer_snapshot()
            .filter(|end| end.at >= started && end.termination.side == TerminationSide::Server)
    }
}

#[derive(Clone)]
pub(crate) struct ObservedConnector(HttpsConnector<HttpConnector>);

impl ObservedConnector {
    pub(crate) fn new(inner: HttpsConnector<HttpConnector>) -> Self {
        Self(inner)
    }
}

type UpstreamIo = MaybeHttpsStream<TokioIo<TcpStream>>;
pub(crate) struct ObservedUpstream {
    io: ObservedIo<TokioIo<UpstreamIo>>,
    observation: UpstreamTermination,
}

impl Connection for ObservedUpstream {
    fn connected(&self) -> Connected {
        self.io
            .get_ref()
            .inner()
            .connected()
            .extra(self.observation.clone())
    }
}

impl Service<Uri> for ObservedConnector {
    type Response = TokioIo<ObservedUpstream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let future = self.0.call(uri);
        Box::pin(async move {
            let io = future.await?;
            let observation = UpstreamTermination::default();
            Ok(TokioIo::new(ObservedUpstream {
                io: ObservedIo::new(
                    TokioIo::new(io),
                    observation.0.clone(),
                    TerminationSide::Server,
                ),
                observation,
            }))
        })
    }
}

impl AsyncRead for ObservedUpstream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for ObservedUpstream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub(crate) struct UpstreamFailure {
    pub(crate) error: anyhow::Error,
    pub(crate) termination: Option<ObservedTermination>,
}
impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(fmt)
    }
}

pub(crate) async fn send_observed(
    client: &crate::ProxyClient,
    mut request: Request<Full<Bytes>>,
    started: Instant,
) -> Result<Response<Incoming>, UpstreamFailure> {
    let capture = capture_connection(&mut request);
    client.request(request).await.map_err(|error| {
        let observation = if error.is_connect() {
            None
        } else {
            let mut extras = hyper::http::Extensions::new();
            if let Some(connected) = capture.connection_metadata().as_ref() {
                connected.get_extras(&mut extras);
            }
            extras.remove::<UpstreamTermination>()
        }
        .unwrap_or_default();
        let error = anyhow::Error::new(error);
        observation.0.observe_server_error(&error);
        UpstreamFailure {
            termination: observation.observed_since(started),
            error,
        }
    })
}

pub(crate) async fn send_https_observed(
    config: Arc<rustls::ClientConfig>,
    address: std::net::SocketAddr,
    server_name: &str,
    request: Request<Full<Bytes>>,
    started: Instant,
) -> Result<Response<Incoming>, UpstreamFailure> {
    let observation = UpstreamTermination::default();
    let result: Result<_> = async {
        let stream = TcpStream::connect(address)
            .await
            .with_context(|| format!("failed to connect HTTPS upstream {address}"))?;
        stream.set_nodelay(true)?;
        let stream = ObservedIo::new(stream, observation.0.clone(), TerminationSide::Server);
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
            .context("invalid HTTPS upstream server name")?;
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .context("upstream TLS handshake failed")?;
        let tls = ObservedIo::new(tls, observation.0.clone(), TerminationSide::Server);
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut response = sender.send_request(request).await?;
        response.extensions_mut().insert(observation.clone());
        Ok(response)
    }
    .await;
    result.map_err(|error| {
        observation.0.observe_server_error(&error);
        UpstreamFailure {
            termination: observation.observed_since(started),
            error,
        }
    })
}
