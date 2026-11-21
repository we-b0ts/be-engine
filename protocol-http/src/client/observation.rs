//! Bind each pooled physical connection to independent upstream observations.
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
use tokio_rustls::rustls;
use tower_service::Service;
use traffic_model::TerminationSide;
use traffic_protocol::transport::{
    ConnectionControl, ConnectionTermination, ObservedIo, ObservedTermination,
};

#[derive(Clone, Debug, Default)]
pub struct UpstreamTermination(pub ConnectionTermination);

impl UpstreamTermination {
    pub fn observed_since(&self, started: Instant) -> Option<ObservedTermination> {
        self.0
            .peer_snapshot()
            .filter(|end| end.at >= started && end.termination.side == TerminationSide::Server)
    }
}

#[derive(Clone)]
pub struct ObservedConnector(HttpsConnector<HttpConnector>);

impl ObservedConnector {
    pub fn new(inner: HttpsConnector<HttpConnector>) -> Self {
        Self(inner)
    }
}

type UpstreamIo = MaybeHttpsStream<TokioIo<TcpStream>>;
pub struct ObservedUpstream {
    io: ObservedIo<TokioIo<UpstreamIo>>,
    observation: UpstreamTermination,
}

impl ObservedUpstream {
    /// Retain control of the actual upgraded TCP transport through the HTTP/TLS
    /// adapters. A captured peer FIN/RST is not a WebSocket close handshake.
    pub fn connection_control(&self) -> io::Result<ConnectionControl> {
        let tcp = match self.io.get_ref().inner() {
            MaybeHttpsStream::Http(io) => io.inner(),
            MaybeHttpsStream::Https(io) => io.inner().get_ref().0.inner().inner(),
        };
        ConnectionControl::new(tcp)
    }
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
pub struct UpstreamFailure {
    pub error: anyhow::Error,
    pub termination: Option<ObservedTermination>,
}
impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(fmt)
    }
}

pub async fn send_observed(
    client: &super::ProxyClient,
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

pub async fn send_https_observed(
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
