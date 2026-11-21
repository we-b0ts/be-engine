//! Each primary response stream owns its transport and cancellation input.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, header::HOST};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use traffic_protocol::transport::ConnectionControl;

pub(super) struct StreamTransport {
    control: ConnectionControl,
    connection: tokio::task::JoinHandle<()>,
}

impl StreamTransport {
    pub(super) fn cancel(&self) -> Result<()> {
        self.control
            .reset()
            .context("failed to deliver primary HTTP stream cancellation")
    }
}

impl Drop for StreamTransport {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

pub(super) async fn request(
    mut request: Request<Full<Bytes>>,
) -> Result<(Response<Incoming>, StreamTransport)> {
    ensure!(
        request.uri().scheme_str() == Some("http"),
        "primary HTTP stream Target requires an http URI"
    );
    let authority = request
        .uri()
        .authority()
        .context("Target URI has no authority")?;
    let host = request.uri().host().context("Target URI has no host")?;
    let socket = TcpStream::connect((
        host.trim_start_matches('[').trim_end_matches(']'),
        request.uri().port_u16().unwrap_or(80),
    ))
    .await
    .context("failed to connect primary HTTP stream Target")?;
    socket.set_nodelay(true)?;
    let control = ConnectionControl::new(&socket)?;
    if !request.headers().contains_key(HOST) {
        let host = authority
            .as_str()
            .parse()
            .context("invalid Target Host header")?;
        request.headers_mut().insert(HOST, host);
    }
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .parse()?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let transport = StreamTransport {
        control,
        connection,
    };
    let response = sender
        .send_request(request)
        .await
        .context("primary HTTP stream Target request failed")?;
    Ok((response, transport))
}
