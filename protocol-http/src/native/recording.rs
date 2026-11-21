//! Finite HTTP capture retains protocol framing behind shared ownership receipts.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use traffic_model::trace::OutputKind;
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{CaptureHost, ConnectionIo, NativeFuture, Operation},
    message::{MessageEncoder, ProtocolMessage},
};
use uuid::Uuid;

pub(super) struct Capture(pub ConnectionInfo);

impl CaptureSession for Capture {
    fn run(
        self: Box<Self>,
        client: Box<dyn ConnectionIo>,
        upstream: Box<dyn ConnectionIo>,
        host: Arc<dyn CaptureHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let mut client = tokio::io::BufReader::new(client);
            let prefix = client.fill_buf().await?;
            if prefix.is_empty() {
                return Ok(());
            }
            let tls = prefix[0] == 0x16;
            let (client, upstream): (Box<dyn ConnectionIo>, Box<dyn ConnectionIo>) = if tls {
                let client = host
                    .accept_tls(Box::new(client), vec![b"http/1.1".to_vec()])
                    .await?;
                (client, connect_tls(upstream, &self.0.endpoint.host).await?)
            } else {
                (Box::new(client), upstream)
            };
            let mut client = wire::Reader::new(client);
            let mut upstream = wire::Reader::new(upstream);
            let Some(request) = client.request().await? else {
                return Ok(());
            };
            let id = Uuid::new_v4();
            let method: hyper::Method = request.method.parse()?;
            let operation = if method.is_safe() {
                Operation::Read
            } else {
                Operation::Write
            };
            let Some(permit) = host
                .begin(ProtocolRef::exchange("http", id), operation)
                .await?
            else {
                client
                    .io
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                client.io.flush().await?;
                return Ok(());
            };
            let started_at = chrono::Utc::now();
            let started = std::time::Instant::now();
            let request_bytes = encode_request(&request)?;
            upstream.io.write_all(&request_bytes).await?;
            upstream.io.flush().await?;
            let response = upstream.response(&request.method).await?;
            let values = response
                .project()?
                .values
                .into_iter()
                .map(|(path, value)| (path, value.bytes))
                .collect();
            let output = response.encode(&values)?;
            let receipt = permit.prepare_output(OutputKind::End)?;
            client.io.write_all(&output).await?;
            client.io.flush().await?;
            receipt.commit();
            let authority = request
                .headers
                .get("host")
                .and_then(|values| values.first())
                .cloned()
                .unwrap_or_else(|| {
                    traffic_protocol::observation::format_endpoint(
                        &self.0.endpoint.host,
                        self.0.endpoint.port,
                    )
                });
            let event = crate::events::HttpExchangeEvent {
                outcome: DependencyExchangeOutcome::Response,
                id,
                timestamp: chrono::Utc::now(),
                request_started_at: started_at,
                client_addr: self.0.client_addr.clone(),
                upstream_addr: self
                    .0
                    .upstream_addr
                    .as_deref()
                    .and_then(|value| value.parse().ok()),
                scheme: if tls { "https" } else { "http" }.into(),
                method: request.method,
                uri: request.uri,
                authority: Some(authority),
                request_headers: request.headers,
                request_body: request.body.into(),
                response_status: Some(response.status),
                response_headers: Some(response.headers),
                response_body: Some(response.body.into()),
                response_stream: None,
                discovered_tcp_targets: Vec::new(),
                duration_ms: started.elapsed().as_millis(),
                error: None,
            };
            permit.complete(CaptureSnapshot::capture(&event)?).await?;
            client.io.shutdown().await?;
            Ok(())
        })
    }
}

fn encode_request(request: &RequestMessage) -> Result<Vec<u8>> {
    let mut output = format!("{} {} HTTP/1.1\r\n", request.method, request.uri).into_bytes();
    for (name, values) in &request.headers {
        if matches!(
            name.as_str(),
            "connection" | "keep-alive" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        for value in values {
            output.extend_from_slice(name.as_bytes());
            output.extend_from_slice(b": ");
            output.extend_from_slice(value.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
    }
    output.extend_from_slice(
        format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            request.body.len()
        )
        .as_bytes(),
    );
    output.extend_from_slice(&request.body);
    Ok(output)
}

async fn connect_tls(io: Box<dyn ConnectionIo>, host: &str) -> Result<Box<dyn ConnectionIo>> {
    use tokio_rustls::rustls;
    let certificates = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates.certs {
        roots.add(certificate)?;
    }
    ensure!(
        !roots.is_empty(),
        "HTTP upstream TLS has no trusted certificates"
    );
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, io)
        .await?;
    Ok(Box::new(stream))
}
