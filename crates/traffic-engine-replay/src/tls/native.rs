//! Shared certificate termination used by registered native sessions.
use super::MitmCa;
use std::sync::Arc;
use traffic_protocol::connection::{ConnectionIo, NativeFuture, TlsServer};

pub struct ServerTls(pub Arc<MitmCa>);

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServerTls")
    }
}

impl TlsServer for ServerTls {
    fn accept(
        &self,
        io: Box<dyn ConnectionIo>,
        host: String,
        alpn: Vec<Vec<u8>>,
    ) -> NativeFuture<'_, Box<dyn ConnectionIo>> {
        Box::pin(async move {
            let config = self.0.server_config_for_transport(&host, alpn)?;
            let stream = tokio_rustls::TlsAcceptor::from(config).accept(io).await?;
            Ok(Box::new(stream) as Box<dyn ConnectionIo>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn registered_session_tls_uses_the_replay_ca_and_requested_alpn() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let ca = Arc::new(
            MitmCa::load_or_generate(
                directory.path().join("ca.pem"),
                directory.path().join("ca-key.pem"),
            )
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = ServerTls(ca.clone());
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            let mut io = service
                .accept(Box::new(io), "api.test".into(), vec![b"http/1.1".to_vec()])
                .await
                .unwrap();
            io.write_all(b"ok").await.unwrap();
            io.flush().await.unwrap();
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_cert_der()).unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connection = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut client = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("api.test").unwrap(),
                connection,
            )
            .await
            .unwrap();
        assert_eq!(
            client.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let mut body = [0; 2];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");
        server.await.unwrap();
    }
}
