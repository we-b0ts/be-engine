//! Native HTTP request parsing delegates value matching and actual response writes.
use super::*;
use tokio::io::AsyncWriteExt;
use traffic_protocol::connection::{ConnectionIo, NativeFuture, RequestHost, ResponseFramer};

pub(super) struct Server(pub ConnectionInfo);
struct Framer;
impl ResponseFramer for Framer {}

impl ServerSession for Server {
    fn run(
        self: Box<Self>,
        io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let mut io = tokio::io::BufReader::new(io);
            let prefix = io.fill_buf().await?;
            if prefix.is_empty() {
                return Ok(());
            }
            let tls = prefix[0] == 0x16;
            let io: Box<dyn ConnectionIo> = if tls {
                host.accept_tls(Box::new(io), vec![b"http/1.1".to_vec()])
                    .await?
            } else {
                Box::new(io)
            };
            let mut reader = wire::Reader::new(io, self.0.max_frame_bytes);
            if let Some(head) = reader.request_head().await? {
                let _input = host.begin_input().await?;
                let request = reader.request_body(head).await?;
                let delivery = host.execute(Arc::new(request)).await?;
                delivery.write(&mut reader.io, &mut Framer).await?;
            }
            reader.io.shutdown().await?;
            Ok(())
        })
    }
}
use tokio::io::AsyncBufReadExt;
