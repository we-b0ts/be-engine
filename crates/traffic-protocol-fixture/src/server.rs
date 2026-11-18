//! Native sessions submit decoded business messages to the shared host.
use super::*;
use traffic_protocol::connection::{ConnectionIo, NativeFuture, RequestHost, ResponseFramer};

pub(super) struct Server {
    limit: usize,
}
impl Server {
    pub(super) fn new(limit: usize) -> Self {
        Self { limit }
    }
}
impl ResponseFramer for Decoder {}

impl ServerSession for Server {
    fn run(
        self: Box<Self>,
        io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let mut reader = traffic_protocol::io::BufferedReader::new(io, self.limit);
            let mut decoder = Decoder;
            while let Some(body) =
                traffic_protocol::io::read_frame(&mut reader, &mut decoder).await?
            {
                let response = host.execute(Arc::new(Message(body))).await?;
                response.write(&mut reader.inner, &mut decoder).await?;
            }
            Ok(())
        })
    }
}
