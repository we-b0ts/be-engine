//! Native full-duplex sessions retain session state and share finite delivery.
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
            let (reader, mut writer) = tokio::io::split(io);
            let mut reader = traffic_protocol::io::BufferedReader::new(reader, self.limit);
            let (tx, mut rx) = tokio::sync::mpsc::channel(32);
            let incoming_host = host.clone();
            let incoming = async move {
                let mut bound = false;
                while let Some(body) =
                    traffic_protocol::io::read_frame(&mut reader, &mut Decoder).await?
                {
                    let listen = serde_json::from_slice::<Value>(&body)?["operation"] == "listen";
                    bound |= listen;
                    let message = Arc::new(Message(body));
                    let delivery = if bound {
                        incoming_host.execute_bound(message, None).await?
                    } else {
                        incoming_host.execute(message).await?
                    };
                    if tx.send((listen, delivery)).await.is_err() {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            let outgoing = async {
                let mut anchors = Vec::new();
                let mut pending = std::collections::VecDeque::<(
                    bool,
                    Box<dyn traffic_protocol::connection::ResponseDelivery>,
                )>::new();
                let mut closed = false;
                loop {
                    if closed && pending.is_empty() {
                        return Ok::<_, anyhow::Error>(());
                    }
                    tokio::select! {
                        request = rx.recv(), if !closed && pending.len() < 32 => {
                            match request { Some(request) => pending.push_back(request), None => closed = true }
                        }
                        ready = async { pending.front_mut().expect("pending response").1.ready().await }, if !pending.is_empty() => {
                            ready?;
                            let (listen, mut delivery) = pending.pop_front().expect("ready response");
                            if listen { delivery.retain_as_anchor(); }
                            let reference = delivery.reference();
                            delivery.write(&mut writer, &mut Decoder).await?;
                            if listen { anchors.push(reference.context("fixture delivery has no Source reference")?); }
                        }
                        delivery = host.next_message(anchors.clone()), if !anchors.is_empty() => {
                            delivery?.write(&mut writer, &mut Decoder).await?;
                        }
                    }
                }
            };
            tokio::try_join!(incoming, outgoing)?;
            Ok(())
        })
    }
}
