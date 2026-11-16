//! Native RESP sessions submit ordinary requests to shared replay admission.
use super::*;
use tokio::io::AsyncWriteExt;
use traffic_protocol::connection::{ConnectionIo, NativeFuture, RequestHost, ResponseFramer};

pub(super) struct Server {
    pub limit: usize,
}

struct Framer;
impl ResponseFramer for Framer {}

impl ServerSession for Server {
    fn run(
        self: Box<Self>,
        io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let mut reader = crate::BufferedReader::new(io, self.limit);
            let mut resp_version = 2;
            let mut database = 0;
            let mut username = None;
            while let Some(frame) = crate::read_frame(&mut reader).await? {
                let command = crate::redis_command(&frame.raw)?;
                ensure!(
                    !crate::builtins::redis_is_unsupported(&command)
                        && !crate::is_pubsub_command(&command.name),
                    "Redis command mode is unavailable in native serving"
                );
                if let Some(response) = crate::builtins::redis_builtin(
                    &command,
                    &mut resp_version,
                    &mut database,
                    &mut username,
                ) {
                    reader.inner.write_all(&response).await?;
                    reader.inner.flush().await?;
                    if command.name == "QUIT" {
                        break;
                    }
                    continue;
                }
                ensure!(
                    resp_version == 2,
                    "Redis native serving currently requires RESP2"
                );
                let response = host
                    .execute(Arc::new(RequestMessage {
                        command: command.name,
                        args: command.args.into_iter().map(Bytes::from).collect(),
                        resp_version,
                        database,
                        username: username.clone(),
                    }))
                    .await?;
                response.write(&mut reader.inner, &mut Framer).await?;
            }
            Ok(())
        })
    }
}
