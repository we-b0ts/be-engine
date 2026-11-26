//! Native HTTP request parsing delegates value matching and actual response writes.
use super::*;
use std::io::ErrorKind;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, ReadHalf};
use traffic_protocol::connection::{ConnectionIo, NativeFuture, RequestHost, ResponseFramer};

pub(super) struct Server;
struct Framer {
    check_http10_head: bool,
    close_without_shutdown: bool,
    reader: Option<ReadHalf<Box<dyn ConnectionIo>>>,
    extra_input: bool,
}

impl ResponseFramer for Framer {
    fn frame(&mut self, bytes: Bytes) -> Result<Bytes> {
        if std::mem::take(&mut self.check_http10_head) {
            let chunked = bytes
                .split(|byte| *byte == b'\n')
                .take_while(|line| *line != b"\r")
                .any(|line| line.strip_suffix(b"\r") == Some(crate::message::CHUNKED_HEADER));
            ensure!(!chunked, "chunked HTTP Replay requires an HTTP/1.1 request");
        }
        Ok(bytes)
    }

    fn target_stopped(&mut self) {
        self.close_without_shutdown = true;
    }

    fn wait_for_client_close(&mut self) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            ensure!(
                !self.extra_input,
                "client sent another request instead of closing HTTP stream"
            );
            let reader = self.reader.as_mut().expect("HTTP response reader");
            match reader.read(&mut [0_u8; 1]).await {
                Ok(0) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::UnexpectedEof
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    ) => {}
                Ok(_) => {
                    anyhow::bail!("client sent another request instead of closing HTTP stream")
                }
                Err(error) => return Err(error.into()),
            }
            self.close_without_shutdown = true;
            Ok(())
        })
    }
}

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
            let mut reader = wire::Reader::new(io);
            if let Some(head) = reader.request_head().await? {
                let _input = host.begin_input().await?;
                let http11 = head.http11;
                let request = reader.request_body(head).await?;
                let request = websocket_refusal::target_request(request, http11);
                let request = if tls && http11 {
                    crate::request_metadata::tls_target_request(request)
                } else {
                    request
                };
                let delivery = host.execute(request).await?;
                let extra_input = reader.has_buffered_input();
                let (read, mut write) = tokio::io::split(reader.io);
                let mut framer = Framer {
                    check_http10_head: !http11,
                    close_without_shutdown: false,
                    reader: Some(read),
                    extra_input,
                };
                delivery.write(&mut write, &mut framer).await?;
                if !framer.close_without_shutdown {
                    write.shutdown().await?;
                }
                return Ok(());
            }
            reader.io.shutdown().await?;
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http10_rejects_chunked_framing_only_in_the_response_head() {
        let mut framer = Framer {
            check_http10_head: true,
            close_without_shutdown: false,
            reader: None,
            extra_input: false,
        };
        let wire = Bytes::from_static(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
        assert!(framer.frame(wire).is_err());

        let mut framer = Framer {
            check_http10_head: true,
            close_without_shutdown: false,
            reader: None,
            extra_input: false,
        };
        let wire = Bytes::from_static(
            b"HTTP/1.1 200 OK\r\ncontent-length: 26\r\n\r\ntransfer-encoding: chunked",
        );
        assert_eq!(framer.frame(wire.clone()).unwrap(), wire);
    }
}
