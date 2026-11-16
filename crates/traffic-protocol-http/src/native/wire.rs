//! Bounded finite HTTP/1 framing and transfer decoding.
use super::*;
use crate::headers::HeaderSnapshot;
use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use traffic_protocol::connection::ConnectionIo;

pub(super) struct Reader {
    pub io: Box<dyn ConnectionIo>,
    buffer: BytesMut,
    limit: usize,
}

impl Reader {
    pub fn new(io: Box<dyn ConnectionIo>, limit: usize) -> Self {
        Self {
            io,
            buffer: BytesMut::new(),
            limit,
        }
    }

    async fn read_more(&mut self) -> Result<bool> {
        let mut bytes = [0; 8192];
        let length = self.io.read(&mut bytes).await?;
        ensure!(
            self.buffer
                .len()
                .checked_add(length)
                .is_some_and(|size| size <= self.limit.saturating_add(65536)),
            "HTTP frame exceeds the byte limit"
        );
        self.buffer.extend_from_slice(&bytes[..length]);
        Ok(length > 0)
    }

    async fn head(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(end) = self
                .buffer
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
            {
                ensure!(end + 4 <= 65536, "HTTP headers exceed the byte limit");
                return Ok(Some(self.buffer.split_to(end + 4).freeze()));
            }
            ensure!(
                self.buffer.len() < 65536,
                "HTTP headers exceed the byte limit"
            );
            if !self.read_more().await? {
                ensure!(
                    self.buffer.is_empty(),
                    "HTTP headers ended before completion"
                );
                return Ok(None);
            }
        }
    }

    async fn take(&mut self, length: usize) -> Result<Bytes> {
        ensure!(length <= self.limit, "HTTP body exceeds the byte limit");
        while self.buffer.len() < length {
            ensure!(self.read_more().await?, "HTTP body ended before completion");
        }
        Ok(self.buffer.split_to(length).freeze())
    }

    async fn chunked(&mut self) -> Result<Bytes> {
        let mut output = BytesMut::new();
        loop {
            let (offset, size) = loop {
                if let httparse::Status::Complete(chunk) = httparse::parse_chunk_size(&self.buffer)
                    .map_err(|_| anyhow::anyhow!("invalid HTTP chunk size"))?
                {
                    break chunk;
                }
                ensure!(
                    self.buffer.len() < 8192,
                    "HTTP chunk header exceeds the byte limit"
                );
                ensure!(
                    self.read_more().await?,
                    "HTTP chunk header ended before completion"
                );
            };
            let _ = self.buffer.split_to(offset);
            let size = usize::try_from(size)?;
            ensure!(
                output
                    .len()
                    .checked_add(size)
                    .is_some_and(|length| length <= self.limit),
                "HTTP chunked body exceeds the byte limit"
            );
            output.extend_from_slice(&self.take(size).await?);
            ensure!(
                self.take(2).await?.as_ref() == b"\r\n",
                "HTTP chunk delimiter or trailers are unsupported"
            );
            if size == 0 {
                return Ok(output.freeze());
            }
        }
    }

    async fn body(&mut self, headers: &HeaderSnapshot) -> Result<Bytes> {
        let transfer = headers.get("transfer-encoding");
        let lengths = headers.get("content-length");
        if let Some(transfer) = transfer {
            ensure!(
                lengths.is_none()
                    && transfer.len() == 1
                    && transfer[0].eq_ignore_ascii_case("chunked"),
                "HTTP transfer framing is ambiguous or unsupported"
            );
            return self.chunked().await;
        }
        let length = if let Some(lengths) = lengths {
            let first = lengths.first().context("HTTP content length is empty")?;
            ensure!(
                lengths.iter().all(|length| length == first),
                "HTTP content lengths disagree"
            );
            ensure!(
                first.bytes().all(|byte| byte.is_ascii_digit()) && !first.is_empty(),
                "invalid HTTP content length"
            );
            first.parse::<usize>()?
        } else {
            0
        };
        self.take(length).await
    }

    pub async fn request(&mut self) -> Result<Option<RequestMessage>> {
        let Some(head) = self.head().await? else {
            return Ok(None);
        };
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut headers);
        ensure!(
            request.parse(&head)?.is_complete(),
            "HTTP request headers are incomplete"
        );
        let method = request.method.context("HTTP method missing")?.to_owned();
        ensure!(
            method != "CONNECT",
            "HTTP CONNECT requires an installed tunnel capability"
        );
        let uri: hyper::Uri = request
            .path
            .context("HTTP request target missing")?
            .parse()?;
        let uri = uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        let headers = snapshot(request.headers)?;
        ensure!(
            !headers.contains_key("upgrade") && !headers.contains_key("expect"),
            "HTTP upgrades and expect/continue require an installed streaming capability"
        );
        let body = self.body(&headers).await?;
        Ok(Some(RequestMessage {
            method,
            uri,
            headers,
            body,
        }))
    }

    pub async fn response(&mut self, method: &str) -> Result<ResponseMessage> {
        for _ in 0..8 {
            let head = self
                .head()
                .await?
                .context("HTTP upstream ended before response headers")?;
            let mut fields = [httparse::EMPTY_HEADER; 128];
            let mut response = httparse::Response::new(&mut fields);
            ensure!(
                response.parse(&head)?.is_complete(),
                "HTTP response headers are incomplete"
            );
            let status = response.code.context("HTTP response status missing")?;
            ensure!(
                status != 101,
                "HTTP upgrades require an installed streaming capability"
            );
            let headers = snapshot(response.headers)?;
            if (100..200).contains(&status) {
                continue;
            }
            finite_response_headers(&headers)?;
            let bodyless = method == "HEAD" || matches!(status, 204 | 304);
            let body = if bodyless {
                Bytes::new()
            } else if headers.contains_key("content-length")
                || headers.contains_key("transfer-encoding")
            {
                self.body(&headers).await?
            } else {
                while self.read_more().await? {}
                ensure!(
                    self.buffer.len() <= self.limit,
                    "HTTP body exceeds the byte limit"
                );
                self.buffer.split().freeze()
            };
            return Ok(ResponseMessage {
                status,
                headers,
                body,
                head_request: method == "HEAD",
            });
        }
        anyhow::bail!("too many interim HTTP responses")
    }
}

fn snapshot(headers: &[httparse::Header<'_>]) -> Result<HeaderSnapshot> {
    let mut values = HeaderSnapshot::new();
    for header in headers {
        values
            .entry(header.name.to_ascii_lowercase())
            .or_default()
            .push(std::str::from_utf8(header.value)?.to_owned());
    }
    Ok(values)
}
