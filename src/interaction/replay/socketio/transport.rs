//! Engine.IO transport I/O. Session IDs are learned only from the live Target.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _, stream::SplitSink};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode, Uri};
use std::collections::{BTreeMap, VecDeque};
use tokio::{net::TcpStream, sync::mpsc, task::JoinHandle};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{
        Message,
        client::IntoClientRequest as _,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

use super::super::HttpClient;
use crate::http::response_headers;
use crate::interaction::model::{MessageKind, WireMessage};
use crate::recorder::HeaderMapSnapshot;

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

type Writer = SplitSink<WebSocket, Message>;

struct ReaderTask(JoinHandle<()>);
impl ReaderTask {
    fn abort(&self) {
        self.0.abort();
    }
}
impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) enum ReaderEvent {
    Message(WireMessage),
    Ping(Bytes),
    Close { code: Option<u16>, reason: String },
    Closed,
    Error(String),
}

enum Outgoing {
    Polling {
        client: Box<HttpClient>,
        uri: Uri,
        headers: hyper::HeaderMap,
    },
    WebSocket(Writer),
    Closed,
}

pub(super) struct Transport {
    outgoing: Outgoing,
    reader: ReaderTask,
    tx: mpsc::Sender<ReaderEvent>,
    rx: mpsc::Receiver<ReaderEvent>,
    deferred: VecDeque<ReaderEvent>,
    origin: String,
    sid: Option<String>,
    max_message_bytes: usize,
    socket_io: bool,
    engine_close_sent: bool,
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMapSnapshot,
}

impl Transport {
    pub(super) async fn connect(
        client: HttpClient,
        origin: &str,
        request: Request<Full<Bytes>>,
        max_message_bytes: usize,
        generic_websocket: bool,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(64);
        let websocket = generic_websocket
            || query_parameter(request.uri(), "transport").as_deref() == Some("websocket");
        if !generic_websocket {
            ensure!(
                query_parameter(request.uri(), "EIO").as_deref() == Some("4"),
                "only Engine.IO v4 replay is supported"
            );
            ensure!(
                query_parameter(request.uri(), "sid").is_none(),
                "Socket.IO replay must begin with a fresh session without a recorded SID"
            );
        }
        if websocket {
            let (writer, reader, response) = connect_websocket(
                request.uri(),
                request.headers(),
                tx.clone(),
                max_message_bytes,
            )
            .await?;
            return Ok(Self {
                outgoing: Outgoing::WebSocket(writer),
                reader,
                tx,
                rx,
                origin: origin.into(),
                sid: None,
                max_message_bytes,
                socket_io: !generic_websocket,
                engine_close_sent: false,
                deferred: VecDeque::new(),
                status: response.status(),
                headers: response_headers::snapshot_standard(response.headers()),
            });
        }
        ensure!(
            query_parameter(request.uri(), "transport").as_deref() == Some("polling"),
            "unsupported Engine.IO transport"
        );
        let uri = request.uri().clone();
        let mut request_headers = request.headers().clone();
        let response = client
            .request(request)
            .await
            .context("Engine.IO polling handshake failed")?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "Engine.IO polling handshake returned HTTP {status}"
        );
        let headers = response_headers::snapshot_standard(response.headers());
        apply_response_cookies(&mut request_headers, response.headers())?;
        let bytes = collect_body(response.into_body(), max_message_bytes).await?;
        let deferred = parse_payload(&bytes, max_message_bytes)?
            .into_iter()
            .map(ReaderEvent::Message)
            .collect();
        // The reader waits until OPEN has supplied a live SID via set_sid().
        let reader = ReaderTask(tokio::spawn(async {}));
        Ok(Self {
            outgoing: Outgoing::Polling {
                client: Box::new(client),
                uri,
                headers: request_headers,
            },
            reader,
            tx,
            rx,
            origin: origin.into(),
            sid: None,
            max_message_bytes,
            socket_io: true,
            engine_close_sent: false,
            deferred,
            status,
            headers,
        })
    }

    pub(super) fn set_sid(&mut self, sid: String) -> Result<()> {
        ensure!(!sid.is_empty(), "Target Engine.IO OPEN has an empty SID");
        if let Some(previous) = &self.sid {
            ensure!(
                *previous == sid,
                "Target changed Engine.IO SID in a live session"
            );
            return Ok(());
        }
        self.sid = Some(sid.clone());
        if let Outgoing::Polling {
            client,
            uri,
            headers,
        } = &self.outgoing
        {
            let uri = with_sid(uri, &sid)?;
            let client = client.clone();
            let headers = headers.clone();
            let tx = self.tx.clone();
            let limit = self.max_message_bytes;
            self.reader = ReaderTask(tokio::spawn(async move {
                loop {
                    let result = async {
                        let mut request = Request::builder()
                            .method("GET")
                            .uri(uri.clone())
                            .body(Full::new(Bytes::new()))?;
                        copy_headers(&headers, request.headers_mut());
                        let response = client
                            .request(request)
                            .await
                            .context("Engine.IO polling read failed")?;
                        ensure!(
                            response.status().is_success(),
                            "Engine.IO polling read returned HTTP {}",
                            response.status()
                        );
                        let bytes = collect_body(response.into_body(), limit).await?;
                        ensure!(
                            !bytes.is_empty(),
                            "Engine.IO polling returned an empty payload"
                        );
                        send_payload(&tx, &bytes, limit).await
                    }
                    .await;
                    match result {
                        Ok(true) => break,
                        Ok(false) => {}
                        Err(error) => {
                            let _ = tx.send(ReaderEvent::Error(format!("{error:#}"))).await;
                            break;
                        }
                    }
                }
            }));
        }
        Ok(())
    }

    pub(super) async fn recv(&mut self) -> Option<ReaderEvent> {
        if let Some(event) = self.deferred.pop_front() {
            Some(event)
        } else {
            self.rx.recv().await
        }
    }

    pub(super) async fn send(&mut self, message: &WireMessage) -> Result<()> {
        match &mut self.outgoing {
            Outgoing::WebSocket(writer) => {
                let message = match message.kind {
                    MessageKind::Text => Message::Text(message.data.clone().into()),
                    MessageKind::Binary => Message::Binary(message.decode()?.into()),
                };
                writer
                    .send(message)
                    .await
                    .context("Socket.IO WebSocket send failed")?;
            }
            Outgoing::Polling {
                client,
                uri,
                headers,
            } => {
                let sid = self
                    .sid
                    .as_deref()
                    .context("cannot send polling packet before Target OPEN")?;
                let uri = with_sid(uri, sid)?;
                let payload = match message.kind {
                    MessageKind::Text => message.data.clone(),
                    MessageKind::Binary => format!("b{}", message.data),
                };
                let mut request = Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "text/plain;charset=UTF-8")
                    .body(Full::new(Bytes::from(payload)))?;
                copy_headers(headers, request.headers_mut());
                let response = client
                    .request(request)
                    .await
                    .context("Engine.IO polling write failed")?;
                ensure!(
                    response.status().is_success(),
                    "Engine.IO polling write returned HTTP {}",
                    response.status()
                );
                let response = collect_body(response.into_body(), self.max_message_bytes).await?;
                ensure!(
                    response.as_ref() == b"ok",
                    "unexpected Engine.IO polling POST acknowledgement"
                );
            }
            Outgoing::Closed => anyhow::bail!("Socket.IO transport is closed"),
        }
        if self.socket_io && message.kind == MessageKind::Text && message.data == "1" {
            self.engine_close_sent = true;
        }
        Ok(())
    }

    pub(super) fn is_websocket(&self) -> bool {
        matches!(self.outgoing, Outgoing::WebSocket(_))
    }

    pub(super) async fn pong(&mut self, bytes: Bytes) -> Result<()> {
        if let Outgoing::WebSocket(writer) = &mut self.outgoing {
            writer.send(Message::Pong(bytes)).await?;
        }
        Ok(())
    }

    pub(super) async fn upgrade(
        &mut self,
        uri: &str,
        headers: &BTreeMap<String, Vec<String>>,
    ) -> Result<()> {
        ensure!(
            matches!(self.outgoing, Outgoing::Polling { .. }),
            "Engine.IO upgrade requires an active polling transport"
        );
        let sid = self
            .sid
            .as_deref()
            .context("Engine.IO upgrade requires Target OPEN")?;
        let uri = with_sid(
            &crate::recorded_request::target_uri(&self.origin, uri)?,
            sid,
        )?;
        ensure!(
            query_parameter(&uri, "transport").as_deref() == Some("websocket"),
            "Engine.IO upgrade URI must select websocket transport"
        );
        let mut request_headers = hyper::HeaderMap::new();
        for (name, values) in headers {
            let name = hyper::header::HeaderName::from_bytes(name.as_bytes())?;
            for value in values {
                request_headers.append(name.clone(), value.parse()?);
            }
        }
        let (mut writer, reader, _) = connect_websocket(
            &uri,
            &request_headers,
            self.tx.clone(),
            self.max_message_bytes,
        )
        .await?;
        writer.send(Message::Text("2probe".into())).await?;
        // Probe is transport control; ordinary polling events received meanwhile are retained.
        let mut deferred = Vec::new();
        let mut deferred_bytes = 0usize;
        loop {
            match self
                .rx
                .recv()
                .await
                .context("WebSocket upgrade probe ended")?
            {
                ReaderEvent::Message(message) if message == WireMessage::text("3probe") => break,
                ReaderEvent::Closed | ReaderEvent::Close { .. } => {
                    anyhow::bail!("Target closed during Engine.IO upgrade probe")
                }
                ReaderEvent::Error(message) => anyhow::bail!("Engine.IO upgrade failed: {message}"),
                event => {
                    if let ReaderEvent::Message(message) = &event {
                        deferred_bytes = deferred_bytes.saturating_add(message.decode()?.len());
                        ensure!(
                            deferred_bytes <= self.max_message_bytes,
                            "Engine.IO upgrade deferred output exceeds budget"
                        );
                    }
                    ensure!(
                        deferred.len() < 1024,
                        "Engine.IO upgrade has too many deferred messages"
                    );
                    deferred.push(event);
                }
            }
        }
        writer.send(Message::Text("5".into())).await?;
        self.reader.abort();
        self.reader = reader;
        self.outgoing = Outgoing::WebSocket(writer);
        // Retain polling observations ahead of later WebSocket messages.
        self.deferred.extend(deferred);
        Ok(())
    }

    pub(super) async fn close(&mut self, code: Option<u16>, reason: &str) -> Result<()> {
        self.finish_close(code, reason, true).await
    }

    /// Rejected or otherwise failed requests must not wait for the peer's application loop.
    pub(super) async fn abort(&mut self, code: Option<u16>, reason: &str) -> Result<()> {
        self.finish_close(code, reason, false).await
    }

    async fn finish_close(
        &mut self,
        code: Option<u16>,
        reason: &str,
        wait_for_peer: bool,
    ) -> Result<()> {
        let websocket = matches!(self.outgoing, Outgoing::WebSocket(_));
        match &mut self.outgoing {
            Outgoing::Closed => return Ok(()),
            Outgoing::WebSocket(writer) => {
                let result = async {
                    if self.socket_io && !self.engine_close_sent {
                        writer.send(Message::Text("1".into())).await?;
                        self.engine_close_sent = true;
                    }
                    writer
                        .send(Message::Close(code.map(|code| CloseFrame {
                            code: CloseCode::from(code),
                            reason: reason.into(),
                        })))
                        .await?;
                    writer.close().await
                }
                .await;
                match result {
                    Ok(())
                    | Err(
                        tokio_tungstenite::tungstenite::Error::ConnectionClosed
                        | tokio_tungstenite::tungstenite::Error::AlreadyClosed,
                    ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Outgoing::Polling { .. } => {
                if !self.engine_close_sent {
                    self.send(&WireMessage::text("1")).await?;
                }
            }
        }
        // Flushing our close is not completion of the peer's close operation.
        // In particular, a preceding Socket.IO namespace disconnect can still
        // be awaiting real application cleanup before the peer processes CLOSE.
        // Retain the live reader and Case until actual peer termination; the
        // caller bounds this I/O and can interrupt it on dependency rejection.
        if websocket && wait_for_peer {
            while let Some(ReaderEvent::Message(_) | ReaderEvent::Ping(_)) = self.recv().await {}
        }
        self.outgoing = Outgoing::Closed;
        self.reader.abort();
        Ok(())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn connect_websocket(
    uri: &Uri,
    headers: &hyper::HeaderMap,
    tx: mpsc::Sender<ReaderEvent>,
    limit: usize,
) -> Result<(Writer, ReaderTask, hyper::Response<Option<Vec<u8>>>)> {
    let mut url = url::Url::parse(&uri.to_string())?;
    url.set_scheme(if uri.scheme_str() == Some("https") {
        "wss"
    } else {
        "ws"
    })
    .map_err(|_| anyhow::anyhow!("invalid Target WebSocket URL"))?;
    let mut request = url.as_str().into_client_request()?;
    copy_headers(headers, request.headers_mut());
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit));
    let (socket, response) =
        tokio_tungstenite::connect_async_with_config(request, Some(config), true)
            .await
            .context("Target WebSocket handshake failed")?;
    let (writer, mut incoming) = socket.split();
    let reader = tokio::spawn(async move {
        while let Some(message) = incoming.next().await {
            let event = match message {
                Ok(Message::Text(data)) => ReaderEvent::Message(WireMessage::text(data.as_str())),
                Ok(Message::Binary(data)) => ReaderEvent::Message(WireMessage::binary(&data)),
                Ok(Message::Ping(data)) => ReaderEvent::Ping(data),
                Ok(Message::Pong(_)) => continue,
                Ok(Message::Close(frame)) => {
                    let (code, reason) = frame.map_or((None, String::new()), |frame| {
                        (Some(u16::from(frame.code)), frame.reason.to_string())
                    });
                    let _ = tx.send(ReaderEvent::Close { code, reason }).await;
                    return;
                }
                Ok(Message::Frame(_)) => continue,
                Err(error) => ReaderEvent::Error(error.to_string()),
            };
            if tx.send(event).await.is_err() {
                return;
            }
        }
        let _ = tx.send(ReaderEvent::Closed).await;
    });
    Ok((writer, ReaderTask(reader), response))
}

fn copy_headers(source: &hyper::HeaderMap, target: &mut hyper::HeaderMap) {
    for (name, value) in source {
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "upgrade"
                | "content-length"
                | "transfer-encoding"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-extensions"
                | "sec-websocket-accept"
                | "content-type"
        ) {
            continue;
        }
        target.append(name, value.clone());
    }
}

fn query_parameter(uri: &Uri, name: &str) -> Option<String> {
    url::form_urlencoded::parse(uri.query()?.as_bytes())
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn with_sid(uri: &Uri, sid: &str) -> Result<Uri> {
    let mut url = url::Url::parse(&uri.to_string())?;
    let pairs = url
        .query_pairs()
        .filter(|(key, _)| key != "sid" && key != "t")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("sid", sid);
    Ok(url.as_str().parse()?)
}

async fn send_payload(tx: &mpsc::Sender<ReaderEvent>, bytes: &[u8], limit: usize) -> Result<bool> {
    let mut closed = false;
    for message in parse_payload(bytes, limit)? {
        closed |= message.kind == MessageKind::Text && message.data == "1";
        tx.send(ReaderEvent::Message(message))
            .await
            .context("Engine.IO receiver stopped")?;
    }
    Ok(closed)
}

fn parse_payload(bytes: &[u8], limit: usize) -> Result<Vec<WireMessage>> {
    let payload = std::str::from_utf8(bytes).context("Engine.IO polling payload is not UTF-8")?;
    payload
        .split('\u{1e}')
        .map(|packet| {
            ensure!(
                packet.len() <= limit,
                "Engine.IO polling packet exceeds message budget"
            );
            Ok(if let Some(binary) = packet.strip_prefix('b') {
                WireMessage::binary(&STANDARD.decode(binary)?)
            } else {
                WireMessage::text(packet)
            })
        })
        .collect()
}

async fn collect_body(mut body: hyper::body::Incoming, limit: usize) -> Result<Bytes> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            ensure!(
                bytes.len().saturating_add(data.len()) <= limit,
                "Engine.IO polling payload exceeds configured limit"
            );
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.into())
}

fn apply_response_cookies(
    target: &mut hyper::HeaderMap,
    response: &hyper::HeaderMap,
) -> Result<()> {
    let mut cookies = BTreeMap::new();
    for header in target.get_all(hyper::header::COOKIE) {
        for cookie in header.to_str()?.split(';') {
            if let Some((name, value)) = cookie.trim().split_once('=') {
                cookies.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    for header in response.get_all(hyper::header::SET_COOKIE) {
        if let Some((name, value)) = header
            .to_str()?
            .split(';')
            .next()
            .unwrap_or_default()
            .split_once('=')
        {
            cookies.insert(name.trim().to_owned(), value.to_owned());
        }
    }
    if !cookies.is_empty() {
        target.insert(
            hyper::header::COOKIE,
            cookies
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ")
                .parse()?,
        );
    }
    Ok(())
}
