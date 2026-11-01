//! WebSocket upgrade and a bidirectional, message-preserving recording pump.
mod closing;
mod disconnect;
mod disconnect_read;
mod failure;
mod upstream;

use super::{
    SessionRef,
    transport::{self, GatewayBody},
};
use crate::interaction::model::{EndReason, WireMessage};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use std::sync::{Arc, Mutex};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{CloseFrame, Role, frame::coding::CloseCode},
    },
};

#[derive(Clone)]
pub(super) struct DownstreamUpgrade(pub(super) Arc<Mutex<Option<OnUpgrade>>>);

pub(super) fn restore_upgrade(
    source: &hyper::HeaderMap,
    target: &mut hyper::HeaderMap,
    body_is_empty: bool,
) {
    for name in [
        "upgrade",
        "connection",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "origin",
    ] {
        if let Some(value) = source.get(name) {
            target.insert(name, value.clone());
        }
    }
    // Compression must be decoded by this recorder. Negotiate uncompressed frames.
    target.remove("sec-websocket-extensions");
    // Older gateways materialize empty upgrade bodies as Content-Length: 0.
    // Source's strict WebSocket parser rejects even that empty HTTP body.
    // Normalize only a body we have fully read and proved empty.
    if body_is_empty {
        target.remove(hyper::header::CONTENT_LENGTH);
        target.remove(hyper::header::TRANSFER_ENCODING);
    }
}

pub(super) async fn dispatch(
    req: Request<Full<Bytes>>,
    session: SessionRef,
    initial: bool,
) -> Result<Response<GatewayBody>> {
    if session
        .observation
        .lock()
        .expect("interaction observation poisoned")
        .protocol()
        == crate::interaction::model::Protocol::SocketIo
    {
        let transport = crate::interaction::socketio::classify_request(
            req.method().as_str(),
            &req.uri().to_string(),
            true,
        )?;
        ensure!(
            transport.transport == crate::interaction::socketio::Transport::WebSocket,
            "Engine.IO transport does not match WebSocket"
        );
        let bound_sid = session
            .sid
            .lock()
            .expect("interaction SID poisoned")
            .clone();
        ensure!(
            if initial {
                transport.sid.is_none()
            } else {
                transport.sid == bound_sid
            },
            "Engine.IO WebSocket SID does not match this case"
        );
    }
    let downstream = req
        .extensions()
        .get::<DownstreamUpgrade>()
        .context("missing downstream upgrade")?
        .0
        .lock()
        .expect("upgrade poisoned")
        .take()
        .context("upgrade already taken")?;
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let body_is_empty = bytes.is_empty();
    let uri = transport::build_upstream_uri(&session.upstream, &parts.uri)?;
    let mut request = transport::build_upstream_request(
        &parts.method,
        uri,
        bytes,
        &parts.headers,
        session.state.config().http_gateway.preserve_host,
    )?;
    restore_upgrade(&parts.headers, request.headers_mut(), body_is_empty);
    let mut closing = session.close.subscribe();
    let mut response = tokio::select! {
        response = session.state.client().request(request) => response.context("WebSocket upstream upgrade failed")?,
        _ = closing.changed() => anyhow::bail!("WebSocket case closed before upgrade"),
    };
    ensure!(
        response.status() == StatusCode::SWITCHING_PROTOCOLS,
        "upstream refused WebSocket upgrade"
    );
    ensure!(
        !response.headers().contains_key("sec-websocket-extensions"),
        "upstream negotiated unsupported WebSocket compression"
    );
    if !initial {
        let mut recorded_headers = crate::recorder::HeaderMapSnapshot::new();
        for (name, value) in &parts.headers {
            recorded_headers.entry(name.to_string()).or_default().push(
                value
                    .to_str()
                    .context("WebSocket upgrade header is not UTF-8")?
                    .to_owned(),
            );
        }
        session
            .observation
            .lock()
            .expect("interaction observation poisoned")
            .upgrade(parts.uri.to_string(), recorded_headers, session.now())?;
    } else {
        *session
            .response
            .lock()
            .expect("interaction response poisoned") =
            Some((response.status().as_u16(), response.headers().clone()));
    }
    let upstream = hyper::upgrade::on(&mut response);
    let lifetime = super::transport_lifetime::TransportLifetime::new(session.clone());
    let owner = session.clone();
    let case_id = session.case.id;
    let task = tokio::spawn(async move {
        let _lifetime = lifetime;
        let mut phase = "upgrade";
        let mut client_close_code = None;
        let result = async {
            let (downstream, upstream) = tokio::try_join!(downstream, upstream)?;
            let limit = session.state.config().http_gateway.interaction.max_message_bytes;
            let socket_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(limit)).max_frame_size(Some(limit));
            let (downstream, client_transport) = crate::interaction::websocket_transport::FramedTransport::new(TokioIo::new(downstream), true);
            let mut downstream = WebSocketStream::from_raw_socket(downstream, Role::Server, Some(socket_config)).await;
            let (mut upstream, upstream_control) = upstream::upgrade(upstream, socket_config).await?;
            loop {
                tokio::select! {
                    message = downstream.next() => {
                        phase = "client_read";
                        let message = match message {
                            Some(Ok(message)) => message,
                            Some(Err(error)) if failure::client_lost(&error) => {
                                phase = "client_disconnect_cleanup";
                                disconnect::observed(&session, &mut upstream, &upstream_control, &client_transport, &error.into()).await?;
                                break;
                            }
                            Some(Err(error)) => return Err(error.into()),
                            None => anyhow::bail!("client WebSocket ended without an observed CLOSE"),
                        };
                        if let Message::Close(frame) = &message {
                            client_close_code = frame.as_ref().map(|frame| u16::from(frame.code));
                        }
                        phase = "client_observe";
                        observe(&session, &message, true)?;
                        let close = matches!(message, Message::Close(_));
                        let logical_close = matches!(&message, Message::Text(text) if text.as_str() == "1") && session.observation.lock().expect("interaction observation poisoned").protocol() == crate::interaction::model::Protocol::SocketIo;
                        let completion = if logical_close || close {
                            session.request_close(EndReason::ClientClose);
                            phase = "close_prepare";
                            closing::ApplicationClose::prepare(&session).await?
                        } else { None };
                        phase = "upstream_send";
                        upstream.send(message).await?;
                        if logical_close && !close {
                            session.request_close(EndReason::ClientClose);
                            let _ = downstream.close(None).await;
                            phase = "close_confirmation";
                            if let Some(completion) = completion { completion.wait_after_close(&session).await?; }
                            let _ = upstream.close(None).await;
                            wait_peer_close(&mut upstream).await;
                            break;
                        }
                        if close {
                            session.request_close(EndReason::ClientClose);
                            // Flush Tungstenite's queued echo while the case
                            // still retains Source application disconnect work.
                            let _ = downstream.flush().await;
                            phase = "close_confirmation";
                            if let Some(completion) = completion { completion.wait_after_close(&session).await?; }
                            wait_peer_close(&mut upstream).await;
                            break;
                        }
                    }
                    message = upstream.next() => {
                        phase = "source_read";
                        let Some(message) = message else { session.request_close(EndReason::ServerEof); break; };
                        let message = message?;
                        phase = "source_observe";
                        observe(&session, &message, false)?;
                        let close = matches!(message, Message::Close(_));
                        phase = "downstream_send";
                        if let Err(error) = downstream.send(message).await {
                            if !failure::client_lost(&error) { return Err(error.into()); }
                            phase = "client_disconnect_read";
                            let timeout_ms = session.observation.lock().expect("interaction observation poisoned").policy().cleanup_timeout_ms;
                            let read_error = disconnect_read::after_write_failure(
                                &mut downstream, &client_transport, &mut closing,
                                std::time::Duration::from_millis(timeout_ms),
                            ).await?;
                            phase = "client_disconnect_cleanup";
                            disconnect::observed(&session, &mut upstream, &upstream_control, &client_transport, &read_error.into()).await?;
                            break;
                        }
                        if close { session.request_close(EndReason::ServerEof); break; }
                    }
                    _ = closing.changed() => {
                        client_transport.begin_cleanup();
                        let frame = Some(CloseFrame { code: CloseCode::Normal, reason: "recording case complete".into() });
                        phase = "close_prepare";
                        let completion = closing::ApplicationClose::prepare(&session).await?;
                        // Engine.IO CLOSE releases the Source session before TCP shutdown.
                        let socket_io = session.observation.lock().expect("interaction observation poisoned").protocol() == crate::interaction::model::Protocol::SocketIo;
                        if socket_io {
                            if !session.eio_closed.load(std::sync::atomic::Ordering::SeqCst) { let _ = upstream.send(Message::Text("1".into())).await; }
                        } else { let _ = upstream.close(frame.clone()).await; }
                        let _ = downstream.close(frame).await;
                        phase = "close_confirmation";
                        if let Some(completion) = completion { completion.wait_after_close(&session).await?; }
                        let _ = upstream.close(None).await;
                        wait_peer_close(&mut upstream).await;
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        if let Err(error) = result {
            session
                .transport_failed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            session.state.invalidate_active_case(
                session.case.id,
                crate::recorder::CaseInvalidation::new(
                    "interaction_transport_failed",
                    format!("WebSocket failed: phase={phase}, error_kind={}; capture is incomplete; inspect recorder diagnostics and record again", failure::kind(&error)),
                ),
            );
            tracing::warn!(
                case_id = %session.case.id,
                phase,
                client_close_code,
                error_kind = failure::kind(&error),
                confirmation = ?error.downcast_ref::<closing::ConfirmationFailure>(),
                "recorded WebSocket transport or application-close confirmation failed"
            );
            session.request_close(EndReason::TransportError);
        }
    });
    owner
        .transports
        .lock()
        .expect("interaction transports poisoned")
        .push(task.abort_handle());
    let (mut parts, body) = response.into_parts();
    parts
        .headers
        .insert("x-traffic-e2e-case-id", case_id.to_string().parse()?);
    Ok(Response::from_parts(
        parts,
        body.map_err(anyhow::Error::from).boxed_unsync(),
    ))
}

/// Keep TransportLifetime alive until Source completes its close operation.
/// finish::run owns the cleanup deadline and marks an aborted transport incomplete.
async fn wait_peer_close<S>(socket: &mut WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(Ok(message)) = socket.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
    let _ = socket.close(None).await;
}

fn observe(session: &SessionRef, message: &Message, input: bool) -> Result<()> {
    if !input && let Message::Close(frame) = message {
        session
            .observation
            .lock()
            .expect("interaction observation poisoned")
            .server_close(
                frame.as_ref().map(|frame| u16::from(frame.code)),
                frame
                    .as_ref()
                    .map_or("", |frame| frame.reason.as_str())
                    .to_owned(),
            );
    }
    if input && let Message::Close(frame) = message {
        session
            .observation
            .lock()
            .expect("interaction observation poisoned")
            .client_close(
                frame.as_ref().map(|frame| u16::from(frame.code)),
                frame
                    .as_ref()
                    .map_or("", |frame| frame.reason.as_str())
                    .to_owned(),
                session.now(),
            )?;
    }
    let wire = match message {
        Message::Text(text) => Some(WireMessage::text(text.as_str())),
        Message::Binary(bytes) => Some(WireMessage::binary(bytes)),
        _ => None,
    };
    if let Some(wire) = wire {
        if !input
            && wire.kind == crate::interaction::model::MessageKind::Text
            && wire.data.starts_with('0')
            && session
                .observation
                .lock()
                .expect("interaction observation poisoned")
                .protocol()
                == crate::interaction::model::Protocol::SocketIo
            && let crate::interaction::socketio::EngineIoPacket::Open(open) =
                crate::interaction::socketio::decode_engine_io_text(
                    &wire.data,
                    session
                        .state
                        .config()
                        .http_gateway
                        .interaction
                        .max_message_bytes,
                )?
        {
            let mut sid = session.sid.lock().expect("interaction SID poisoned");
            ensure!(
                sid.as_ref().is_none_or(|sid| sid == &open.sid),
                "Source changed its live Engine.IO SID"
            );
            *sid = Some(open.sid);
        }
        if wire.kind == crate::interaction::model::MessageKind::Text
            && wire.data == "1"
            && session
                .observation
                .lock()
                .expect("interaction observation poisoned")
                .protocol()
                == crate::interaction::model::Protocol::SocketIo
        {
            session
                .eio_closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if input {
            if wire.kind == crate::interaction::model::MessageKind::Text && wire.data == "5" {
                session
                    .upgraded
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            session.observe_input(wire)?;
        } else {
            session
                .observation
                .lock()
                .expect("interaction observation poisoned")
                .output(wire, session.now())?;
        }
        session.changed.notify_one();
    }
    Ok(())
}
