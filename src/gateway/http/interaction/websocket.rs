//! WebSocket upgrade and a bidirectional, message-preserving recording pump.

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

pub(super) fn restore_upgrade(source: &hyper::HeaderMap, target: &mut hyper::HeaderMap) {
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
    let uri = transport::build_upstream_uri(&session.upstream, &parts.uri)?;
    let mut request = transport::build_upstream_request(
        &parts.method,
        uri,
        bytes,
        &parts.headers,
        session.state.config().http_gateway.preserve_host,
    )?;
    restore_upgrade(&parts.headers, request.headers_mut());
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
        let result = async {
            let (downstream, upstream) = tokio::try_join!(downstream, upstream)?;
            let limit = session.state.config().http_gateway.interaction.max_message_bytes;
            let socket_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(limit)).max_frame_size(Some(limit));
            let mut downstream = WebSocketStream::from_raw_socket(TokioIo::new(downstream), Role::Server, Some(socket_config)).await;
            let mut upstream = WebSocketStream::from_raw_socket(TokioIo::new(upstream), Role::Client, Some(socket_config)).await;
            loop {
                tokio::select! {
                    message = downstream.next() => {
                        let Some(message) = message else { session.request_close(EndReason::ClientClose); break; };
                        let message = message?;
                        observe(&session, &message, true)?;
                        let close = matches!(message, Message::Close(_));
                        let logical_close = matches!(&message, Message::Text(text) if text.as_str() == "1") && session.observation.lock().expect("interaction observation poisoned").protocol() == crate::interaction::model::Protocol::SocketIo;
                        upstream.send(message).await?;
                        if logical_close && !close {
                            session.request_close(EndReason::ClientClose);
                            let _ = upstream.close(None).await;
                            let _ = downstream.close(None).await;
                            break;
                        }
                        if close { session.request_close(EndReason::ClientClose); break; }
                    }
                    message = upstream.next() => {
                        let Some(message) = message else { session.request_close(EndReason::ServerEof); break; };
                        let message = message?;
                        observe(&session, &message, false)?;
                        let close = matches!(message, Message::Close(_));
                        downstream.send(message).await?;
                        if close { session.request_close(EndReason::ServerEof); break; }
                    }
                    _ = closing.changed() => {
                        let frame = Some(CloseFrame { code: CloseCode::Normal, reason: "recording case complete".into() });
                        // Engine.IO CLOSE releases the Source session before TCP shutdown.
                        if !session.eio_closed.load(std::sync::atomic::Ordering::SeqCst) && session.observation.lock().expect("interaction observation poisoned").protocol() == crate::interaction::model::Protocol::SocketIo { let _ = upstream.send(Message::Text("1".into())).await; }
                        let _ = upstream.close(frame.clone()).await;
                        let _ = downstream.close(frame).await;
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        if let Err(error) = result {
            tracing::debug!(%error, "recorded WebSocket ended");
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
