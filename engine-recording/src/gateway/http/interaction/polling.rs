//! Engine.IO polling shares one recording case across all HTTP requests.

use super::{
    SessionRef,
    transport::{self, GatewayBody},
};
use crate::interaction::{
    model::{EndReason, WireMessage},
    socketio::{EngineIoPacket, decode_engine_io_text},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};

pub(super) async fn dispatch(
    req: Request<Full<Bytes>>,
    session: SessionRef,
    initial: bool,
) -> Result<Response<GatewayBody>> {
    let _lifetime = super::transport_lifetime::TransportLifetime::new(session.clone());
    let transport = crate::interaction::socketio::classify_request(
        req.method().as_str(),
        &req.uri().to_string(),
        false,
    )?;
    ensure!(
        transport.transport == crate::interaction::socketio::Transport::Polling,
        "Engine.IO transport does not match polling"
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
        "Engine.IO polling SID does not match this case"
    );
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await?.to_bytes();
    if parts.method == hyper::Method::POST {
        observe(&session, &bytes, true)?;
    }
    let uri = transport::build_upstream_uri(&session.upstream, &parts.uri)?;
    let outbound = transport::build_upstream_request(
        &parts.method,
        uri,
        bytes,
        &parts.headers,
        session.state.config().http_gateway.preserve_host,
    )?;
    let mut closing = session.close.subscribe();
    let limit = session
        .state
        .config()
        .http_gateway
        .interaction
        .max_total_bytes;
    let response = tokio::select! {
        response = async {
            let response = session.state.client().request(outbound).await.context("Engine.IO polling failed")?;
            let (parts, body) = response.into_parts();
            let bytes = Limited::new(body, limit).collect().await.map_err(anyhow::Error::from_boxed)?.to_bytes();
            Ok::<_, anyhow::Error>((parts, bytes))
        } => response?,
        _ = closing.changed() => anyhow::bail!("recording session closed"),
    };
    let (mut response_parts, body) = response;
    ensure!(
        response_parts.status == StatusCode::OK,
        "Engine.IO polling returned a non-success response"
    );
    if parts.method == hyper::Method::GET {
        observe(&session, &body, false)?;
    }
    if initial {
        *session
            .response
            .lock()
            .expect("interaction response poisoned") = Some((
            response_parts.status.as_u16(),
            response_parts.headers.clone(),
        ));
    }
    response_parts.headers.insert(
        "x-traffic-e2e-case-id",
        session.case.id.to_string().parse()?,
    );
    if let Some(sid) = session
        .sid
        .lock()
        .expect("interaction SID poisoned")
        .as_deref()
    {
        response_parts
            .headers
            .insert("x-traffic-e2e-session-id", sid.parse()?);
    }
    Ok(Response::from_parts(
        response_parts,
        Full::new(body)
            .map_err(|never| match never {})
            .boxed_unsync(),
    ))
}

fn observe(session: &SessionRef, bytes: &[u8], input: bool) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("Engine.IO polling body is not UTF-8")?;
    let limit = session
        .state
        .config()
        .http_gateway
        .interaction
        .max_message_bytes;
    for packet in text.split('\u{1e}') {
        let decoded = decode_engine_io_text(packet, limit)?;
        if let EngineIoPacket::Open(open) = &decoded {
            ensure!(!input, "client sent an Engine.IO OPEN");
            *session.sid.lock().expect("interaction SID poisoned") = Some(open.sid.clone());
            session
                .state
                .inner
                .interactions
                .by_sid
                .lock()
                .expect("interaction sessions poisoned")
                .insert(open.sid.clone(), session.clone());
        }
        let wire = if let EngineIoPacket::Binary(bytes) = &decoded {
            WireMessage::binary(bytes)
        } else {
            WireMessage::text(packet)
        };
        if input {
            session.observe_input(wire)?;
        } else {
            session
                .observation
                .lock()
                .expect("interaction observation poisoned")
                .output(wire, session.now())?;
        }
        if matches!(decoded, EngineIoPacket::Close) {
            session
                .eio_closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            session.request_close(if input {
                EndReason::ClientClose
            } else {
                EndReason::ServerEof
            });
        }
    }
    session.changed.notify_one();
    Ok(())
}

pub(super) async fn close(session: &SessionRef) -> Result<()> {
    if session.eio_closed.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    let sid = session
        .sid
        .lock()
        .expect("interaction SID poisoned")
        .clone();
    let Some(sid) = sid else {
        return Ok(());
    };
    let query = {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer
            .append_pair("EIO", "4")
            .append_pair("transport", "polling")
            .append_pair("sid", &sid);
        serializer.finish()
    };
    let uri = format!("{}?{}", session.original_uri.path(), query).parse()?;
    let uri = transport::build_upstream_uri(&session.upstream, &uri)?;
    let mut request = transport::build_upstream_request(
        &hyper::Method::POST,
        uri,
        Bytes::from_static(b"1"),
        &session.request_headers,
        session.state.config().http_gateway.preserve_host,
    )?;
    request.headers_mut().remove("content-length");
    request.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/plain;charset=UTF-8"),
    );
    let response = session.state.client().request(request).await?;
    ensure!(response.status().is_success(), "Engine.IO close failed");
    Limited::new(response.into_body(), 1024)
        .collect()
        .await
        .map_err(anyhow::Error::from_boxed)?;
    Ok(())
}
