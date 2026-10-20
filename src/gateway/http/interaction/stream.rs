//! Incremental HTTP forwarding; body ownership lasts through case finalization.

use super::{SessionRef, body::LiveBody, transport::GatewayBody};
use crate::interaction::model::EndReason;
use anyhow::{Context, Result, ensure};
use http_body_util::BodyExt;
use hyper::Response;
use tokio::sync::mpsc;

pub(super) async fn forward(
    response: Response<hyper::body::Incoming>,
    session: SessionRef,
) -> Result<Response<GatewayBody>> {
    session
        .state
        .inner
        .active_cases
        .enable_stream_tail(session.case.id);
    let mut closing = session.close.subscribe();
    let (parts, mut body) = response.into_parts();
    let rewrite_input = crate::http::rewrite::RewriteInput {
        method: &session.method,
        uri: &session.original_uri,
        authority: session
            .request_headers
            .get("host")
            .and_then(|host| host.to_str().ok()),
        status: parts.status,
        headers: &parts.headers,
        body: &[],
    };
    let rewrites = &session.state.config().http_response_rewrite;
    ensure!(
        !rewrites.is_enabled()
            || !rewrites
                .rules
                .iter()
                .any(|rule| crate::http::rewrite::matches(rule, &rewrite_input)),
        "primary stream requires an incompatible complete-body response rewrite"
    );
    ensure!(
        parts
            .headers
            .get("content-encoding")
            .is_none_or(|encoding| encoding.as_bytes().eq_ignore_ascii_case(b"identity")),
        "primary stream requires an uncompressed response"
    );
    *session
        .response
        .lock()
        .expect("interaction response poisoned") =
        Some((parts.status.as_u16(), parts.headers.clone()));
    let protocol = session
        .observation
        .lock()
        .expect("interaction observation poisoned")
        .protocol();
    if super::response_protocol(&parts.headers) != Some(protocol) {
        session.state.invalidate_active_case(
            session.case.id,
            crate::recorder::CaseInvalidation::new(
                "primary_stream_content_type_unsupported",
                "primary stream response content type is missing, unsupported, or differs from the declared protocol",
            ),
        );
        anyhow::bail!("unsupported response content type for declared primary stream");
    }
    let (sender, receiver) = mpsc::channel(8);
    let lifetime = super::transport_lifetime::TransportLifetime::new(session.clone());
    let owner = session.clone();
    let task = tokio::spawn(async move {
        let _lifetime = lifetime;
        let result = async {
            loop {
                let frame = tokio::select! {
                    biased;
                    frame = body.frame() => frame,
                    _ = closing.changed() => break,
                    _ = sender.closed() => { client_cancelled(&session)?; break; },
                };
                let Some(frame) = frame else {
                    session.observation.lock().expect("interaction observation poisoned").stream_eof(session.now())?;
                    session.request_close(EndReason::ServerEof);
                    break;
                };
                let frame = frame.context("stream response body failed")?;
                if let Some(bytes) = frame.data_ref() {
                    session.observation.lock().expect("interaction observation poisoned").stream_bytes(bytes, session.now())?;
                    session.changed.notify_one();
                }
                tokio::select! {
                    result = sender.send(Ok(frame)) => if result.is_err() { client_cancelled(&session)?; break; },
                    _ = closing.changed() => break,
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        if let Err(error) = result {
            session.request_close(EndReason::ProtocolError);
            let _ = sender.try_send(Err(error));
        }
        drop(body);
        drop(sender);
    });
    owner
        .transports
        .lock()
        .expect("interaction transports poisoned")
        .push(task.abort_handle());
    Ok(Response::from_parts(
        parts,
        LiveBody(receiver).boxed_unsync(),
    ))
}

fn client_cancelled(session: &SessionRef) -> Result<()> {
    session
        .observation
        .lock()
        .expect("interaction observation poisoned")
        .client_close(None, String::new(), session.now())?;
    session.request_close(EndReason::ClientClose);
    Ok(())
}
