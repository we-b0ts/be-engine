//! Retain real peer transport ends through Source teardown and dependency drain.
use super::*;
use crate::dependency::termination::ConnectionControl;
use crate::interaction::{model::ClientTransportEnd, websocket_transport::FrameObservation};
use crate::recorder::CaseInvalidation;
use std::sync::atomic::Ordering;

pub(super) async fn observed<S>(
    session: &SessionRef,
    upstream: &mut WebSocketStream<S>,
    control: &ConnectionControl,
    observed: &FrameObservation,
    error: &anyhow::Error,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some((end, at)) = observed
        .termination()
        .filter(|_| observed.complete_boundary())
    else {
        // An EOF inside a frame is still incomplete capture. Keep the existing
        // failed-case cleanup without converting it into a valid terminal input.
        return cleanup(session, upstream, error).await;
    };
    let offset = at
        .saturating_duration_since(session.started)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    session
        .observation
        .lock()
        .expect("interaction observation poisoned")
        .client_transport_end(end, offset)?;
    session.request_close(EndReason::ClientTransportEnd);
    let completion = closing::ApplicationClose::prepare(session)
        .await?
        .context("client transport end requires supported application disconnect confirmation")?;
    match end {
        ClientTransportEnd::Eof => control.shutdown_write()?,
        ClientTransportEnd::Reset => control.reset()?,
    }
    completion.wait_after_close(session).await?;
    // Never send a synthetic Engine.IO or WS CLOSE for a TCP terminal input.
    // The exact live SID's awaited cleanup is the application completion proof;
    // keep the transport owner until its peer read also ends.
    while let Some(Ok(message)) = upstream.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
    session
        .client_disconnect_confirmed
        .store(true, Ordering::SeqCst);
    tracing::info!(case_id = %session.case.id, ?end,
        source_disconnect_confirmed = true,
        "recorded client transport end; retaining case through dependency drain");
    Ok(())
}

pub(super) async fn cleanup<S>(
    session: &SessionRef,
    upstream: &mut WebSocketStream<S>,
    error: &anyhow::Error,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Start the ordinary cleanup deadline while retaining the transport and
    // dependency ownership. This is never an observed client CLOSE input.
    session.transport_failed.store(true, Ordering::SeqCst);
    session.request_close(EndReason::TransportError);
    tracing::warn!(case_id = %session.case.id, phase = "client_read",
        error_kind = failure::kind(error), source_disconnect_confirmed = false,
        "client transport lost; beginning bounded Source disconnect cleanup");
    let completion = closing::ApplicationClose::prepare(session)
        .await?
        .context("client disconnect requires supported application close confirmation")?;
    upstream
        .close(Some(CloseFrame {
            code: CloseCode::Away,
            reason: "recording client disconnected".into(),
        }))
        .await?;
    completion.wait_after_close(session).await?;
    wait_peer_close(upstream).await;
    session.state.invalidate_active_case(
        session.case.id,
        CaseInvalidation::new(
            "interaction_client_transport_lost",
            format!(
                "client_read failed: {}; capture is incomplete; Source application disconnect confirmed",
                failure::kind(error)
            ),
        )
        .allow_drained_case_recovery(),
    );
    session
        .client_disconnect_confirmed
        .store(true, Ordering::SeqCst);
    tracing::warn!(case_id = %session.case.id, phase = "client_read",
        error_kind = failure::kind(error), source_disconnect_confirmed = true,
        "client transport lost; retaining failed case through dependency drain");
    Ok(())
}
