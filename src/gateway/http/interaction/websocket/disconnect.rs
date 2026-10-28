//! Archive lost-client captures only after proving Source application teardown.
use super::*;
use crate::recorder::CaseInvalidation;
use std::sync::atomic::Ordering;

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
