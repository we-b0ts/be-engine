//! Consume a sealed commit at its Source sequence using an autocommit write receipt.
use super::*;
use traffic_model::recording::ProtocolRef;

struct CommitFramer;
impl ResponseFramer for CommitFramer {}

impl<P: ReplayProtocolSet> Host<P> {
    pub(super) async fn cover_autocommit_commit(
        &self,
        request: Arc<dyn ProtocolMessage>,
        after: ProtocolRef,
    ) -> Result<()> {
        ensure!(
            self.event_session,
            "autocommit completion requires a sealed Source Session"
        );
        let session = RequestSession {
            after: Some(after),
            autocommit_completion: true,
            ..Default::default()
        };
        let delivery = self
            .execute_request(
                request,
                None,
                Some(session),
                request::RequestAdmission::AutocommitCompletion,
            )
            .await?
            .context("autocommit write has no sealed commit to cover")?;
        ensure!(
            matches!(
                delivery.session_step(),
                Some(ReplaySessionStep::AutocommitCommit { .. })
            ),
            "autocommit completion selected a different Source operation"
        );
        // The UPDATE was already flushed to this connection. Only the sealed
        // COMMIT's delivery boundaries and coverage are pending.
        delivery
            .write(&mut tokio::io::sink(), &mut CommitFramer)
            .await
    }
}
