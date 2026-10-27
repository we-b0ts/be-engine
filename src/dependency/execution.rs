//! Protocol-independent interruption of a request after Replay rejects a dependency.
#[derive(Debug)]
pub(crate) struct UnmatchedDependency {
    pub(crate) observed_status: Option<u16>,
}
impl std::fmt::Display for UnmatchedDependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "request execution incomplete: dependency did not match the recorded contract"
        )
    }
}
impl std::error::Error for UnmatchedDependency {}

pub(crate) async fn rejected(receiver: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    let Some(receiver) = receiver else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if *receiver.borrow() {
            return;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
            return;
        }
    }
}
