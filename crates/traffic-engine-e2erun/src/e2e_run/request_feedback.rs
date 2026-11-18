//! Live dependency rejection interrupts only its failed primary request through its ordinary case lifecycle.
use std::path::Path;
use std::time::Duration;
use tokio::sync::watch;

pub(super) struct Monitor {
    receiver: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}
impl Monitor {
    pub(super) fn start(session: &Path, case: &str) -> Self {
        let (sender, receiver) = watch::channel(false);
        let config = crate::replay::ReplayControlConfig {
            session_path: session.into(),
            command: "case_execution_status".into(),
            case_id: Some(case.into()),
            fail_on_dirty: false,
            fail_on_incomplete: false,
            wait_timeout: None,
        };
        let task = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    crate::replay::run_replay_control(config.clone()),
                )
                .await
                {
                    Ok(Ok(reply)) if reply["failed"] == true => {
                        let _ = sender.send(true);
                        return;
                    }
                    _ => {}
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        Self { receiver, task }
    }
    pub(super) fn receiver(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
