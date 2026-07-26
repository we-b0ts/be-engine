use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tracing::warn;

type BackgroundFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

enum BackgroundCommand {
    Spawn(BackgroundFuture),
    Shutdown(Duration, oneshot::Sender<()>),
}

#[derive(Clone)]
pub(super) struct BackgroundTasks {
    sender: mpsc::UnboundedSender<BackgroundCommand>,
}

impl BackgroundTasks {
    pub(super) fn new() -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    Some(command) = receiver.recv() => match command {
                        BackgroundCommand::Spawn(task) => {
                            tasks.spawn(task);
                        }
                        BackgroundCommand::Shutdown(timeout, done) => {
                            drain_join_set(&mut tasks, timeout).await;
                            let _ = done.send(());
                            return;
                        }
                    },
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                        if let Err(error) = result {
                            warn!(%error, "comparison recording background task failed");
                        }
                    }
                    else => return,
                }
            }
        });
        Self { sender }
    }

    pub(super) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        if self
            .sender
            .send(BackgroundCommand::Spawn(Box::pin(task)))
            .is_err()
        {
            warn!("comparison recording background task rejected because tracker stopped");
        }
    }

    pub(super) async fn drain(&self, timeout: Duration) {
        let (done, completed) = oneshot::channel();
        if self
            .sender
            .send(BackgroundCommand::Shutdown(timeout, done))
            .is_ok()
        {
            let _ = completed.await;
        }
    }
}

async fn drain_join_set(tasks: &mut JoinSet<()>, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(error))) => warn!(%error, "comparison recording background task failed"),
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                warn!(
                    "timed out draining comparison recording background tasks; remaining tasks aborted"
                );
            }
        }
    }
}
