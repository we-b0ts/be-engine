//! Bounded private timing queries; waiting never occupies the control server.
use super::*;
use crate::interaction::model::DispatchDependency;
use crate::interaction::replay::timing::{FastTail, InputTiming};
use futures_util::future::BoxFuture;
use tokio::sync::watch;

// The begin response carries exact Source receipt and pending identities. Size
// for the standard 100,000-message transcript, without enlarging live queries.
const BEGIN_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

struct Observer {
    socket: PathBuf,
    case: String,
    epoch: DateTime<Utc>,
    ordered_fast: bool,
    fast_tail: Option<FastTail>,
}

pub(crate) async fn connect(
    session: &Path,
    case: &str,
    mode: SocketIoTiming,
) -> Result<Arc<dyn InputTiming>> {
    let session: Value = serde_json::from_slice(&tokio::fs::read(session).await?)?;
    let socket = PathBuf::from(
        session["control_socket"]
            .as_str()
            .context("replay control socket unavailable")?,
    );
    let response = super::super::native_event::send_with_response_limit(
        &socket,
        serde_json::json!({"command":"input_timing_begin","case_id":case,"socketio_timing":mode}),
        BEGIN_RESPONSE_LIMIT,
    )
    .await?;
    Ok(Arc::new(Observer {
        socket,
        case: case.into(),
        epoch: serde_json::from_value(response["epoch"].clone())?,
        ordered_fast: response["ordered_fast"] == true,
        fast_tail: serde_json::from_value(response["fast_tail"].clone())?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn begin_reads_the_full_heartbeat_pending_identity_set() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let session = directory.path().join("session.json");
        std::fs::write(
            &session,
            serde_json::json!({"control_socket":socket}).to_string(),
        )
        .unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            stream.read_line(&mut request).await.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&request).unwrap()["command"],
                "input_timing_begin"
            );
            let tail = FastTail {
                close_sequence: None,
                output_count: 5,
                idle_ms: 3,
                heartbeat_acks: Some([2, 3].into()),
                heartbeat_pending_without_ack: (4..2659).collect(),
                native_observation: false,
            };
            let reply = serde_json::json!({"ok":true,"epoch":Utc::now(),"ordered_fast":true,"fast_tail":tail});
            let line = format!("{reply}\n");
            assert!(line.len() > 8192);
            stream.get_mut().write_all(line.as_bytes()).await.unwrap();
        });
        let observer = connect(&session, "case", SocketIoTiming::Auto)
            .await
            .unwrap();
        assert_eq!(
            observer
                .fast_tail()
                .unwrap()
                .heartbeat_pending_without_ack
                .len(),
            2655
        );
        server.await.unwrap();
    }
}

impl InputTiming for Observer {
    fn wait(&self, sequence: u64, completed: Vec<u64>) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(self.wait_for("input_timing", sequence, completed, None))
    }

    fn wait_dispatch(
        &self,
        sequence: u64,
        completed: Vec<u64>,
        events_ready: watch::Receiver<bool>,
        unadmitted: watch::Sender<Option<DispatchDependency>>,
    ) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(self.wait_for(
            "input_timing",
            sequence,
            completed,
            Some((events_ready, unadmitted)),
        ))
    }

    fn ordered_fast(&self) -> bool {
        self.ordered_fast
    }

    fn fast_tail(&self) -> Option<FastTail> {
        self.fast_tail.clone()
    }

    fn wait_fast_tail(&self) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(self.wait_for("input_timing_tail", 0, Vec::new(), None))
    }
}

type DispatchFeedback = (
    watch::Receiver<bool>,
    watch::Sender<Option<DispatchDependency>>,
);

impl Observer {
    async fn wait_for(
        &self,
        command: &str,
        sequence: u64,
        completed: Vec<u64>,
        mut dispatch: Option<DispatchFeedback>,
    ) -> Result<Advance> {
        let mut query = Query {
            epoch: self.epoch,
            sequence,
            completed,
            closed_at: None,
            events_ready: None,
        };
        loop {
            query.events_ready = dispatch
                .as_mut()
                .map(|(events, _)| *events.borrow_and_update());
            let response = super::super::native_event::send(
                &self.socket,
                serde_json::json!({"command":command,"case_id":self.case,"input_timing":query}),
            )
            .await?;
            if let Some((events, unadmitted)) = &mut dispatch {
                let missing: Option<DispatchDependency> =
                    serde_json::from_value(response["unadmitted_request"].clone())?;
                unadmitted.send_if_modified(|previous| {
                    if *previous == missing {
                        return false;
                    }
                    *previous = missing;
                    true
                });
                if query.events_ready == Some(false) && missing.is_none() {
                    events.wait_for(|ready| *ready).await?;
                    continue;
                }
            }
            if response["ready"] == true {
                return Ok(serde_json::from_value(response["advance"].clone())?);
            }
            let wait = response["wait_ms"]
                .as_u64()
                .context("input timing wait missing")?;
            tokio::time::sleep(Duration::from_millis(wait.max(1))).await;
        }
    }
}
