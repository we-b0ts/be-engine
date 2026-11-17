//! Bounded private timing queries; waiting never occupies the control server.
use super::*;
use crate::interaction::model::DispatchDependency;
use crate::interaction::replay::timing::{FastTail, InputTiming};
use futures_util::future::BoxFuture;
use tokio::sync::watch;

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
    let response = super::super::native_event::send(
        &socket,
        serde_json::json!({"command":"input_timing_begin","case_id":case,"socketio_timing":mode}),
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

    fn native_prefix_active(&self) -> BoxFuture<'_, Result<bool>> {
        Box::pin(async {
            let query = Query {
                epoch: self.epoch,
                sequence: 0,
                completed: Vec::new(),
                closed_at: None,
                events_ready: None,
            };
            let response = super::super::native_event::send(
                &self.socket,
                serde_json::json!({"command":"input_timing_native_prefix","case_id":self.case,"input_timing":query}),
            )
            .await?;
            Ok(response["active"] == true)
        })
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
                let waiting_for_request = missing.is_some();
                unadmitted.send_if_modified(|previous| {
                    if *previous == missing {
                        return false;
                    }
                    *previous = missing;
                    true
                });
                if query.events_ready == Some(false) && !waiting_for_request {
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
