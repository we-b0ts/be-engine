//! Bounded private timing queries; waiting never occupies the control server.
use super::*;
use crate::interaction::replay::timing::InputTiming;
use futures_util::future::BoxFuture;

struct Observer {
    socket: PathBuf,
    case: String,
    epoch: DateTime<Utc>,
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
    }))
}

impl InputTiming for Observer {
    fn wait(&self, sequence: u64, completed: Vec<u64>) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(async move {
            loop {
                let response = super::super::native_event::send(&self.socket,
                    serde_json::json!({"command":"input_timing","case_id":self.case,
                        "input_timing":Query {epoch:self.epoch,sequence,completed:completed.clone(),closed_at:None}})).await?;
                if response["ready"] == true {
                    return Ok(serde_json::from_value(response["advance"].clone())?);
                }
                let wait = response["wait_ms"]
                    .as_u64()
                    .context("input timing wait missing")?;
                tokio::time::sleep(Duration::from_millis(wait.max(1))).await;
            }
        })
    }
}
