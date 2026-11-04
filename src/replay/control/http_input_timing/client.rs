//! Private driver feedback reports an actual primary transport cancellation.
use super::*;
use crate::interaction::replay::timing::Advance;

struct Observer {
    socket: PathBuf,
    case: String,
    epoch: DateTime<Utc>,
}

pub(crate) async fn connect(session: &Path, case: &str) -> Result<Option<Arc<dyn InputTiming>>> {
    let session: Value = serde_json::from_slice(&tokio::fs::read(session).await?)?;
    let socket = PathBuf::from(
        session["control_socket"]
            .as_str()
            .context("HTTP timing control socket absent")?,
    );
    let response = super::super::native_event::send(
        &socket,
        serde_json::json!({"command":"http_input_timing_begin","case_id":case}),
    )
    .await?;
    if response["enabled"] != true {
        return Ok(None);
    }
    Ok(Some(Arc::new(Observer {
        socket,
        case: case.into(),
        epoch: serde_json::from_value(response["epoch"].clone())?,
    })))
}

impl InputTiming for Observer {
    fn wait(&self, sequence: u64, completed: Vec<u64>) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(async move {
            loop {
                let response = super::super::native_event::send(&self.socket, serde_json::json!({
                    "command":"http_input_timing_wait","case_id":self.case,
                    "input_timing":{"epoch":self.epoch,"sequence":sequence,"completed":completed}
                })).await?;
                if response["ready"] == true {
                    return Ok(Advance::default());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    }

    fn closed(&self, started_at: DateTime<Utc>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            super::super::native_event::send(
                &self.socket,
                serde_json::json!({
                    "command":"http_input_timing_closed","case_id":self.case,
                    "input_timing":{"epoch":self.epoch,"sequence":1,"completed":[],"closed_at":started_at}
                }),
            )
            .await?;
            Ok(())
        })
    }
}
