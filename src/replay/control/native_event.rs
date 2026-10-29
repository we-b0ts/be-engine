//! Private metadata-only feedback from the trusted live Socket.IO driver.
use super::*;
use crate::interaction::replay::{NativeEvent, NativeEventSink};
use futures_util::future::BoxFuture;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct Observation {
    epoch: DateTime<Utc>,
    event: NativeEvent,
}

struct Observer {
    socket: PathBuf,
    case: String,
    epoch: DateTime<Utc>,
}

pub(crate) async fn connect(
    session: &Path,
    case: &str,
) -> Result<Option<Arc<dyn NativeEventSink>>> {
    let session: Value = serde_json::from_slice(&tokio::fs::read(session).await?)?;
    let socket = PathBuf::from(
        session["control_socket"]
            .as_str()
            .context("replay control socket unavailable")?,
    );
    let response = send(
        &socket,
        serde_json::json!({"command":"native_event_begin", "case_id":case}),
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

impl NativeEventSink for Observer {
    fn observe(&self, event: NativeEvent) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            send(
                &self.socket,
                serde_json::json!({"command":"native_event", "case_id":self.case,
                "native_event":Observation {epoch:self.epoch,event}}),
            )
            .await?;
            Ok(())
        })
    }
}

async fn send(socket: &Path, request: Value) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut payload = serde_json::to_vec(&request)?;
        ensure!(
            payload.len() <= 8192,
            "native event control metadata exceeds bound"
        );
        payload.push(b'\n');
        let mut stream = UnixStream::connect(socket).await?;
        stream.write_all(&payload).await?;
        let mut line = String::new();
        use tokio::io::AsyncReadExt;
        BufReader::new(stream)
            .take(8193)
            .read_line(&mut line)
            .await?;
        ensure!(
            line.len() <= 8192,
            "native event control response exceeds bound"
        );
        let response: Value = serde_json::from_str(&line)?;
        ensure!(
            response["ok"] == true,
            "native event feedback admission failed"
        );
        Ok(response)
    })
    .await
    .context("native event control feedback timed out")?
}

pub(super) async fn accept(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<ReplayState>>,
) -> Value {
    let result = async {
        let mut state = state.lock().await;
        let case = request
            .case_id
            .as_deref()
            .context("native event feedback requires case_id")?;
        ensure!(
            state.active_case_id.as_deref() == Some(case)
                && state.finalized_at.is_none()
                && !state.target_session_stopped,
            "native event feedback requires the active live case"
        );
        if request.command == "native_event_begin" && !state.redis.needs_native_events(case) {
            return Ok(serde_json::json!({"ok":true,"enabled":false}));
        }
        let epoch = state
            .redis
            .request_contracts
            .request_times(case)
            .target
            .context("native event feedback requires request admission")?;
        if request.command == "native_event_begin" {
            let enabled = state.redis.native_events_begin(case, epoch);
            return Ok(serde_json::json!({"ok":true,"enabled":enabled,"epoch":epoch}));
        }
        let observation = request
            .native_event
            .as_ref()
            .context("native event metadata missing")?;
        ensure!(
            observation.epoch == epoch,
            "native event request epoch changed"
        );
        state
            .redis
            .observe_native_event(case, epoch, &observation.event)?;
        Ok::<_, anyhow::Error>(serde_json::json!({"ok":true}))
    }
    .await;
    result.unwrap_or_else(|error| serde_json::json!({"ok":false,"error":error.to_string()}))
}
