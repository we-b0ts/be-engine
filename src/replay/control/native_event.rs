//! Private metadata-only feedback from the trusted live Socket.IO driver.
use super::*;
use crate::interaction::replay::{NativeEvent, NativeEventSink};
use futures_util::future::BoxFuture;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct Observation {
    epoch: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event: Option<NativeEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acknowledged: Option<u64>,
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
    fn connected<'a>(
        &'a self,
        namespace: &'a str,
        sid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            send(&self.socket, serde_json::json!({"command":"native_connected", "case_id":self.case,
                "native_event":Observation {epoch:self.epoch,event:None,namespace:Some(namespace.into()),sid:sid.map(str::to_owned),acknowledged:None}})).await?;
            Ok(())
        })
    }
    fn observe(&self, event: NativeEvent) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            send(
                &self.socket,
                serde_json::json!({"command":"native_event", "case_id":self.case,
                "native_event":Observation {epoch:self.epoch,event:Some(event),namespace:None,sid:None,acknowledged:None}}),
            )
            .await?;
            Ok(())
        })
    }
    fn acknowledged(&self, sequence: u64) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            send(&self.socket, serde_json::json!({"command":"native_input_ack","case_id":self.case,
                "native_event":Observation {epoch:self.epoch,event:None,namespace:None,sid:None,acknowledged:Some(sequence)}})).await?;
            Ok(())
        })
    }
}

pub(super) async fn send(socket: &Path, request: Value) -> Result<Value> {
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
            "replay control feedback admission failed: {}",
            feedback_rejection(&request, &response)
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
            .pubsub
            .native_clock
            .epoch(case)
            .or_else(|| state.redis.pubsub.namespace_sessions.epoch(case))
            .or_else(|| state.redis.request_contracts.request_times(case).target)
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
        if request.command == "native_input_ack" {
            ensure!(
                observation.event.is_none()
                    && observation.namespace.is_none()
                    && observation.sid.is_none(),
                "input ACK carries unrelated native metadata"
            );
            let sequence = observation
                .acknowledged
                .context("native input ACK missing")?;
            state
                .redis
                .pubsub
                .native_clock
                .input_acknowledged(case, epoch, sequence)?;
            return Ok(serde_json::json!({"ok":true}));
        }
        ensure!(
            observation.acknowledged.is_none(),
            "native event carries input ACK"
        );
        if request.command == "native_connected" {
            ensure!(
                observation.event.is_none(),
                "native namespace observation carries an event"
            );
            let namespace = observation
                .namespace
                .as_deref()
                .context("native namespace missing")?;
            state
                .redis
                .pubsub
                .native_clock
                .connected(case, epoch, namespace)?;
            state.redis.pubsub.namespace_sessions.connected(
                case,
                epoch,
                namespace,
                observation.sid.as_deref(),
            )?;
            return Ok(serde_json::json!({"ok":true}));
        }
        ensure!(
            observation.namespace.is_none() && observation.sid.is_none(),
            "native event observation carries a namespace boundary"
        );
        let event = observation
            .event
            .as_ref()
            .context("native event metadata missing")?;
        state.redis.observe_native_event(case, epoch, event)?;
        Ok::<_, anyhow::Error>(serde_json::json!({"ok":true}))
    }
    .await;
    result.unwrap_or_else(|error| {
        serde_json::json!({"ok":false,"reason":"native_event_rejected","error":error.to_string()})
    })
}

fn feedback_rejection(request: &Value, response: &Value) -> Value {
    let command = request["command"]
        .as_str()
        .filter(|command| {
            matches!(
                *command,
                "native_event_begin"
                    | "native_connected"
                    | "native_event"
                    | "native_input_ack"
                    | "input_timing_begin"
                    | "input_timing"
                    | "input_timing_tail"
            )
        })
        .unwrap_or("unknown_command");
    let reason = response["reason"]
        .as_str()
        .filter(|reason| {
            matches!(
                *reason,
                "native_event_rejected"
                    | "input_timing_rejected"
                    | "input_timing_source_unavailable"
            )
        })
        .unwrap_or("control_rejected");
    // Control errors can originate in private Source evidence. Propagate only
    // engine-owned categories, never arbitrary server details or payloads.
    serde_json::json!({"command":command,"reason":reason})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_rejection_names_the_stage_without_disclosing_server_details() {
        let request = serde_json::json!({"command":"input_timing_begin"});
        let response = serde_json::json!({"reason":"input_timing_source_unavailable","error":"private-source-token"});
        assert_eq!(
            feedback_rejection(&request, &response),
            serde_json::json!({"command":"input_timing_begin","reason":"input_timing_source_unavailable"})
        );
        let untrusted = serde_json::json!({"command":"private-command", "reason":"private-reason", "error":"private-source-token"});
        assert_eq!(
            feedback_rejection(&untrusted, &untrusted),
            serde_json::json!({"command":"unknown_command","reason":"control_rejected"})
        );
    }
}
