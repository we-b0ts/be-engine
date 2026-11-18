//! Private metadata-only feedback from the trusted live Socket.IO driver.
use super::*;
use crate::interaction::replay::{NativeEvent, NativeEventSink};
use futures_util::future::BoxFuture;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub epoch: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<NativeEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<u64>,
}

struct Observer {
    socket: PathBuf,
    case: String,
    epoch: DateTime<Utc>,
    events: bool,
    input_acks: bool,
}

pub async fn connect(session: &Path, case: &str) -> Result<Option<Arc<dyn NativeEventSink>>> {
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
        events: response["events"].as_bool().unwrap_or(true),
        input_acks: response["input_acks"].as_bool().unwrap_or(true),
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
            if !self.events {
                return Ok(());
            }
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
            if !self.input_acks {
                return Ok(());
            }
            send(&self.socket, serde_json::json!({"command":"native_input_ack","case_id":self.case,
                "native_event":Observation {epoch:self.epoch,event:None,namespace:None,sid:None,acknowledged:Some(sequence)}})).await?;
            Ok(())
        })
    }
}

pub async fn send(socket: &Path, request: Value) -> Result<Value> {
    send_with_response_limit(socket, request, 8192).await
}

pub async fn send_with_response_limit(
    socket: &Path,
    request: Value,
    response_limit: usize,
) -> Result<Value> {
    let command = feedback_command(&request);
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
            .take((response_limit + 1) as u64)
            .read_line(&mut line)
            .await?;
        ensure!(
            line.len() <= response_limit,
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
    .with_context(|| format!("replay control feedback timed out ({command})"))?
}

fn feedback_command(request: &Value) -> &str {
    request["command"]
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
                    | "input_timing_native_prefix"
                    | "http_input_timing_begin"
                    | "http_input_timing_wait"
                    | "http_input_timing_closed"
            )
        })
        .unwrap_or("unknown_command")
}

fn feedback_rejection(request: &Value, response: &Value) -> Value {
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
    serde_json::json!({"command":feedback_command(request),"reason":reason})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn namespace_only_observer_does_not_send_unneeded_feedback() {
        let directory = tempfile::tempdir().unwrap();
        let observer = Observer {
            socket: directory.path().join("unused.sock"),
            case: "case".into(),
            epoch: Utc::now(),
            events: false,
            input_acks: false,
        };
        observer
            .observe(NativeEvent {
                namespace: "/rpc".into(),
                event: "ready".into(),
                ordinal: 1,
            })
            .await
            .unwrap();
        observer.acknowledged(2).await.unwrap();
        assert!(observer.connected("/rpc", Some("sid")).await.is_err());
    }

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
