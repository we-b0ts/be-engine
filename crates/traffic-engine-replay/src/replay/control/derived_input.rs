//! Private pre-send admission of independently reconstructed input deliveries.
use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub request_sent_at: chrono::DateTime<chrono::Utc>,
    pub request: Value,
}
impl std::fmt::Debug for Registration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DerivedInputRegistration")
            .field("request_sent_at", &self.request_sent_at)
            .finish_non_exhaustive()
    }
}

pub async fn register(
    session_path: &Path,
    case: &str,
    sent_at: chrono::DateTime<chrono::Utc>,
    request: &Value,
) -> Result<()> {
    let session: Value = serde_json::from_slice(&tokio::fs::read(session_path).await?)?;
    let socket = session["control_socket"]
        .as_str()
        .context("replay control socket unavailable")?;
    let mut payload = serde_json::to_vec(
        &serde_json::json!({"command":"derived_input","case_id":case,"derived_input":{"request_sent_at":sent_at,"request":request}}),
    )?;
    ensure!(
        payload.len() < MAX_CONTROL_BYTES,
        "derived input exceeds private control bound"
    );
    payload.push(b'\n');
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(&payload).await?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await?;
    let response: Value = serde_json::from_str(&line)?;
    ensure!(
        response["ok"] == true,
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("derived input admission failed")
    );
    Ok(())
}
