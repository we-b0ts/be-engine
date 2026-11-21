//! Private transport of complete response identity constraints to the policy owner.
use crate::replay::control::MAX_CONTROL_BYTES;
use crate::value_contract::identities::IdentityPair;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

pub const MAX_PAIRS: usize = 4096;

pub async fn check_response_identities(
    session_path: &Path,
    case: &str,
    pairs: &[IdentityPair],
) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    ensure!(
        pairs.len() <= MAX_PAIRS,
        "response identity constraint bound exceeded"
    );
    let session: Value = serde_json::from_slice(&tokio::fs::read(session_path).await?)?;
    let socket = session["control_socket"]
        .as_str()
        .context("replay control socket is unavailable")?;
    let mut payload = serde_json::to_vec(&serde_json::json!({
        "command": "response_identities", "case_id": case, "identity_pairs": pairs
    }))?;
    ensure!(
        payload.len() < MAX_CONTROL_BYTES,
        "response identity control payload bound exceeded"
    );
    payload.push(b'\n');
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(&payload).await?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let response: Value = serde_json::from_str(&line)?;
    ensure!(
        response["ok"] == true,
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("response identity relations differ from dependency observations")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_identity_batch_fits_private_transport_budget() {
        let pairs = (0..MAX_PAIRS)
            .map(|index| IdentityPair {
                source: serde_json::to_string(&format!("{index:0512x}")).unwrap(),
                target: serde_json::to_string(&format!("{:0512x}", index + MAX_PAIRS)).unwrap(),
            })
            .collect::<Vec<_>>();
        let payload = serde_json::to_vec(&serde_json::json!({
            "command":"response_identities", "case_id":"case", "identity_pairs":pairs,
        }))
        .unwrap();
        assert!(payload.len() < MAX_CONTROL_BYTES);
    }
}
