//! Private response constraints join the dependency bijection before ending a case.
use super::*;
use crate::value_contract::identities::IdentityPair;

const MAX_PAIRS: usize = 4096;
// Includes both 256-byte tokens and domain/envelope overhead for 4096 entities.
pub(super) const MAX_CONTROL_BYTES: usize = 4 * 1024 * 1024;

pub(crate) async fn check_response_identities(
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

pub(super) async fn accept(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<ReplayState>>,
) -> Value {
    let outcome = async {
        ensure!(
            request.identity_pairs.len() <= MAX_PAIRS,
            "response identity constraint bound exceeded"
        );
        let state = state.lock().await;
        let case = request
            .case_id
            .as_deref()
            .context("response identities require case_id")?;
        ensure!(
            state.active_case_id.as_deref() == Some(case),
            "response identities require the active case"
        );
        let owner = &state
            .replay_policy
            .as_ref()
            .context("response identities require a policy")?
            .request_contracts;
        let formats = owner
            .compiled_rules()
            .into_iter()
            .flat_map(|policy| &policy.rules)
            .flat_map(|rule| rule.rule.contract.values())
            .filter_map(|contract| match contract.unconditional() {
                crate::policy::FieldContract::Identity {
                    binding, format, ..
                } => Some((binding.as_str(), *format)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        for pair in &request.identity_pairs {
            let format = *formats
                .get(pair.domain.as_str())
                .context("undeclared response identity domain")?;
            for token in [&pair.source, &pair.target] {
                ensure!(
                    crate::value_contract::json::identity_token(
                        &Value::String(token.clone()),
                        "",
                        format,
                        ""
                    )
                    .is_ok(),
                    "response identity representation is invalid"
                );
            }
        }
        let decision = owner.preview_identity_pairs(case, &request.identity_pairs)?;
        owner.commit_identity(decision)
    }
    .await;
    match outcome {
        Ok(()) => serde_json::json!({"ok": true}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_domain_batch_fits_private_transport_budget() {
        let pairs = (0..MAX_PAIRS)
            .map(|index| IdentityPair {
                domain: "d".repeat(64),
                source: format!("{index:0256x}"),
                target: format!("{:0256x}", index + MAX_PAIRS),
            })
            .collect::<Vec<_>>();
        let payload = serde_json::to_vec(&serde_json::json!({
            "command":"response_identities", "case_id":"case", "identity_pairs":pairs,
        }))
        .unwrap();
        assert!(payload.len() < MAX_CONTROL_BYTES);
    }
}
