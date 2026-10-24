//! Private response constraints join the dependency bijection before ending a case.
use super::*;
use crate::value_contract::identities::IdentityPair;

const MAX_PAIRS: usize = 4096;
// Bounded complete typed scalars and envelope overhead for 4096 entities.
pub(super) const MAX_CONTROL_BYTES: usize = 16 * 1024 * 1024;

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
        let compiled = owner.compiled_rules();
        let formats = compiled
            .into_iter()
            .flat_map(|policy| &policy.rules)
            .flat_map(|rule| rule.rule.contract.values())
            .filter_map(|contract| match contract.unconditional() {
                crate::policy::FieldContract::Identity { prefix, format } => {
                    Some((prefix.as_str(), *format))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let global_fields = compiled
            .into_iter()
            .flat_map(|policy| {
                policy
                    .global_json
                    .iter()
                    .flat_map(|json| json.fields.values())
                    .chain(
                        policy
                            .mysql
                            .iter()
                            .flat_map(|mysql| mysql.tables.values())
                            .flat_map(|table| table.fields.values()),
                    )
                    .chain(policy.redis.iter().flat_map(|redis| redis.keys.values()))
                    .chain(policy.http.iter().flat_map(|http| http.headers.values()))
            })
            .filter(|field| field.is_identity())
            .collect::<Vec<_>>();
        let template_tokens = compiled
            .into_iter()
            .flat_map(|policy| &policy.native)
            .flat_map(|rule| match &rule.rule.effect {
                crate::policy::NativeEffect::ResponseGenerated(effect) => effect
                    .fields
                    .values()
                    .filter_map(|field| match &field.contract {
                        crate::policy::native::GeneratedResponse::Template { fields, .. } => Some(
                            fields
                                .values()
                                .map(|field| &field.contract)
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    })
                    .flatten()
                    .collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect::<Vec<_>>();
        for pair in &request.identity_pairs {
            let source: Value = serde_json::from_str(&pair.source)?;
            let target: Value = serde_json::from_str(&pair.target)?;
            ensure!(
                (!global_fields.is_empty()
                    && source == target
                    && crate::value_contract::json::identity_key(&source, "").is_ok())
                    || formats.iter().any(|(prefix, format)| {
                        [&source, &target].into_iter().all(|value| {
                            crate::value_contract::json::identity_token(value, prefix, *format, "")
                                .is_ok()
                        })
                    })
                    || global_fields.iter().any(|field| {
                        match field.select_contract(&source) {
                            Ok(crate::policy::FieldContract::Identity { prefix, format }) => {
                                crate::value_contract::json::identity_token(
                                    &target, &prefix, format, "",
                                )
                                .is_ok()
                            }
                            _ => false,
                        }
                    })
                    || template_tokens.iter().any(|token| {
                        source
                            .as_str()
                            .zip(target.as_str())
                            .is_some_and(|(source, target)| {
                                (token.length.is_some() || source.len() == target.len())
                                    && crate::value_contract::generated::template::valid_token(
                                        source, token,
                                    )
                                    && crate::value_contract::generated::template::valid_token(
                                        target, token,
                                    )
                            })
                    }),
                "response identity representation has no declared format"
            );
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
