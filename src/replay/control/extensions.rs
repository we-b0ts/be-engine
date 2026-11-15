//! Active-case control extensions retain application-owned parameter semantics.
use super::*;

pub(super) async fn accept<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<RuntimeState<P>>>,
) -> Value {
    let state = state.lock().await;
    let case = request
        .case_id
        .as_deref()
        .filter(|case| state.active_case_id.as_deref() == Some(*case));
    let outcome = match &state.replay_policy {
        Some(policy) => policy
            .contracts()
            .control(case, &request.command, &request.parameters),
        None => state
            .native
            .contracts
            .control(case, &request.command, &request.parameters),
    };
    match outcome {
        Ok(Some(response)) => response,
        Ok(None) => serde_json::json!({"ok":false,
            "error":format!("unknown replay control command {}",request.command)}),
        Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extension_parameters_reject_duplicate_fields_at_every_depth() {
        for input in [
            r#"{"command":"extension","value":1,"value":2}"#,
            r#"{"command":"extension","value":{"nested":1,"nested":2}}"#,
            r#"{"command":"response_identities","identity_pairs":[{"source":"1","source":"2","target":"3"}]}"#,
        ] {
            assert!(serde_json::from_str::<ReplayControlRequest>(input).is_err());
        }
        let input = r#"{"command":"extension","value":{"nested":1}}"#;
        let request: ReplayControlRequest = serde_json::from_str(input).unwrap();
        assert!(request.parameters.contains_key("value"));
    }
}
