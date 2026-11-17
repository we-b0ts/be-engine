//! Runner scopes select strict native finalization over the actual control wire.
use super::*;
use crate::replay::FinalizationScope;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[tokio::test]
async fn focused_and_whole_rounds_keep_strict_checks_with_explicit_scopes() {
    for (scope, expected) in [
        (FinalizationScope::SelectedCases, "finalize_cases"),
        (FinalizationScope::WholeSession, "finalize"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let session = temp.path().join("session.json");
        fs::write(
            &session,
            serde_json::json!({"control_socket":socket}).to_string(),
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = tokio::io::BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["command"], expected);
            assert_eq!(request["fail_on_dirty"], true);
            assert_eq!(request["fail_on_incomplete"], true);
            reader
                .get_mut()
                .write_all(b"{\"ok\":true,\"complete\":true,\"dirty\":false,\"finalized\":true}\n")
                .await
                .unwrap();
        });
        let mut state = ActiveRunState::new("run".into(), 1, &case_inventory(), temp.path());
        state.replay_session = session;
        finalize_replay(&mut state, false, scope).await.unwrap();
        assert!(state.replay_finalized);
        assert!(state.errors.is_empty());
        peer.await.unwrap();
    }
}
