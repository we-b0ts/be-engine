//! Recorder-protected INPUT must use the same authenticated reader as execution.
use super::*;

fn recording(project: &Path) -> (std::path::PathBuf, Vec<Value>, Vec<u8>, Vec<u8>) {
    let root = project.join(".traffic-e2e/local/artifacts/recordings/run");
    let (globals, original) = fixture(&root);
    crate::platform::encryption_key::load_or_create(project).unwrap();
    let path = root.join("case/request.json");
    let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    request["uri"] = "/socket.io/?EIO=4&transport=websocket&token=synthetic-query-secret".into();
    request["headers"] = json!({"authorization":["Bearer synthetic-header-secret"]});
    request["interaction"]["actions"][0]["action"]["message"]["data"] =
        "40/chat,{\"token\":\"synthetic-connect-secret\"}".into();
    crate::interaction::private::protect_request(&mut request, &path).unwrap();
    let protected = serde_json::to_vec(&request).unwrap();
    assert!(!String::from_utf8_lossy(&protected).contains("synthetic-"));
    assert!(
        request["interaction"]["actions"][0]["action"]["message"]["data"]
            .as_str()
            .unwrap()
            .starts_with("traffic-e2e:enc:")
    );
    std::fs::write(&path, &protected).unwrap();
    (root, globals, original, protected)
}

#[tokio::test]
async fn protected_native_connect_uses_managed_input_without_rewriting_evidence() {
    for lazy in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let (root, globals, original, protected) = recording(project.path());
        let output_path = root.join("case/expected-response.json");
        let expected_before = std::fs::read(&output_path).unwrap();
        let runtime = runtime(&root, &[], &globals, lazy).await.unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        let epoch = guards::begin(&runtime).await;
        assert_eq!(
            guards::connected(&runtime, epoch, "/chat").await["ok"],
            true
        );
        assert_eq!(read(&mut subscriber).await, original);
        guards::silent(&mut subscriber).await;
        assert_eq!(
            runtime
                .state
                .lock()
                .await
                .redis
                .pubsub
                .report()
                .unwrap()
                .delivered_pushes,
            1
        );
        assert_eq!(
            std::fs::read(root.join("case/request.json")).unwrap(),
            protected
        );
        assert_eq!(std::fs::read(output_path).unwrap(), expected_before);
        task.abort();
    }
}

#[tokio::test]
async fn tampered_private_native_input_fails_preparation_instead_of_hiding_namespace() {
    let project = tempfile::tempdir().unwrap();
    let (root, globals, _, protected) = recording(project.path());
    let mut request: Value = serde_json::from_slice(&protected).unwrap();
    let value = &mut request["interaction"]["actions"][0]["action"]["message"]["data"];
    let ciphertext = value.as_str().unwrap();
    let (prefix, body) = ciphertext.rsplit_once(':').unwrap();
    let mut altered = body.as_bytes().to_vec();
    altered[0] = if altered[0] == b'A' { b'B' } else { b'A' };
    *value = format!("{prefix}:{}", String::from_utf8(altered).unwrap()).into();
    std::fs::write(root.join("case/request.json"), request.to_string()).unwrap();
    let error = runtime(&root, &[], &globals, true)
        .await
        .err()
        .expect("tampered INPUT must fail closed");
    assert!(format!("{error:#}").contains("native notification INPUT"));
    assert!(!format!("{error:#}").contains("synthetic-connect-secret"));
}

#[tokio::test]
async fn missing_managed_key_fails_native_input_preparation_without_fallback() {
    // A supplied environment key is an explicitly supported alternative; never
    // mutate process-wide environment while other encryption tests are running.
    if std::env::var_os(crate::request_headers::ENCRYPTION_KEY_ENV).is_some() {
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let (root, globals, _, _) = recording(project.path());
    std::fs::remove_file(
        project
            .path()
            .join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH),
    )
    .unwrap();
    let error = runtime(&root, &[], &globals, true)
        .await
        .err()
        .expect("missing key must fail closed");
    assert!(format!("{error:#}").contains("native notification INPUT"));
}
