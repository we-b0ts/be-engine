//! Opt-in real-recording regression using a genuine immutable production image.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

#[tokio::test]
#[ignore = "requires local recording, startup credentials, Docker and a pinned real Target image"]
async fn recorded_http_close_on_pinned_target() {
    let required = |name: &str| std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}"));
    let context = crate::E2eRunContext {
        target_root: required("TRAFFIC_E2E_TEST_TARGET_ROOT").into(),
        case_source: required("TRAFFIC_E2E_TEST_CASE_SOURCE").into(),
        run_key: Some(required("TRAFFIC_E2E_TEST_RUN_KEY").into_string().unwrap()),
    };
    let result_path = PathBuf::from(required("TRAFFIC_E2E_TEST_RESULT_PATH"));
    let api = required("TRAFFIC_E2E_TEST_API").into_string().unwrap();
    required("TRAFFIC_E2E_TEST_ENGINE_BINARY");
    required("TRAFFIC_E2E_TEST_TARGET_IMAGE");
    let result = run_e2e_api(context, &api).await.unwrap();
    let artifact = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(result_path)
        .unwrap();
    serde_json::to_writer_pretty(artifact, &result).unwrap();
    assert!(
        result.passed,
        "recorded pinned-image Replay failed; inspect the private result artifact"
    );
}
