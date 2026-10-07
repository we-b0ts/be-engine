use super::*;

#[tokio::test(start_paused = true)]
async fn configured_post_ready_cap_allows_recording_despite_periodic_redis_activity() {
    let temp = tempfile::tempdir().unwrap();
    let path = super::project::fixture(&temp);
    let mut options = super::project::options(&path);
    assert_eq!(options.startup_timeout_seconds, 300);
    options.data_root = temp.path().to_owned();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut config = options.config().unwrap();
    // No request headers are captured by this clock-only observation test.
    config.recording.encrypt_request_headers.clear();
    let state = crate::AppState::new(config).await.unwrap();
    let ready_at = tokio::time::Instant::now();
    let observing = state.clone();
    let observation = tokio::spawn(async move {
        observing
            .wait_for_post_ready_admission(ready_at)
            .await
            .unwrap()
    });
    tokio::task::yield_now().await;
    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(10)).await;
        state.record_redis_cache_request();
        tokio::task::yield_now().await;
        assert!(!observation.is_finished());
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(
        observation.await.unwrap(),
        crate::PostReadyWaitOutcome::MaximumWaitElapsed
    );
    assert_eq!(ready_at.elapsed(), Duration::from_secs(30));
}
