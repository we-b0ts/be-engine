use super::*;

struct DirectFixture {
    relay: proxy::Relay<RedisService>,
    url: String,
    adapter: JoinHandle<()>,
}

impl DirectFixture {
    async fn new(origin: hyper::Uri, max_body: usize) -> Self {
        let relay = proxy::Relay::new(
            None,
            origin,
            "all-apis".into(),
            Duration::from_secs(2),
            max_body,
        );
        relay.open();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = watch::channel(false);
        let serving = relay.clone();
        let adapter = tokio::spawn(async move {
            let _stop = stop;
            proxy::serve(listener, serving, stopped).await.unwrap();
        });
        Self {
            relay,
            url,
            adapter,
        }
    }

    async fn request(&self, method: &str, path: &str, body: &'static str) -> StatusCode {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client
            .request(
                Request::builder()
                    .method(method)
                    .uri(format!("{}{path}", self.url))
                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        response.into_body().collect().await.unwrap();
        status
    }
}

impl Drop for DirectFixture {
    fn drop(&mut self) {
        self.adapter.abort();
    }
}

#[test]
fn direct_requests_need_no_redis_or_admission_headers_and_preserve_all_methods() {
    runtime().block_on(async {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = DirectFixture::new(
            format!("http://{}", source.local_addr().unwrap())
                .parse()
                .unwrap(),
            1024,
        )
        .await;
        let upstream = tokio::spawn(async move {
            for method in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] {
                let (mut stream, _) = source.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert!(request.starts_with(&format!("{method} /items?q=1 HTTP/1.1")));
                assert!(request.ends_with("payload"));
                assert!(!request.contains("x-breeze-admission"));
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        for method in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                fixture.request(method, "/items?q=1", "payload").await,
                StatusCode::NO_CONTENT
            );
        }
        upstream.await.unwrap();
    });
}

#[test]
fn direct_admission_keeps_single_request_ownership_and_rejects_closed_or_oversized_input() {
    runtime().block_on(async {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = DirectFixture::new(
            format!("http://{}", source.local_addr().unwrap())
                .parse()
                .unwrap(),
            4,
        )
        .await;
        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let (started, release) = (entered.clone(), finish.clone());
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = source.accept().await.unwrap();
            read_request(&mut stream).await;
            started.notify_one();
            release.notified().await;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), source.accept())
                    .await
                    .is_err()
            );
        });
        let first = fixture.request("POST", "/items", "ok");
        let second = async {
            entered.notified().await;
            assert_eq!(
                fixture.request("POST", "/items", "ok").await,
                StatusCode::NOT_FOUND
            );
            finish.notify_one();
        };
        let (status, ()) = tokio::join!(first, second);
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            fixture.request("POST", "/items", "oversized").await,
            StatusCode::NOT_FOUND
        );
        fixture.relay.close();
        assert_eq!(
            fixture.request("POST", "/items", "ok").await,
            StatusCode::NOT_FOUND
        );
        upstream.await.unwrap();
    });
}

#[test]
fn configured_include_and_exclude_rules_apply_before_source_dispatch_in_direct_mode() {
    runtime().block_on(async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let path = super::project::fixture(&temp);
        let mut options = super::project::options(&path);
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        options.source_origin = format!("http://{}", source.local_addr().unwrap());
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        options.recorder_listen = gateway_listener.local_addr().unwrap();
        options.data_root = temp.path().join("data");
        options.no_interception = true;
        let mut config = options.config().unwrap();
        config.http_gateway.rules[0].methods = vec!["POST".into()];
        config.http_gateway.rules[0].path_prefixes = vec!["/api".into()];
        config.http_gateway.exclude_rules[0].path_prefixes = vec!["/api/private".into()];
        config.http_gateway.ready.enabled = false;
        config.recording.encrypt_request_headers.clear();
        config.recording.case_dependency_post_response_window_ms = 0;
        let state = crate::AppState::new(config).await.unwrap();
        state
            .close_bootstrap("direct rule test ready")
            .await
            .unwrap();
        let running = state.clone();
        let gateway = tokio::spawn(async move {
            crate::gateway::http::run_with_listener(running, gateway_listener)
                .await
                .unwrap()
        });
        let fixture = DirectFixture::new(
            format!("http://{}", options.recorder_listen)
                .parse()
                .unwrap(),
            1024,
        )
        .await;
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = source.accept().await.unwrap();
            assert!(
                read_request(&mut stream)
                    .await
                    .starts_with("POST /api/public HTTP/1.1")
            );
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        assert_eq!(
            fixture.request("DELETE", "/api/public", "").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            fixture.request("POST", "/api/private", "").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            fixture.request("POST", "/api/public", "body").await,
            StatusCode::NO_CONTENT
        );
        upstream.await.unwrap();
        gateway.abort();
        let _ = gateway.await;
        state.recorder().finish_run().await.unwrap();
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(state.recorder().run_dir.join("recording-run.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report["published_cases"], 1);
        assert_eq!(report["status"], "completed");
    });
}
