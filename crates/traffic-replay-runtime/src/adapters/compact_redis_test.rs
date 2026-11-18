use super::*;
use traffic_model::compact::{self, PayloadRef};
use traffic_protocol_redis::{BufferedReader, encode_array, read_frame};

const CHANNEL: &[u8] = b"codex-compact-verify";
const KEY: &[u8] = b"codex-compact-verify-large";
const EMPTY_QUEUE: &[u8] = b"codex-compact-verify-empty";

type Redis = BufferedReader<TcpStream>;

async fn connect(address: SocketAddr) -> Result<Redis> {
    Ok(BufferedReader::new(
        TcpStream::connect(address).await?,
        1024 * 1024,
    ))
}

async fn send(connection: &mut Redis, args: &[&[u8]]) -> Result<()> {
    connection.inner.write_all(&encode_array(args)).await?;
    Ok(())
}

async fn receive(connection: &mut Redis) -> Result<Vec<u8>> {
    Ok(read_frame(connection)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Redis closed the connection"))?
        .raw
        .to_vec())
}

async fn exchange(connection: &mut Redis, args: &[&[u8]]) -> Result<Vec<u8>> {
    send(connection, args).await?;
    receive(connection).await
}

async fn exercise(address: SocketAddr, value: &[u8]) -> Result<()> {
    let mut commands = connect(address).await?;
    assert_eq!(
        exchange(&mut commands, &[b"SET", KEY, value]).await?,
        b"+OK\r\n"
    );
    let mut subscription = connect(address).await?;
    assert!(
        exchange(&mut subscription, &[b"SUBSCRIBE", CHANNEL])
            .await?
            .starts_with(b"*3\r\n")
    );
    let mut blocked = connect(address).await?;
    send(&mut blocked, &[b"BLPOP", EMPTY_QUEUE, b"1"]).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let result = exchange(&mut commands, &[b"GET", KEY]).await?;
    let mut expected = format!("{}{}\r\n", '$', value.len()).into_bytes();
    expected.extend_from_slice(value);
    expected.extend_from_slice(b"\r\n");
    assert_eq!(result, expected);
    let publish = [b"PUBLISH".as_slice(), CHANNEL, value];
    let (published, pushed) = tokio::try_join!(
        exchange(&mut commands, &publish),
        receive(&mut subscription),
    )?;
    assert_eq!(published, b":1\r\n");
    assert_eq!(pushed, encode_array(&[b"message", CHANNEL, value]));
    assert_eq!(receive(&mut blocked).await?, b"*-1\r\n");
    assert!(
        exchange(&mut subscription, &[b"UNSUBSCRIBE", CHANNEL])
            .await?
            .starts_with(b"*3\r\n")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable Redis at BE_ENGINE_TEST_REDIS"]
async fn real_redis_compact_recording_replays_large_values_concurrency_and_pubsub() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let upstream: SocketAddr = std::env::var("BE_ENGINE_TEST_REDIS")?.parse()?;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let directory = tempfile::tempdir()?;
        let local = directory.path().join(".traffic-e2e/local");
        let key = local.join(crate::test_support::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key.parent().unwrap())?;
        std::fs::write(key, crate::test_support::generate_encryption_key()?)?;
        let source_api = TcpListener::bind("127.0.0.1:0").await?;
        let proxy = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_address = proxy.local_addr()?;
        let mut config = crate::AppConfig { artifacts: None, ..Default::default() };
        config.http_gateway.enabled = true;
        config.http_gateway.ready.enabled = false;
        config.http_gateway.matched_upstream = format!("http://{}", source_api.local_addr()?);
        config.http_gateway.rules = vec![crate::HttpGatewayRuleConfig {
            name: Some("compact-redis".into()),
            methods: vec!["GET".into()],
            paths: vec!["/verify".into()],
            ..Default::default()
        }];
        config.recording.output_dir = local.join("recordings");
        config.recording.traffic_jsonl = crate::TrafficJsonlMode::Off;
        config.tls.ca_cert_path = directory.path().join("recorder-ca.pem");
        config.tls.ca_key_path = directory.path().join("recorder-ca-key.pem");
        config.dns_mock.enabled = true;
        config.dns_mock.fake_cidr = "127.0.0.0/24".into();
        config.dns_mock.registry_path = directory.path().join("dns.json");
        config.tcp_gateway.enabled = true;
        config.tcp_gateway.protocol_detection.redis_port_hints.push(proxy_address.port());
        std::fs::write(&config.dns_mock.registry_path, serde_json::to_vec(&json!({"entries":[{
            "domain":"redis.test", "fake_ip":"127.0.0.1", "real_ips":["127.0.0.1"],
            "first_seen":Utc::now(), "last_seen":Utc::now()
        }]}))?)?;
        let providers = crate::protocols::default_providers();
        let state = crate::AppState::new_with_providers(config, providers.clone()).await?;
        crate::test_support::install_recording_upstream(&state, "redis.test", proxy_address.port(), upstream)?;
        crate::test_support::close_bootstrap(&state, "real Redis verify ready").await?;
        let proxy_state = state.clone();
        let proxy_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for _ in 0..3 {
                let (stream, peer) = proxy.accept().await?;
                connections.spawn(handle_connection(stream, peer, proxy_state.clone()));
            }
            while let Some(connection) = connections.join_next().await { connection??; }
            anyhow::Ok(())
        });
        let value = (0..8192).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let source_value = value.clone();
        let source = tokio::spawn(async move {
            let (mut stream, _) = source_api.accept().await?;
            read_http_head(&mut stream).await;
            exercise(proxy_address, &source_value).await?;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            stream.shutdown().await?;
            anyhow::Ok(())
        });
        let gateway = TcpListener::bind("127.0.0.1:0").await?;
        let address = gateway.local_addr()?;
        let gateway_task = tokio::spawn(crate::test_support::serve_recording_gateway(state.clone(), gateway));
        let mut client = TcpStream::connect(address).await?;
        client.write_all(b"GET /verify HTTP/1.1\r\nHost: source.test\r\nConnection: close\r\n\r\n").await?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        source.await??;
        proxy_task.await??;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"ok"));
        assert!(crate::test_support::wait_for_no_active_case(&state, Duration::from_secs(3)).await);
        assert!(!state.recorder().finish_run().await?);
        gateway_task.abort();
        let root = state.recorder().run_dir().as_ref().clone();
        let (_, manifest) = crate::dependency_index::recording::manifest(&root)?;
        crate::dependency_index::recording::authenticate(&root)?;
        assert!(manifest.capture_complete);
        assert!(!root.join(".global-replay-index.json").exists());
        assert!(!root.join(".global-replay-pages").exists());
        let events = std::fs::read_to_string(root.join(compact::EVENTS))?
            .lines().map(compact::decode_event).collect::<Result<Vec<_>>>()?;
        assert!(events.windows(2).all(|pair| pair[0].sequence < pair[1].sequence));
        let semantic = crate::dependency_index::scoped::read_bytes(&root.join(compact::DEPENDENCIES))?;
        let rows = std::str::from_utf8(&semantic)?.lines()
            .map(serde_json::from_str::<Value>).collect::<serde_json::Result<Vec<_>>>()?;
        let request = |command| {
            rows.iter().find(|row| row["command"].as_str() == Some(command)).unwrap()["capture"]["sequence"].as_u64().unwrap()
        };
        let start = |id| events.iter().find(|event| {
            matches!(event.event, traffic_model::trace::CaptureEvent::Started { dependency_sequence, .. } if dependency_sequence == id)
        }).unwrap().sequence;
        let end = |id| events.iter().find(|event| {
            matches!(event.event, traffic_model::trace::CaptureEvent::Output { dependency_sequence, output: traffic_model::trace::OutputKind::End, .. } if dependency_sequence == id)
        }).unwrap().sequence;
        let blocked = request("BLPOP");
        let get = request("GET");
        assert!(start(blocked) < start(get) && start(get) < end(get) && end(get) < end(blocked));
        let primary = events.iter().filter_map(|event| {
            if let traffic_model::trace::CaptureEvent::PrimaryBoundary { case_id, boundary } = event.event
                && case_id == manifest.inputs[0].case_id
            {
                Some((event.sequence, boundary))
            } else {
                None
            }
        }).collect::<Vec<_>>();
        let [(opened, traffic_model::trace::PrimaryBoundary::Start), (closed, traffic_model::trace::PrimaryBoundary::ResponseEnd)] = primary.as_slice() else {
            anyhow::bail!("expected two primary boundaries, got {primary:?}");
        };
        assert!(*opened < start(blocked) && end(blocked) < *closed);
        let payload = std::fs::metadata(root.join(PayloadRef::path(0)))?.len();
        assert!(payload > value.len() as u64);
        let recording = Recording {
            _directory: directory,
            source_bytes: std::fs::read(root.join(compact::DEPENDENCIES))?,
            root,
            case: manifest.inputs[0].case_id.to_string(),
            providers,
            startup_listener: false,
        };
        for lazy in [false, true] {
            let replay = Replay::start(&recording, lazy).await;
            exercise(replay.address, &value).await?;
            let report = replay.finish().await;
            assert_eq!(report["dependency_protocols"]["redis"]["matched_count"], 7, "{report}");
            assert_eq!(report["dependency_protocols"]["redis"]["unused_case"], json!([]), "{report}");
            assert_eq!(report["batch_reconciliation"]["dependency_inventory_verified"], true, "{report}");
            eprintln!("real Redis inventory matched=7 lazy={lazy} event_count={} dependency_bytes={} payload_bytes={payload} semantic_jsonl_bytes={}", events.len(), recording.source_bytes.len(), semantic.len());
        }
        Ok(())
    }).await?
}
