//! A separately compiled protocol exercises real recording and Replay entry points.
use crate::protocols::{DependencyProtocol, DependencyProviders};
use crate::replay::{
    ReplayConfig, ReplayControlConfig, ReplayDependencyLoading, ReplayLifecycleConfig,
};
use anyhow::Result;
use chrono::Utc;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_contract::{
    codec::Codec,
    rule::{FieldContract, IdentityFormat},
};
use traffic_engine::test_support::serve_recording_connection as handle_connection;
use traffic_policy_value::{MessageSide, RuleBinding, ValueRule};

#[path = "compact_redis_test.rs"]
mod compact_redis;

const NATIVE: &str = traffic_protocol_fixture::NAME;

fn providers() -> Arc<DependencyProviders> {
    let mut providers = crate::protocols::default_providers().as_ref().clone();
    if providers.provider(DependencyProtocol::new(NATIVE)).is_err() {
        providers
            .register(
                DependencyProtocol::new(NATIVE),
                Arc::new(traffic_protocol_fixture::Provider),
            )
            .unwrap();
    }
    let rule = Arc::new(ValueRule {
        id: "generated_entity".into(),
        contract: FieldContract::Identity {
            prefix: String::new(),
            format: IdentityFormat::Decimal,
        },
    });
    for side in [MessageSide::Request, MessageSide::Response] {
        providers
            .bindings_mut()
            .register(
                NATIVE,
                side,
                RuleBinding {
                    rule: rule.clone(),
                    selector: json!({"kind":"document"}),
                    codec: Codec::Json,
                    pointer: "/id".into(),
                },
                false,
            )
            .unwrap();
    }
    Arc::new(providers)
}

struct Recording {
    _directory: tempfile::TempDir,
    root: PathBuf,
    case: String,
    providers: Arc<DependencyProviders>,
    source_bytes: Vec<u8>,
    startup_listener: bool,
}

async fn record() -> Recording {
    record_with_startup(false).await
}

async fn record_with_startup(startup: bool) -> Recording {
    record_with_value(startup, "original").await
}

async fn record_with_value(startup: bool, fixed: &'static str) -> Recording {
    record_scenario(startup, fixed, false).await
}

async fn record_scenario(startup: bool, fixed: &'static str, notifications: bool) -> Recording {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let native_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let native_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let native_address = native_proxy.local_addr().unwrap();
    let primary_source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let providers = providers();
    let mut config = crate::AppConfig {
        artifacts: None,
        ..Default::default()
    };
    config.http_gateway.enabled = true;
    config.http_gateway.ready.enabled = false;
    config.http_gateway.matched_upstream =
        format!("http://{}", primary_source.local_addr().unwrap());
    config.http_gateway.rules = vec![crate::HttpGatewayRuleConfig {
        name: Some("native-extension".into()),
        methods: vec!["GET".into()],
        paths: vec!["/record/native".into()],
        ..Default::default()
    }];
    let local = directory.path().join(".traffic-e2e/local");
    let key_path = local.join(crate::test_support::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    std::fs::write(
        key_path,
        crate::test_support::generate_encryption_key().unwrap(),
    )
    .unwrap();
    config.recording.output_dir = local.join("recordings");
    config.recording.traffic_jsonl = crate::TrafficJsonlMode::Off;
    config.recording.case_dependency_post_response_window_ms = 0;
    config.tls.ca_cert_path = directory.path().join("ca.pem");
    config.tls.ca_key_path = directory.path().join("ca-key.pem");
    config.dns_mock.enabled = true;
    config.dns_mock.fake_cidr = "127.0.0.0/24".into();
    config.dns_mock.registry_path = directory.path().join("dns.json");
    config.tcp_gateway.enabled = true;
    std::fs::write(
        &config.dns_mock.registry_path,
        serde_json::to_vec(&json!({"entries":[{
            "domain":"fixture.test","fake_ip":"127.0.0.1","real_ips":["127.0.0.1"],
            "first_seen":Utc::now(),"last_seen":Utc::now()
        }]}))
        .unwrap(),
    )
    .unwrap();
    let state = crate::AppState::new_with_providers(config, providers.clone())
        .await
        .unwrap();
    crate::test_support::install_recording_upstream(
        &state,
        "fixture.test",
        native_address.port(),
        native_upstream.local_addr().unwrap(),
    )
    .unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = native_upstream.accept().await.unwrap();
        let first = if notifications && !startup {
            "listen"
        } else {
            "fetch"
        };
        let operations = if startup {
            vec![if notifications { "listen" } else { "warm" }, first, "next"]
        } else {
            vec![first, "next"]
        };
        for operation in operations {
            let request = traffic_protocol_fixture::read(&mut stream).await.unwrap();
            assert_eq!(
                request,
                json!({"id":42,"operation":operation,"fixed":fixed})
            );
            if notifications && operation == "next" {
                stream
                    .write_all(
                        &traffic_protocol_fixture::encode(
                            &json!({"notification":true,"id":42,"index":1}),
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            stream
                .write_all(&traffic_protocol_fixture::encode(&request).unwrap())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            if notifications && operation == first {
                stream
                    .write_all(
                        &traffic_protocol_fixture::encode(
                            &json!({"notification":true,"id":42,"index":0}),
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
        }
    });
    let recording = state.clone();
    let proxy = tokio::spawn(async move {
        let (stream, peer) = native_proxy.accept().await.unwrap();
        handle_connection(stream, peer, recording).await.unwrap();
    });
    let startup_dependency = if startup {
        let mut stream = TcpStream::connect(native_address).await.unwrap();
        let request =
            json!({"id":42,"operation":if notifications {"listen"} else {"warm"},"fixed":fixed});
        stream
            .write_all(&traffic_protocol_fixture::encode(&request).unwrap())
            .await
            .unwrap();
        assert_eq!(
            traffic_protocol_fixture::read(&mut stream).await.unwrap(),
            request
        );
        Some(stream)
    } else {
        None
    };
    crate::test_support::close_bootstrap(&state, "fixture Source ready")
        .await
        .unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = primary_source.accept().await.unwrap();
        read_http_head(&mut stream).await;
        let mut dependency = match startup_dependency {
            Some(stream) => stream,
            None => TcpStream::connect(native_address).await.unwrap(),
        };
        for operation in [
            if notifications && !startup {
                "listen"
            } else {
                "fetch"
            },
            "next",
        ] {
            let request = json!({"id":42,"operation":operation,"fixed":fixed});
            let wire = traffic_protocol_fixture::encode(&request).unwrap();
            for piece in wire.chunks(3) {
                dependency.write_all(piece).await.unwrap();
            }
            if notifications && operation == "next" {
                assert_eq!(
                    traffic_protocol_fixture::read(&mut dependency)
                        .await
                        .unwrap(),
                    json!({"notification":true,"id":42,"index":1})
                );
            }
            assert_eq!(
                traffic_protocol_fixture::read(&mut dependency)
                    .await
                    .unwrap(),
                request
            );
            if notifications && operation != "next" {
                for index in 0..1 {
                    assert_eq!(
                        traffic_protocol_fixture::read(&mut dependency)
                            .await
                            .unwrap(),
                        json!({"notification":true,"id":42,"index":index})
                    );
                }
            }
        }
        drop(dependency);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = gateway_listener.local_addr().unwrap();
    let serving = state.clone();
    let gateway = tokio::spawn(crate::test_support::serve_recording_gateway(
        serving,
        gateway_listener,
    ));
    let mut client = TcpStream::connect(gateway_address).await.unwrap();
    client
        .write_all(b"GET /record/native HTTP/1.1\r\nHost: source.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"ok"));
    source.await.unwrap();
    upstream.await.unwrap();
    proxy.await.unwrap();
    assert!(
        traffic_engine::test_support::wait_for_no_active_case(&state, Duration::from_secs(2)).await
    );
    assert!(!state.recorder().finish_run().await.unwrap());
    gateway.abort();
    let root = state.recorder().run_dir().as_ref().clone();
    let manifest: crate::dependency::observation::RecordingManifest =
        serde_json::from_slice(&std::fs::read(root.join("dependency-manifest.json")).unwrap())
            .unwrap();
    assert!(manifest.sealed && manifest.capture_complete);
    assert_eq!(manifest.inputs.len(), 1);
    assert!(manifest.semantic_inventory.unsupported_by_scope.is_empty());
    let source_bytes = std::fs::read(root.join(traffic_model::compact::DEPENDENCIES)).unwrap();
    let semantic_bytes = crate::dependency_index::scoped::read_bytes(
        &root.join(traffic_model::compact::DEPENDENCIES),
    )
    .unwrap();
    let rows = String::from_utf8_lossy(&semantic_bytes)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let native = rows
        .iter()
        .filter(|row| row["event_type"] == traffic_protocol_fixture::EVENT)
        .collect::<Vec<_>>();
    assert_eq!(native.len(), 2 + usize::from(startup));
    assert!(native.iter().all(|row| row.get("target_host").is_none() && row["peer"]["address"] == "fixture.test"));
    Recording {
        _directory: directory,
        root,
        case: manifest.inputs[0].case_id.to_string(),
        providers,
        source_bytes,
        startup_listener: startup && notifications,
    }
}

async fn read_http_head(stream: &mut TcpStream) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
}

struct Replay {
    _directory: tempfile::TempDir,
    address: SocketAddr,
    session: PathBuf,
    case: String,
    task: tokio::task::JoinHandle<Result<()>>,
    startup_connection: Option<TcpStream>,
}

impl Replay {
    async fn start(recording: &Recording, lazy: bool) -> Self {
        Self::start_with_startup(recording, lazy, false).await
    }
    async fn start_with_startup(recording: &Recording, lazy: bool, deliver_startup: bool) -> Self {
        Self::start_with_policy(recording, lazy, deliver_startup, None).await
    }
    async fn start_with_policy(
        recording: &Recording,
        lazy: bool,
        deliver_startup: bool,
        policy: Option<&str>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let session = directory.path().join("session.json");
        let policy_path = policy.map(|policy| {
            let path = directory.path().join("policy.yaml");
            std::fs::write(&path, policy).unwrap();
            path
        });
        let config = ReplayConfig {
            case_dir: recording.root.clone(),
            selected_case_ids: vec![recording.case.clone()],
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(directory.path().join("report.json")),
            session_path: Some(session.clone()),
            control_socket_path: Some(crate::replay::allocate_control_socket()),
            ca_cert_path: Some(directory.path().join("ca.pem")),
            ca_key_path: Some(directory.path().join("ca-key.pem")),
            policy_path,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        };
        let providers = recording.providers.clone();
        let task = tokio::spawn(crate::run_replay_with_providers(
            config,
            ReplayLifecycleConfig {
                dependency_loading: ReplayDependencyLoading {
                    lazy_cases: lazy,
                    ..Default::default()
                },
                ..Default::default()
            },
            None,
            providers,
        ));
        let ready = control(&session, "wait_ready", None).await;
        assert_eq!(ready["ok"], true);
        let address: SocketAddr = ready["session"]["tcp_listen"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let mut startup_connection = None;
        if deliver_startup {
            let mut target = TcpStream::connect(address).await.unwrap();
            let request = json!({"id":1042,"operation":if recording.startup_listener {"listen"} else {"warm"},"fixed":"original"});
            target
                .write_all(&traffic_protocol_fixture::encode(&request).unwrap())
                .await
                .unwrap();
            assert_eq!(
                traffic_protocol_fixture::read(&mut target).await.unwrap(),
                request
            );
            if recording.startup_listener {
                startup_connection = Some(target);
            }
        }
        assert_eq!(
            control(&session, "begin", Some(&recording.case)).await["ok"],
            true
        );
        assert_eq!(
            control(&session, "request_begin", Some(&recording.case)).await["ok"],
            true
        );
        Self {
            _directory: directory,
            address,
            session,
            case: recording.case.clone(),
            task,
            startup_connection,
        }
    }

    async fn finish(mut self) -> Value {
        self.finalize().await
    }

    async fn finalize(&mut self) -> Value {
        assert_eq!(
            control(&self.session, "end", Some(&self.case)).await["ok"],
            true
        );
        let finalized = control(&self.session, "finalize", None).await;
        assert_eq!(finalized["ok"], true);
        (&mut self.task).await.unwrap().unwrap();
        serde_json::from_slice(&std::fs::read(self._directory.path().join("report.json")).unwrap())
            .unwrap()
    }
}

async fn control(session: &Path, command: &str, case: Option<&str>) -> Value {
    crate::replay::run_replay_control(ReplayControlConfig {
        session_path: session.into(),
        command: command.into(),
        case_id: case.map(ToOwned::to_owned),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        wait_timeout: Some(Duration::from_secs(10)),
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn registered_protocol_records_seals_loads_matches_renders_and_delivers_with_shared_rules() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let recording = record().await;
        for lazy in [false, true] {
            let replay = Replay::start(&recording, lazy).await;
            let mut target = TcpStream::connect(replay.address).await.unwrap();
            for operation in ["fetch", "next"] {
                let request = json!({"id":1042,"operation":operation,"fixed":"original"});
                target
                    .write_all(&traffic_protocol_fixture::encode(&request).unwrap())
                    .await
                    .unwrap();
                let response = traffic_protocol_fixture::read(&mut target).await.unwrap();
                assert_eq!(response, request);
            }
            drop(target);
            let report = replay.finish().await;
            assert_eq!(report["dependency_protocols"][NATIVE]["matched_count"], 2);
            assert_eq!(
                report["dependency_protocols"][NATIVE]["unused_case"],
                json!([])
            );
            assert!(report.get("case_execution_failures").is_none());
            assert_eq!(
                report["batch_reconciliation"]["dependency_inventory_verified"],
                true,
                "{}",
                json!({"reconciliation":report["batch_reconciliation"],
                    "startup":report["startup_phase"],"coverage":report["target_observation_coverage_error"],
                    "ingress":report["http_ingress"],"sequence":report["dependency_sequence_missing"]})
            );
            assert_eq!(
                std::fs::read(recording.root.join(traffic_model::compact::DEPENDENCIES)).unwrap(),
                recording.source_bytes
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn registered_protocol_keeps_unselected_fields_strict_and_rejections_unconsumed() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let recording = record().await;
        let replay = Replay::start(&recording, true).await;
        let mut target = TcpStream::connect(replay.address).await.unwrap();
        target
            .write_all(
                &traffic_protocol_fixture::encode(
                    &json!({"id":1042,"operation":"fetch","fixed":"changed"}),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        target.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
        let report = replay.finish().await;
        assert_eq!(report["dependency_protocols"][NATIVE]["matched_count"], 0);
        assert_eq!(report["dependency_protocols"][NATIVE]["unmatched_count"], 1);
        assert_eq!(
            report["dependency_protocols"][NATIVE]["unused_case"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            report["batch_reconciliation"]["dependency_inventory_verified"],
            false
        );
        let unused = crate::replay::report::unused_source::published_for_cases(
            &report,
            report["unused_source_inventory_id"].as_str().unwrap(),
            &std::collections::BTreeSet::from([recording.case.clone()]),
            recording.providers.report_codecs(),
        )
        .unwrap();
        assert_eq!(unused.len(), 2);
        assert!(
            unused
                .values()
                .all(|occurrence| occurrence.capture_complete)
        );
        assert_eq!(
            std::fs::read(recording.root.join(traffic_model::compact::DEPENDENCIES)).unwrap(),
            recording.source_bytes
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn registered_protocol_unused_case_calls_prevent_batch_verification() {
    let recording = record().await;
    let mut replay = Replay::start(&recording, false).await;
    let report = replay.finalize().await;
    assert_eq!(report["dependency_protocols"][NATIVE]["matched_count"], 0);
    assert_eq!(report["dependency_protocols"][NATIVE]["unmatched_count"], 0);
    assert_eq!(
        report["dependency_protocols"][NATIVE]["unused_case"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        report["batch_reconciliation"]["dependency_inventory_verified"],
        false
    );
    assert!(
        crate::protocols::replay::report::validation::validate_completed_receipt(&report).is_err()
    );
}

#[tokio::test]
async fn registered_protocol_global_evidence_uses_native_projection_and_generic_publication() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let recording = record_with_startup(true).await;
        for (lazy, delivered) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut replay = Replay::start_with_startup(&recording, lazy, delivered).await;
            let report_path = replay._directory.path().join("report.json");
            let published = tempfile::tempdir().unwrap();
            let mut target = TcpStream::connect(replay.address).await.unwrap();
            for operation in ["fetch", "next"] {
                let request = json!({"id":1042,"operation":operation,"fixed":"original"});
                target
                    .write_all(&traffic_protocol_fixture::encode(&request).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    traffic_protocol_fixture::read(&mut target).await.unwrap(),
                    request
                );
            }
            drop(target);
            let report = replay.finalize().await;
            assert_eq!(
                report["dependency_protocols"][NATIVE]["matched_count"],
                if delivered { 3 } else { 2 }
            );
            assert_eq!(
                report["dependency_protocols"][NATIVE]["unused_global_count"],
                usize::from(!delivered)
            );
            let receipt =
                crate::protocols::replay::report::validation::validate_completed_receipt(&report);
            assert_eq!(
                receipt.is_ok(),
                delivered,
                "registered native session receipt: {receipt:?}"
            );
            let page = crate::read_global_dependency_page(&report_path, NATIVE, 0, 10).unwrap();
            assert_eq!(page.total, usize::from(!delivered));
            assert_eq!(report["global_evidence"][NATIVE]["regular"]["recorded"], 1);
            if delivered {
                assert!(page.items.is_empty());
            } else {
                assert_eq!(
                    page.items[0]["native"],
                    json!({"wire_format":"fixture","operation":"warm"})
                );
            }
            let staged = published.path().join("report.json");
            let rebound = crate::protocols::replay::report::artifacts::stage_global_evidence(
                &report_path,
                &staged,
            )
            .unwrap()
            .unwrap_or(report);
            std::fs::write(&staged, serde_json::to_vec(&rebound).unwrap()).unwrap();
            assert_eq!(
                crate::read_global_dependency_page(&staged, NATIVE, 0, 10)
                    .unwrap()
                    .items,
                page.items
            );
            assert_eq!(
                std::fs::read(recording.root.join(traffic_model::compact::DEPENDENCIES)).unwrap(),
                recording.source_bytes
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn registered_protocol_uses_authored_global_json_rules_through_normal_replay() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut recording = record().await;
        let mut providers = crate::protocols::default_providers().as_ref().clone();
        if providers.provider(DependencyProtocol::new(NATIVE)).is_err() {
            providers.register(DependencyProtocol::new(NATIVE), Arc::new(traffic_protocol_fixture::Provider)).unwrap();
        }
        recording.providers = Arc::new(providers);
        let policy = "format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [decimal]}\n";
        for lazy in [false, true] {
            let replay = Replay::start_with_policy(&recording, lazy, false, Some(policy)).await;
            let mut target = TcpStream::connect(replay.address).await.unwrap();
            for operation in ["fetch", "next"] {
                let request = json!({"id":1042,"operation":operation,"fixed":"original"});
                target.write_all(&traffic_protocol_fixture::encode(&request).unwrap()).await.unwrap();
                assert_eq!(traffic_protocol_fixture::read(&mut target).await.unwrap(), request);
            }
            drop(target);
            let report = replay.finish().await;
            assert_eq!(report["dependency_protocols"][NATIVE]["matched_count"], 2);
            assert_eq!(report["batch_reconciliation"]["dependency_inventory_verified"], true);
            assert_eq!(std::fs::read(recording.root.join(traffic_model::compact::DEPENDENCIES)).unwrap(), recording.source_bytes);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn a_failed_native_request_reports_registered_policy_findings_and_source_references() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let recording = record_with_value(false, "red,blue,red").await;
        let replay = Replay::start(&recording, true).await;
        let mut target = TcpStream::connect(replay.address).await.unwrap();
        let request = json!({"id":1042,"operation":"fetch","fixed":"blue,red,red"});
        target
            .write_all(&traffic_protocol_fixture::encode(&request).unwrap())
            .await
            .unwrap();
        let mut response = Vec::new();
        target.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
        let report = replay.finish().await;
        let native = &report["dependency_protocols"][NATIVE];
        assert_eq!(native["matched_count"], 0);
        assert_eq!(native["unmatched_count"], 1);
        assert_eq!(native["unused_case"].as_array().unwrap().len(), 2);
        let failed = &native["unmatched"][0];
        assert!(failed["target_observation_id"].as_str().is_some());
        let compared = &failed["candidate_comparisons"][0];
        assert_eq!(compared["source_reference"]["protocol"], NATIVE);
        assert!(compared["source_exchange_id"].as_str().is_some());
        assert!(
            compared["differences"]
                .as_array()
                .is_some_and(|differences| !differences.is_empty())
        );
        let findings = traffic_protocol::report::findings::candidate_findings(failed, NATIVE);
        let finding = findings
            .iter()
            .find(|finding| finding["policy"] == "unordered-joined-string")
            .unwrap();
        assert_eq!(finding["source_path"], "/fixed");
        assert_eq!(finding["native_location"], "document");
        assert_eq!(
            finding["origin"]["target_observation_id"],
            failed["target_observation_id"]
        );
        let evidence = crate::replay::report::build_dependency_evidence(
            &report,
            recording.providers.report_codecs(),
        );
        let facts = json!({"clusters":evidence.clusters});
        let diagnosed = recording
            .providers
            .report_codecs()
            .diagnose(&facts)
            .unwrap();
        assert!(
            diagnosed.details["policy_findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["policy"] == "unordered-joined-string")
        );
        assert_eq!(
            std::fs::read(recording.root.join(traffic_model::compact::DEPENDENCIES)).unwrap(),
            recording.source_bytes
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn independent_server_messages_record_and_replay_with_shared_policy_and_finite_receipts() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for startup in [false, true] {
        let recording = record_scenario(startup, "original", true).await;
        let trace =
            std::fs::read_to_string(recording.root.join(traffic_model::compact::EVENTS)).unwrap();
        assert_eq!(
            trace
                .lines()
                .filter(|line| line.contains("message_started"))
                .count(),
            2
        );
        for lazy in [false, true] {
            let mut replay = Replay::start_with_startup(&recording, lazy, startup).await;
            let mut target = match replay.startup_connection.take() { Some(target) => target, None => TcpStream::connect(replay.address).await.unwrap() };
            let listen = json!({"id":1042,"operation":if startup {"fetch"} else {"listen"},"fixed":"original"});
            target
                .write_all(&traffic_protocol_fixture::encode(&listen).unwrap())
                .await
                .unwrap();
            assert_eq!(
                traffic_protocol_fixture::read(&mut target).await.unwrap(),
                listen
            );
            for index in 0..1 {
                assert_eq!(
                    traffic_protocol_fixture::read(&mut target).await.unwrap(),
                    json!({"notification":true,"id":1042,"index":index})
                );
            }
            let next = json!({"id":1042,"operation":"next","fixed":"original"});
            target
                .write_all(&traffic_protocol_fixture::encode(&next).unwrap())
                .await
                .unwrap();
            assert_eq!(traffic_protocol_fixture::read(&mut target).await.unwrap(), json!({"notification":true,"id":1042,"index":1}));
            assert_eq!(
                traffic_protocol_fixture::read(&mut target).await.unwrap(),
                next
            );
            drop(target);
            let report = replay.finish().await;
            assert_eq!(
                report["dependency_protocols"][NATIVE]["matched_count"], 4 + usize::from(startup),
                "{report}"
            );
            assert_eq!(
                report["dependency_protocols"][NATIVE]["unused_case"],
                json!([])
            );
            assert_eq!(
                report["batch_reconciliation"]["dependency_inventory_verified"], true,
                "{report}"
            );
            assert_eq!(
                std::fs::read(recording.root.join(traffic_model::compact::DEPENDENCIES)).unwrap(),
                recording.source_bytes
            );
        }
        }
    })
    .await
    .unwrap();
}
