//! Real RESP requests through eager and lazy inventories with foreign API proof.
use super::*;
use crate::replay::{ReplayConfig, ReplayDependencyLoading, ReplayLifecycleConfig, ReplayState};
use redis_value_tests::request;
use serde_json::json;
use std::{fs, sync::Arc};
use tokio::sync::Mutex;

const ERROR: &[u8] = b"";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    origin: PathBuf,
    victim: PathBuf,
    lane: Uuid,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("run");
        let origin = root.join("apis/jobs/origin");
        let victim = root.join("apis/presence/victim");
        for (dir, method, uri, body) in [
            (&origin, "POST", "/jobs", r#"{"background":true}"#),
            (&victim, "PUT", "/presence", r#"{"away":true}"#),
        ] {
            fs::create_dir_all(dir).unwrap();
            fs::write(
                dir.join("request.json"),
                json!({"method":method,"uri":uri,"timestamp":"2026-10-12T11:00:00Z",
                    "body":capture_json(body.as_bytes())})
                .to_string(),
            )
            .unwrap();
            fs::write(dir.join("expected-response.json"), "{}").unwrap();
        }
        fs::write(root.join("recording-run.json"), r#"{"status":"completed"}"#).unwrap();
        let fixture = Self {
            _temp: temp,
            root,
            origin,
            victim,
            lane: Uuid::new_v4(),
        };
        fixture.write(&fixture.origin, &[Self::insert(12)]);
        fixture.write(&fixture.victim, &fixture.records());
        fixture
    }

    fn insert(id: u64) -> Value {
        json!({"event_type":"mysql_exchange","command":"COM_QUERY",
            "target_host":"db.test","target_port":3306,"database":"app","username":"writer",
            "timestamp":"2026-10-12T11:00:00.100Z","outcome":"response","parse_warnings":[],
            "sql":format!("INSERT INTO jobs_0001 (id,role) VALUES ({id},'ASSISTANT')"),
            "response":{"status":"ok","affected_rows":1}})
    }

    fn rules(&self) -> Vec<BackgroundDependencyRuleConfig> {
        vec![serde_json::from_value(json!({
            "name":"jobs-async-read","protocol":"redis","ports":[6379],"command":"GET",
            "key_templates":["job:{job_id}"],
            "trigger_source":{"kind":"api","method":"POST","path":"/jobs",
                "request_body_json":{"/background":true},
                "capture":{"job_id":{"protocol":"mysql","target_host":"db.test","target_port":3306,
                    "database":"app","username":"writer","operation":"INSERT","table_patterns":["jobs_*"],
                    "row_match":{"role":"ASSISTANT"},"column":"id"}}},
            "source_revision":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "source_evidence":"jobs.py:create detaches a task; jobs.py:finish reads its own captured job key"
        })).unwrap()]
    }

    fn command(&self, sequence: u64, command: &str, args: &[&str], response: &[u8]) -> Value {
        let mut event = redis_hash_dependency(self.lane, sequence, command, args, response);
        event["timestamp"] = "2026-10-12T11:00:02Z".into();
        event["outcome"] = "response".into();
        event
    }

    fn records(&self) -> Vec<Value> {
        vec![
            self.command(1, "GET", &["job:12"], b"$-1\r\n"),
            self.command(
                2,
                "ZREM",
                &["presence:7", "client-active", "client-away"],
                b":1\r\n",
            ),
            self.command(3, "ZADD", &["presence:7", "100", "client-away"], b":1\r\n"),
            self.command(
                4,
                "ZREMRANGEBYSCORE",
                &["presence:7", "-inf", "10"],
                b":0\r\n",
            ),
            self.command(
                5,
                "ZREVRANGE",
                &["presence:7", "0", "-1"],
                b"*1\r\n$11\r\nclient-away\r\n",
            ),
            self.command(6, "GET", &["job:12"], b"$-1\r\n"),
        ]
    }

    fn write(&self, dir: &Path, records: &[Value]) {
        fs::write(
            dir.join("dependencies.jsonl"),
            records
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
    }

    async fn spawn(
        &self,
        lazy: bool,
        rules: Vec<BackgroundDependencyRuleConfig>,
    ) -> (
        SocketAddr,
        Arc<Mutex<ReplayState>>,
        tokio::task::JoinHandle<()>,
    ) {
        super::super::write_test_recording_network_manifest(&self.root);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = ReplayRuntime::load_with_lifecycle(
            ReplayConfig {
                case_dir: self.root.clone(),
                selected_case_ids: vec!["victim".into()],
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: None,
                ca_key_path: None,
                policy_path: None,
                http_ignore_query_params: vec![],
                process_owned_dependencies: rules,
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
            ReplayLifecycleConfig {
                dependency_loading: ReplayDependencyLoading {
                    lazy_cases: lazy,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let state = runtime.state.clone();
        let begin = super::super::control::begin_case(
            &super::super::control::ReplayControlRequest {
                command: "begin".into(),
                case_id: Some("victim".into()),
                fail_on_dirty: true,
                fail_on_incomplete: true,
                parameters: Default::default(),
                derived_input: None,
                native_event: None,
                input_timing: None,
                socketio_timing: None,
            },
            state.clone(),
        )
        .await;
        assert_eq!(begin["ok"], true, "{begin}");
        // The completed recording also knows the unselected origin's MySQL
        // endpoint. Route this explicit test socket to its Redis endpoint,
        // as interception does in production.
        let target = state
            .lock()
            .await
            .targets
            .iter()
            .find(|target| target.host == "redis.internal")
            .unwrap()
            .clone();
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let target = target.clone();
                let state = server_state.clone();
                tokio::spawn(async move {
                    super::super::redis::handle_connection(stream, target, state)
                        .await
                        .unwrap();
                });
            }
        });
        (addr, state, task)
    }
}

#[tokio::test]
async fn redis_api_origin_unblocks_presence_and_preserves_finite_inventory_and_report_proof() {
    for lazy in [false, true] {
        let f = Fixture::new();
        let before = fs::read(f.victim.join("dependencies.jsonl")).unwrap();
        let rules = f.rules();
        let (addr, state, task) = f.spawn(lazy, rules.clone()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        for (args, response) in [
            (
                vec!["ZREM", "presence:7", "client-active", "client-away"],
                b":1\r\n".as_slice(),
            ),
            (
                vec!["ZADD", "presence:7", "100", "client-away"],
                b":1\r\n".as_slice(),
            ),
            (
                vec!["ZREMRANGEBYSCORE", "presence:7", "-inf", "10"],
                b":0\r\n".as_slice(),
            ),
            (
                vec!["ZREVRANGE", "presence:7", "0", "-1"],
                b"*1\r\n$11\r\nclient-away\r\n".as_slice(),
            ),
        ] {
            request(&mut client, &args, response).await;
        }
        let report = f.root.join(".replay/report.json");
        {
            let mut state = state.lock().await;
            // Delivery completion is serialized independently of socket reads.
            // Wait below before inspecting final consumption.
            state.finalized_at = Some(Utc::now());
        }
        let snapshot = settled_report(&state, 4).await;
        assert_eq!(snapshot["selected_case_ids"], json!(["victim"]));
        assert!(
            snapshot["redis"]["unmatched"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            snapshot["redis"]["unused_case"].as_array().unwrap().len(),
            2
        );
        fs::write(&report, snapshot.to_string()).unwrap();
        let policy = f.root.join(".replay/policy.yaml");
        let mut config = crate::config::SourceTrafficPolicyConfig::empty();
        config.process_owned_dependencies = rules;
        fs::write(&policy, config.render().unwrap()).unwrap();
        let result =
            crate::protocols::replay::report::ownership::reclassify_background_dependencies(
                &policy,
                &report,
                &std::collections::BTreeMap::from([("victim".into(), f.victim.clone())]),
            )
            .unwrap();
        assert_eq!(result.matched_unused_case, 0);
        assert!(result.remaining_dirty_case_ids.contains("victim"));
        let classified: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
        assert_eq!(classified, snapshot);
        assert_eq!(
            fs::read(f.victim.join("dependencies.jsonl")).unwrap(),
            before
        );
        task.abort();

        let (addr, state, task) = f.spawn(lazy, f.rules()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        request(&mut client, &["GET", "job:12"], b"$-1\r\n").await;
        request(&mut client, &["GET", "job:12"], b"$-1\r\n").await;
        request(&mut client, &["GET", "job:12"], ERROR).await;
        let snapshot = settled_report(&state, 2).await;
        assert_eq!(snapshot["redis"]["unmatched"].as_array().unwrap().len(), 1);
        assert_eq!(
            snapshot["redis"]["unused_case"].as_array().unwrap().len(),
            4
        );
        task.abort();
    }
}

async fn settled_report(state: &Arc<Mutex<ReplayState>>, matched: u64) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
            if report["redis"]["matched_count"] == matched {
                return report;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn same_resource_reads_keep_finite_delivery_and_reclassify_only_the_leftover() {
    for lazy in [false, true] {
        let f = Fixture::new();
        let path = f.victim.join("request.json");
        let mut request_json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        request_json["uri"] = "/jobs/12".into();
        fs::write(path, request_json.to_string()).unwrap();
        let records: Vec<_> = (1..=3)
            .map(|sequence| f.command(sequence, "GET", &["job:12"], b"$-1\r\n"))
            .collect();
        f.write(&f.victim, &records);
        let before = fs::read(f.victim.join("dependencies.jsonl")).unwrap();
        let (addr, state, task) = f.spawn(lazy, f.rules()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        for _ in 0..2 {
            request(&mut client, &["GET", "job:12"], b"$-1\r\n").await;
        }
        // Classify a read-only snapshot while the third finite request remains
        // live. Finalizing this engine would correctly reject that request.
        let snapshot = settled_report(&state, 2).await;
        assert_eq!(
            snapshot["redis"]["unused_case"].as_array().unwrap().len(),
            1
        );
        let report = f.root.join(".replay/same-resource-report.json");
        fs::write(&report, snapshot.to_string()).unwrap();
        let policy = f.root.join(".replay/same-resource-policy.yaml");
        let mut config = crate::config::SourceTrafficPolicyConfig::empty();
        config.process_owned_dependencies = f.rules();
        fs::write(&policy, config.render().unwrap()).unwrap();
        let result =
            crate::protocols::replay::report::ownership::reclassify_background_dependencies(
                &policy,
                &report,
                &std::collections::BTreeMap::from([("victim".into(), f.victim.clone())]),
            )
            .unwrap();
        assert_eq!(result.matched_unused_case, 0);
        assert!(result.remaining_dirty_case_ids.contains("victim"));
        let classified: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(classified["redis"]["matched_count"], 2);
        assert_eq!(classified, snapshot);
        request(&mut client, &["GET", "job:12"], b"$-1\r\n").await;
        request(&mut client, &["GET", "job:12"], ERROR).await;
        let snapshot = settled_report(&state, 3).await;
        assert_eq!(snapshot["redis"]["unmatched"].as_array().unwrap().len(), 1);
        assert_eq!(
            fs::read(f.victim.join("dependencies.jsonl")).unwrap(),
            before
        );
        task.abort();
    }
}

#[tokio::test]
async fn redis_api_origin_keeps_current_business_order_and_exact_arguments() {
    for lazy in [false, true] {
        let f = Fixture::new();
        let (addr, _state, task) = f.spawn(lazy, f.rules()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        request(
            &mut client,
            &["ZADD", "presence:7", "100", "client-away"],
            ERROR,
        )
        .await;
        client = TcpStream::connect(addr).await.unwrap();
        request(
            &mut client,
            &["ZREM", "presence:8", "client-active", "client-away"],
            ERROR,
        )
        .await;
        client = TcpStream::connect(addr).await.unwrap();
        request(
            &mut client,
            &["ZREM", "presence:7", "client-active", "client-away"],
            b":1\r\n",
        )
        .await;
        request(
            &mut client,
            &["ZREM", "presence:7", "client-active", "client-away"],
            ERROR,
        )
        .await;
        client = TcpStream::connect(addr).await.unwrap();
        request(
            &mut client,
            &["ZADD", "presence:7", "101", "client-away"],
            ERROR,
        )
        .await;
        client = TcpStream::connect(addr).await.unwrap();
        request(
            &mut client,
            &["ZADD", "presence:7", "100", "client-away"],
            b":1\r\n",
        )
        .await;
        task.abort();
    }
}

#[tokio::test]
async fn redis_api_origin_missing_ambiguous_owned_and_stateful_evidence_stays_strict() {
    for lazy in [false, true] {
        for mode in 0..8 {
            let f = Fixture::new();
            let mut records = f.records();
            let mut rules = f.rules();
            match mode {
                0 => rules.clear(),
                1 => f.write(&f.origin, &[]),
                2 => f.write(&f.origin, &[Fixture::insert(12), Fixture::insert(13)]),
                3 => {
                    let path = f.victim.join("request.json");
                    let mut request: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    request["uri"] = "/jobs/12".into();
                    fs::write(path, request.to_string()).unwrap();
                }
                4 => records[0]["timestamp"] = "2026-10-12T10:59:59Z".into(),
                5 => records[0]["args"] = json!([capture_json(b"job:99")]),
                6 => records.push(f.command(7, "CLIENT", &["ID"], b":9\r\n")),
                7 => {
                    let path = f.origin.join("request.json");
                    let mut request: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    request["body"] = capture_json(br#"{"background":false}"#);
                    fs::write(path, request.to_string()).unwrap();
                }
                _ => unreachable!(),
            }
            f.write(&f.victim, &records);
            let (addr, state, task) = f.spawn(lazy, rules).await;
            let mut client = TcpStream::connect(addr).await.unwrap();
            request(
                &mut client,
                &["ZREM", "presence:7", "client-active", "client-away"],
                ERROR,
            )
            .await;
            let snapshot = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
            assert_eq!(
                snapshot["redis"]["unmatched"][0]["diagnostic"]["kind"], "lane_blocked",
                "mode={mode}, lazy={lazy}"
            );
            assert_eq!(
                snapshot["redis"]["unmatched"][0]["diagnostic"]["blocked_by"]["sequence"],
                1
            );
            task.abort();
        }
    }
}
