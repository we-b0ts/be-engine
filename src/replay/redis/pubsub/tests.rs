use super::*;
use crate::replay::{ReplayConfig, ReplayDependencyLoading, ReplayLifecycleConfig, ReplayRuntime};
use serde_json::{Value, json};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
mod adapter_echo;
mod broadcast;
mod cancellation;
mod case_inputs;
mod compact_evidence;
mod connection_scope;
mod echo_preparation;
mod input_timing;
mod namespace_sessions;
mod native_clock;
mod repeated_echo;
mod request_contracts;
mod rpc_coverage;
mod rpc_identity_formats;
mod rpc_ingress;
mod scale;
mod subject_delivery;
mod subscriber_generations;
mod subscription_evidence;
mod unused_identity;
mod value_delivery;

const SOURCE: &str = "30b6569f34c2486dafd3bf29b09a071f";
const TARGET: &str = "59629c1606fa4011b698ef82621b84b5";

fn capture(bytes: &[u8]) -> Value {
    json!({"encoding":"base64","data":STANDARD.encode(bytes),"truncated":false})
}

fn request(host: &str, id: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({"method":"emit","event":"example:run","data":[{"argv":["pwd"]}],
        "binary":false,"namespace":"/rpc","room":"peer","skip_sid":null,"callback":["peer","/rpc",id],"host_id":host})).unwrap()
}

fn callback(host: &str, id: u64) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"method":"callback","host_id":host,"sid":"peer","namespace":"/rpc", "id":id,
        "args":[{"success":true,"stdout":"example result","exit_code":0}]}),
    )
    .unwrap()
}

fn exchange(
    connection: Uuid,
    sequence: u64,
    command: &str,
    args: &[&[u8]],
    response: &[u8],
) -> Value {
    json!({"event_type":"redis_exchange","connection_id":connection,"sequence":sequence,
        "target_host":"redis.test","target_port":6379,"database":0,"username":null,"resp_version":2,
        "command":command,"args":args.iter().map(|v|capture(v)).collect::<Vec<_>>(),"response":capture(response),
        "response_kind":if command == "PUBLISH" {"integer"}else{"array"},"duration_ms":0,"replay_safe":true})
}

fn push(subscription: Uuid, publisher: Option<Uuid>, raw: &[u8], delay: u64) -> Value {
    let mut value = json!({"event_type":"redis_pub_sub_push","connection_id":subscription,"subscription_sequence":1,
        "target_host":"redis.test","target_port":6379,"database":0,"username":null,
        "response":capture(raw),"duration_ms":delay,"replay_safe":true});
    if let Some(connection) = publisher {
        value["rpc_request"] = json!({"connection_id":connection,"sequence":1});
    }
    value
}

async fn runtime(
    root: &Path,
    cases: &[Value],
    globals: &[Value],
    lazy: bool,
) -> Result<Arc<ReplayRuntime>> {
    let case = root.join("case");
    tokio::fs::create_dir_all(&case).await?;
    let jsonl = |records: &[Value]| records.iter().map(|v| format!("{v}\n")).collect::<String>();
    tokio::fs::write(case.join("dependencies.jsonl"), jsonl(cases)).await?;
    tokio::fs::write(root.join("global-dependencies.jsonl"), jsonl(globals)).await?;
    load_runtime(root, lazy).await
}

async fn load_runtime(root: &Path, lazy: bool) -> Result<Arc<ReplayRuntime>> {
    let case = root.join("case");
    crate::replay::write_test_recording_network_manifest(root);
    let addr = "127.0.0.1:0".parse().unwrap();
    Ok(Arc::new(
        ReplayRuntime::load_with_lifecycle(
            ReplayConfig {
                case_dir: case,
                selected_case_ids: vec![],
                dns_listen: addr,
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(root.join("ca.pem")),
                ca_key_path: Some(root.join("ca-key.pem")),
                policy_path: root
                    .join(".traffic-e2e/policy.yaml")
                    .is_file()
                    .then(|| root.join(".traffic-e2e/policy.yaml")),
                http_ignore_query_params: vec![],
                process_owned_dependencies: vec![],
                allowed_unused_http: None,
            },
            addr,
            addr,
            ReplayLifecycleConfig {
                dependency_loading: ReplayDependencyLoading {
                    lazy_cases: lazy,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?,
    ))
}

async fn connect(
    runtime: &Arc<ReplayRuntime>,
) -> (
    RedisBufferedReader<TcpStream>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    (RedisBufferedReader::new(stream, 1024 * 1024), task)
}

async fn send(reader: &mut RedisBufferedReader<TcpStream>, parts: &[&[u8]]) -> Vec<u8> {
    reader
        .inner
        .write_all(&crate::redis::encode_array(parts))
        .await
        .unwrap();
    read(reader).await
}

async fn send_unmatched(reader: &mut RedisBufferedReader<TcpStream>, parts: &[&[u8]]) {
    reader
        .inner
        .write_all(&crate::redis::encode_array(parts))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), read_redis_frame(reader))
            .await
            .expect("unmatched command must close its Redis connection")
            .unwrap()
            .is_none()
    );
}

async fn reconnect(
    runtime: &Arc<ReplayRuntime>,
    reader: &mut RedisBufferedReader<TcpStream>,
    task: &mut tokio::task::JoinHandle<Result<()>>,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), &mut *task)
        .await
        .expect("rejected Redis connection must finish cleanup")
        .unwrap()
        .unwrap();
    (*reader, *task) = connect(runtime).await;
}

async fn read(reader: &mut RedisBufferedReader<TcpStream>) -> Vec<u8> {
    tokio::time::timeout(std::time::Duration::from_secs(2), read_redis_frame(reader))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .raw
        .to_vec()
}

#[tokio::test]
async fn rpc_ack_crosses_real_connections_and_maps_only_protocol_identities() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let source_request = request(SOURCE, 1);
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
        let runtime = runtime(
            temp.path(),
            &[
                exchange(
                    publisher,
                    1,
                    "PUBLISH",
                    &[b"jobs", &source_request],
                    b":2\r\n",
                ),
                push(sub, Some(publisher), &raw, 40),
            ],
            &[exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed)],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, mut client_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        let mut wrong: Value = serde_json::from_slice(&request(TARGET, 9)).unwrap();
        wrong["data"][0]["argv"] = json!(["changed-command"]);
        send_unmatched(
            &mut client,
            &[b"PUBLISH", b"jobs", &serde_json::to_vec(&wrong).unwrap()],
        )
        .await;
        reconnect(&runtime, &mut client, &mut client_task).await;
        let started = std::time::Instant::now();
        {
            let state = runtime.state.lock().await;
            let exchange = state
                .redis
                .exchanges
                .iter()
                .find(|e| e.record.command == "PUBLISH")
                .unwrap();
            assert_eq!(
                state
                    .redis
                    .pubsub
                    .matches(exchange, &[b"jobs".to_vec(), request(TARGET, 9)]),
                Some(true),
                "lazy={lazy}, active={:?}, case={:?}, status={:?}, rpc={:?}",
                state.active_case_id,
                exchange.case_id,
                exchange.status,
                exchange.rpc_push
            );
        }
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":2\r\n"
        );
        assert_eq!(
            runtime.state.lock().await.redis.events.matched_count,
            1,
            "PUBLISH waits for its ACK"
        );
        let raw = read(&mut subscriber).await;
        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
        let message = parse_pubsub_push(&raw).unwrap().unwrap();
        let (identity, value) = rpc::callback(&message.payload).unwrap().unwrap();
        assert_eq!(identity.host, TARGET);
        assert_eq!(identity.id, 9);
        assert_eq!(value["args"][0]["stdout"], "example result");
        // Successful delivery releases the finite call, but cannot replenish it.
        send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await;
        let snapshot = runtime.state.lock().await.redis.snapshot();
        assert_eq!(snapshot.matched_count, 2);
        assert!(snapshot.unused_case.is_empty());
        sub_task.abort();
        client_task.abort();
    }
}

#[tokio::test]
async fn generic_pubsub_replays_binary_message_pattern_and_shard_notifications() {
    for (command, confirmation, parts) in [
        (
            "SUBSCRIBE",
            b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n".as_slice(),
            vec![b"message".as_slice(), b"jobs", b"\x00\xffpayload"],
        ),
        (
            "PSUBSCRIBE",
            b"*3\r\n$10\r\npsubscribe\r\n$4\r\njobs\r\n:1\r\n".as_slice(),
            vec![b"pmessage".as_slice(), b"jobs", b"jobs", b"\x00\xffpayload"],
        ),
        (
            "SSUBSCRIBE",
            b"*3\r\n$10\r\nssubscribe\r\n$4\r\njobs\r\n:1\r\n".as_slice(),
            vec![b"smessage".as_slice(), b"jobs", b"\x00\xffpayload"],
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let raw = crate::redis::encode_array(&parts);
        let runtime = runtime(
            temp.path(),
            &[],
            &[
                exchange(sub, 1, command, &[b"jobs"], confirmation),
                push(sub, None, &raw, 10),
            ],
            true,
        )
        .await
        .unwrap();
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut client, &[command.as_bytes(), b"jobs"]).await,
            confirmation
        );
        assert_eq!(read(&mut client).await, raw);
        assert!(
            runtime
                .state
                .lock()
                .await
                .redis
                .pubsub
                .unused(ReplaySource::Startup)
                .is_empty()
        );
        task.abort();
    }
}

#[tokio::test]
async fn historical_rpc_without_ack_requires_recording_refresh() {
    let temp = tempfile::tempdir().unwrap();
    let result = runtime(
        temp.path(),
        &[exchange(
            Uuid::new_v4(),
            1,
            "PUBLISH",
            &[b"jobs", &request(SOURCE, 1)],
            b":2\r\n",
        )],
        &[],
        true,
    )
    .await;
    let error = result.err().expect("missing ACK must fail loading");
    assert!(
        error.to_string().contains("refresh the recording"),
        "{error:#}"
    );
}

#[tokio::test]
async fn unsubscribing_cancels_scheduled_notification() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let removed = b"*3\r\n$11\r\nunsubscribe\r\n$4\r\njobs\r\n:0\r\n";
    let raw = crate::redis::encode_array(&[b"message", b"jobs", b"notification"]);
    let runtime = runtime(
        temp.path(),
        &[],
        &[
            exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed),
            exchange(sub, 2, "UNSUBSCRIBE", &[b"jobs"], removed),
            push(sub, None, &raw, 50),
        ],
        false,
    )
    .await
    .unwrap();
    let (mut client, task) = connect(&runtime).await;
    assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, confirmed);
    assert_eq!(send(&mut client, &[b"UNSUBSCRIBE", b"jobs"]).await, removed);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_redis_frame(&mut client)
        )
        .await
        .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn rpc_callback_counters_are_bijective_and_failure_results_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let publisher = Uuid::new_v4();
    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let first = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
    let mut failure: Value = serde_json::from_slice(&callback(SOURCE, 2)).unwrap();
    failure["args"][0] = json!({"success":false,"exit_code":7,"stderr":"example failure"});
    let second =
        crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(&failure).unwrap()]);
    let mut second_push = push(sub, Some(publisher), &second, 10);
    second_push["rpc_request"]["sequence"] = 2.into();
    let runtime = runtime(
        temp.path(),
        &[
            exchange(
                publisher,
                1,
                "PUBLISH",
                &[b"jobs", &request(SOURCE, 1)],
                b":1\r\n",
            ),
            push(sub, Some(publisher), &first, 10),
            exchange(
                publisher,
                2,
                "PUBLISH",
                &[b"jobs", &request(SOURCE, 2)],
                b":1\r\n",
            ),
            second_push,
        ],
        &[exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmation)],
        true,
    )
    .await
    .unwrap();
    let (mut subscriber, sub_task) = connect(&runtime).await;
    let (mut client, mut task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        confirmation
    );
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
        b":1\r\n"
    );
    read(&mut subscriber).await;
    send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await;
    reconnect(&runtime, &mut client, &mut task).await;
    let changed_host = Uuid::new_v4().simple().to_string();
    send_unmatched(
        &mut client,
        &[b"PUBLISH", b"jobs", &request(&changed_host, 10)],
    )
    .await;
    reconnect(&runtime, &mut client, &mut task).await;
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 10)]).await,
        b":1\r\n"
    );
    let raw = read(&mut subscriber).await;
    let payload = parse_pubsub_push(&raw).unwrap().unwrap().payload;
    let (identity, value) = rpc::callback(&payload).unwrap().unwrap();
    assert_eq!(identity.id, 10);
    assert_eq!(value["args"], failure["args"]);
    let state = runtime.state.lock().await;
    assert!(state.redis.snapshot().unused_case.is_empty());
    let report = state.redis.pubsub.report().unwrap();
    assert_eq!(report.delivered_rpc_callbacks, 2);
    task.abort();
    sub_task.abort();
}

#[tokio::test]
async fn rpc_callback_cannot_escape_its_case_or_a_disconnected_subscriber() {
    for disconnect in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
        let runtime = runtime(
            temp.path(),
            &[
                exchange(
                    publisher,
                    1,
                    "PUBLISH",
                    &[b"jobs", &request(SOURCE, 1)],
                    b":1\r\n",
                ),
                push(sub, Some(publisher), &raw, 50),
            ],
            &[exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmation)],
            false,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmation
        );
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":1\r\n"
        );
        if disconnect {
            drop(subscriber);
            tokio::time::timeout(std::time::Duration::from_secs(1), sub_task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        } else {
            runtime.state.lock().await.active_case_id = None;
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    read_redis_frame(&mut subscriber)
                )
                .await
                .is_err()
            );
            sub_task.abort();
        }
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let state = runtime.state.lock().await;
        let snapshot = state.redis.snapshot();
        assert_eq!(snapshot.matched_count, 1);
        assert!(!snapshot.unused_case.is_empty());
        assert!(!snapshot.unsafe_events.is_empty());
        assert_eq!(snapshot.pubsub.unwrap().failed_pushes, 1);
        task.abort();
    }
}

#[tokio::test]
async fn inconsistent_or_duplicate_rpc_callback_evidence_is_rejected() {
    for mode in [
        "duplicate",
        "wrong_channel",
        "wrong_identity",
        "truncated",
        "unsafe",
        "orphan",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let payload = callback(SOURCE, if mode == "wrong_identity" { 2 } else { 1 });
        let raw = crate::redis::encode_array(&[
            b"message",
            if mode == "wrong_channel" {
                b"other"
            } else {
                b"jobs"
            },
            &payload,
        ]);
        let mut notification = push(sub, Some(publisher), &raw, 10);
        if mode == "truncated" {
            notification["response"]["truncated"] = true.into();
        }
        if mode == "unsafe" {
            notification["replay_safe"] = false.into();
        }
        if mode == "orphan" {
            notification["rpc_request"]["sequence"] = 2.into();
        }
        let mut cases = vec![
            exchange(
                publisher,
                1,
                "PUBLISH",
                &[b"jobs", &request(SOURCE, 1)],
                b":1\r\n",
            ),
            notification.clone(),
        ];
        if mode == "duplicate" {
            cases.push(notification);
        }
        assert!(
            runtime(temp.path(), &cases, &[], true).await.is_err(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn generic_push_requires_matching_subscription_evidence() {
    for mode in ["missing", "wrong_subject", "wrong_kind", "wrong_session"] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let raw = if mode == "wrong_kind" {
            crate::redis::encode_array(&[b"smessage", b"jobs", b"notification"])
        } else {
            crate::redis::encode_array(&[
                b"message",
                if mode == "wrong_subject" {
                    b"other"
                } else {
                    b"jobs"
                },
                b"notification",
            ])
        };
        let mut notification = push(sub, None, &raw, 10);
        if mode == "wrong_session" {
            notification["database"] = 1.into();
        }
        let mut globals = vec![notification];
        if mode != "missing" {
            globals.push(exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmation));
        }
        assert!(
            runtime(temp.path(), &[], &globals, true).await.is_err(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn rpc_subscriber_can_confirm_while_call_is_pending_before_ack_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let publisher = Uuid::new_v4();
    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
    let runtime = runtime(
        temp.path(),
        &[
            exchange(
                publisher,
                1,
                "PUBLISH",
                &[b"jobs", &request(SOURCE, 1)],
                b":1\r\n",
            ),
            push(sub, Some(publisher), &raw, 200),
        ],
        &[exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmation)],
        true,
    )
    .await
    .unwrap();
    crate::replay::deferred::prepare_case(runtime.state.clone(), "case")
        .await
        .unwrap();
    use crate::replay::control::dependency_tail::{RecordedReference, references_consumed};
    let references = [
        RecordedReference::Redis {
            connection_id: publisher,
            sequence: 1,
        },
        RecordedReference::RedisRpcPush {
            connection_id: publisher,
            sequence: 1,
        },
    ];
    assert!(!references_consumed(&*runtime.state.lock().await, "case", &references).unwrap());
    let (mut client, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
        b":1\r\n"
    );
    assert!(
        !references_consumed(&*runtime.state.lock().await, "case", &references).unwrap(),
        "publisher acknowledgement cannot discharge the independent callback delivery"
    );
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let (mut subscriber, sub_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        confirmation
    );
    let raw = read(&mut subscriber).await;
    let payload = parse_pubsub_push(&raw).unwrap().unwrap().payload;
    assert_eq!(rpc::callback(&payload).unwrap().unwrap().0.host, TARGET);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if references_consumed(&*runtime.state.lock().await, "case", &references).unwrap() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    assert!(state.redis.snapshot().unused_case.is_empty());
    task.abort();
    sub_task.abort();
}
