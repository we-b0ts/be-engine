use super::*;
use crate::redis::encode_array;
use base64::Engine as _;
use serde_json::{Value, json};

const HOST: &str = "30b6569f34c2486dafd3bf29b09a071f";

fn ack(id: u64) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"method":"callback","host_id":HOST,"sid":"peer","namespace":"/rpc", "id":id,
        "args":[{"success":false,"exit_code":7,"stderr":"example failure"}]}),
    )
    .unwrap()
}

async fn receive(client: &mut TcpStream, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, expected);
}

#[tokio::test]
async fn rpc_callback_retains_publish_case_across_connections_while_admitted() {
    exercise_rpc(false).await;
}

#[tokio::test]
async fn unanswered_rpc_does_not_block_drain_and_late_callback_cannot_reopen_case() {
    exercise_rpc(true).await;
}

async fn exercise_rpc(close_origin: bool) {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut subscriber, proxy_sub) = tcp_pair().await;
    let (mut redis_sub, upstream_sub) = tcp_pair().await;
    let sub_task = spawn_handler(
        proxy_sub,
        upstream_sub,
        state.clone(),
        redis_sub.peer_addr().unwrap(),
    );
    forward_test_exchange(
        &mut subscriber,
        &mut redis_sub,
        &encode_array(&[b"SUBSCRIBE", b"custom.bus"]),
        b"*3\r\n$9\r\nsubscribe\r\n$10\r\ncustom.bus\r\n:1\r\n",
    )
    .await;

    let first = test_case("rpc-origin");
    let mut guard = Some(state.try_reserve_active_case(first.clone()).unwrap());
    state
        .activate_case_dependencies(guard.as_ref().unwrap())
        .unwrap();
    let (mut publisher, proxy_pub) = tcp_pair().await;
    let (mut redis_pub, upstream_pub) = tcp_pair().await;
    let pub_task = spawn_handler(
        proxy_pub,
        upstream_pub,
        state.clone(),
        redis_pub.peer_addr().unwrap(),
    );
    let request=serde_json::to_vec(&json!({"method":"emit","event":"custom:rpc","data":[{"argv":["example"]}],
        "binary":false,"namespace":"/rpc","room":"peer","skip_sid":null,"callback":["peer","/rpc",1],"host_id":HOST})).unwrap();
    forward_test_exchange(
        &mut publisher,
        &mut redis_pub,
        &encode_array(&[b"PUBLISH", b"custom.bus", &request]),
        b":1\r\n",
    )
    .await;
    state.recorder().flush_all_dependency_files().await.unwrap();
    // PUBLISH has completed. Correlation metadata must not keep a command in flight.
    assert_eq!(
        state
            .inner
            .active_cases
            .dependency_activity(first.id)
            .unwrap()
            .0,
        0
    );
    let second = test_case("unrelated");
    let _second_guard = if close_origin {
        assert_eq!(
            state
                .inner
                .active_cases
                .drain_case_dependencies(first.id, Duration::ZERO, Duration::from_millis(30))
                .await,
            crate::active_case::DependencyDrainResult::Drained
        );
        state.recorder().publish_case(&first).await.unwrap();
        drop(guard.take());
        let next = state.try_reserve_active_case(second.clone()).unwrap();
        state.activate_case_dependencies(&next).unwrap();
        Some(next)
    } else {
        None
    };
    let unrelated = encode_array(&[b"message", b"custom.bus", &ack(99)]);
    redis_sub.write_all(&unrelated).await.unwrap();
    receive(&mut subscriber, &unrelated).await;
    let reply = encode_array(&[b"message", b"custom.bus", &ack(1)]);
    redis_sub.write_all(&reply).await.unwrap();
    receive(&mut subscriber, &reply).await;
    // Drain the source clients so their writer tasks finish publishing evidence.
    drop(subscriber);
    drop(publisher);
    drop(redis_sub);
    drop(redis_pub);
    tokio::time::timeout(Duration::from_secs(2), sub_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), pub_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    state.recorder().flush_all_dependency_files().await.unwrap();
    let original = state
        .recorder()
        .case_staging_dir(&first)
        .join("dependencies.jsonl");
    let original = if close_origin {
        assert!(
            !original.parent().unwrap().exists(),
            "late callback recreated finalized staging"
        );
        state.recorder().case_dir(&first).join("dependencies.jsonl")
    } else {
        original
    };
    if !close_origin {
        state
            .recorder()
            .flush_case_dependency_files(&state.recorder().case_staging_dir(&first))
            .await
            .unwrap();
    }
    let raw = crate::recorder::test_io::read_to_string(original)
        .await
        .unwrap();
    let events: Vec<Value> = raw
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let request = events.iter().find(|e| e["command"] == "PUBLISH").unwrap();
    let global = crate::recorder::test_io::read_to_string(
        state
            .recorder()
            .run_dir
            .join("indexes/unattributed-scope.json"),
    )
    .await
    .unwrap();
    let global_events: Vec<Value> = global
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    if close_origin {
        assert!(
            !events
                .iter()
                .any(|event| event["event_type"] == "redis_pub_sub_push")
        );
    }
    let reply = if close_origin {
        &global_events
    } else {
        &events
    }
    .iter()
    .find(|e| e["event_type"] == "redis_pub_sub_push" && e.get("rpc_request").is_some())
    .unwrap();
    assert_eq!(
        reply["rpc_request"]["connection_id"],
        request["connection_id"]
    );
    assert_eq!(reply["rpc_request"]["sequence"], request["sequence"]);
    assert_ne!(reply["connection_id"], request["connection_id"]);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(reply["response"]["data"].as_str().unwrap())
        .unwrap();
    let parsed = crate::redis::parse_pubsub_push(&bytes).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&parsed.payload).unwrap()["args"][0]["exit_code"],
        7
    );
    let global = crate::recorder::test_io::read_to_string(
        state
            .recorder()
            .run_dir
            .join("indexes/unattributed-scope.json"),
    )
    .await
    .unwrap();
    assert!(global.lines().any(|l| {
        let v: Value = serde_json::from_str(l).unwrap();
        v["event_type"] == "redis_pub_sub_push" && v.get("rpc_request").is_none()
    }));
    let current = state
        .recorder()
        .case_staging_dir(&second)
        .join("dependencies.jsonl");
    if let Ok(raw) = crate::recorder::test_io::read_to_string(current).await {
        assert!(!raw.contains("redis_pub_sub_push"));
    }
}

#[tokio::test]
async fn generic_binary_pubsub_capture_is_semantic_evidence_with_no_rpc_adapter() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy) = tcp_pair().await;
    let (mut redis, upstream) = tcp_pair().await;
    let task = spawn_handler(proxy, upstream, state.clone(), redis.peer_addr().unwrap());
    forward_test_exchange(
        &mut client,
        &mut redis,
        &encode_array(&[b"PSUBSCRIBE", b"events.*"]),
        b"*3\r\n$10\r\npsubscribe\r\n$8\r\nevents.*\r\n:1\r\n",
    )
    .await;
    let notification = encode_array(&[b"pmessage", b"events.*", b"events.one", b"\x00\xff\x01"]);
    redis.write_all(&notification).await.unwrap();
    receive(&mut client, &notification).await;
    drop(client);
    drop(redis);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    state.recorder().flush_all_dependency_files().await.unwrap();
    let raw = crate::recorder::test_io::read_to_string(
        state
            .recorder()
            .run_dir
            .join("indexes/unattributed-scope.json"),
    )
    .await
    .unwrap();
    let event: Value = raw
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|e| e["event_type"] == "redis_pub_sub_push")
        .unwrap();
    assert!(event.get("rpc_request").is_none());
    assert_eq!(event["subscription_sequence"], 1);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(event["response"]["data"].as_str().unwrap())
            .unwrap(),
        notification
    );
}

#[tokio::test]
async fn idle_rpc_and_ordinary_publish_are_retained_without_inventing_an_owner() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    assert!(state.inner.active_cases.close_bootstrap());
    let (mut subscriber, proxy_sub) = tcp_pair().await;
    let (mut redis_sub, upstream_sub) = tcp_pair().await;
    let sub_task = spawn_handler(
        proxy_sub,
        upstream_sub,
        state.clone(),
        redis_sub.peer_addr().unwrap(),
    );
    forward_test_exchange(
        &mut subscriber,
        &mut redis_sub,
        &encode_array(&[b"SUBSCRIBE", b"custom.bus"]),
        b"*3\r\n$9\r\nsubscribe\r\n$10\r\ncustom.bus\r\n:1\r\n",
    )
    .await;
    let (mut publisher, proxy_pub) = tcp_pair().await;
    let (mut redis_pub, upstream_pub) = tcp_pair().await;
    let pub_task = spawn_handler(
        proxy_pub,
        upstream_pub,
        state.clone(),
        redis_pub.peer_addr().unwrap(),
    );
    forward_test_exchange(
        &mut publisher,
        &mut redis_pub,
        &encode_array(&[b"PUBLISH", b"custom.bus", b"ordinary-message"]),
        b":1\r\n",
    )
    .await;
    let payload = serde_json::to_vec(&json!({"method":"emit","event":"custom:rpc","data":[],
        "binary":false,"namespace":"/rpc","room":"peer","skip_sid":null,
        "callback":["peer","/rpc",1],"host_id":HOST}))
    .unwrap();
    forward_test_exchange(
        &mut publisher,
        &mut redis_pub,
        &encode_array(&[b"PUBLISH", b"custom.bus", &payload]),
        b":1\r\n",
    )
    .await;
    let reply = encode_array(&[b"message", b"custom.bus", &ack(1)]);
    redis_sub.write_all(&reply).await.unwrap();
    receive(&mut subscriber, &reply).await;
    drop(subscriber);
    drop(publisher);
    drop(redis_sub);
    drop(redis_pub);
    tokio::time::timeout(Duration::from_secs(2), sub_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), pub_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    state.recorder().flush_all_dependency_files().await.unwrap();
    let raw = crate::recorder::test_io::read_to_string(
        state
            .recorder()
            .run_dir
            .join("indexes/unattributed-scope.json"),
    )
    .await
    .unwrap();
    let events: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let publishes: Vec<_> = events
        .iter()
        .filter(|event| event["command"] == "PUBLISH")
        .collect();
    assert_eq!(publishes.len(), 2);
    assert!(
        publishes
            .iter()
            .all(|event| event["capture"]["attribution"]["kind"] == "unattributed")
    );
    let request = publishes
        .iter()
        .find(|event| event["sequence"] == 2)
        .unwrap();
    assert_eq!(request["sequence"], 2);
    assert_eq!(request["rpc_callback_capture"], "bounded_window");
    assert_eq!(request["capture"]["attribution"]["kind"], "unattributed");
    let callback = events
        .iter()
        .find(|event| event["event_type"] == "redis_pub_sub_push")
        .unwrap();
    assert_eq!(
        callback["rpc_request"]["connection_id"],
        request["connection_id"]
    );
    assert_eq!(callback["rpc_request"]["sequence"], request["sequence"]);
    assert!(callback["rpc_request"].get("case_id").is_none());
}
