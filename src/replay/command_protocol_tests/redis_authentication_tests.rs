use super::*;

async fn read_line(client: &mut TcpStream) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n") {
            response.push(client.read_u8().await.unwrap());
        }
        String::from_utf8(response).unwrap()
    })
    .await
    .expect("Redis response timed out")
}

#[tokio::test]
async fn reports_unobserved_redis_authentication_and_allows_authentication_then_retry() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "private-key", b"$1\r\n1\r\n");
    dependency["username"] = serde_json::json!("default");
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_vec(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let get = b"*2\r\n$3\r\nGET\r\n$11\r\nprivate-key\r\n";

    // PING alone does not establish authentication or consume business evidence.
    client.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
    assert_eq!(read_line(&mut client).await, "+PONG\r\n");
    client.write_all(get).await.unwrap();
    let response = read_line(&mut client).await;
    assert!(response.starts_with("-ERR Redis authentication state mismatch:"));
    assert!(response.contains("target authentication was not observed"));
    assert!(response.contains("whether it is passed to the Redis client"));
    assert!(!response.contains("password is missing"));

    let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
    let event = &report["redis"]["unmatched"][0];
    assert_eq!(
        event["diagnostic"]["fields"],
        serde_json::json!(["authentication_not_observed"])
    );
    assert_eq!(
        response,
        format!("-ERR {}\r\n", event["reason"].as_str().unwrap())
    );
    assert_eq!(report["redis"]["unused_case"].as_array().unwrap().len(), 1);
    assert!(!event.to_string().contains("private-key"));

    client
        .write_all(b"*2\r\n$4\r\nAUTH\r\n$14\r\nfixture-secret\r\n")
        .await
        .unwrap();
    assert_eq!(read_line(&mut client).await, "+OK\r\n");
    client.write_all(get).await.unwrap();
    let mut response = [0; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"$1\r\n1\r\n");
    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    // A later successful retry does not erase the earlier mismatch.
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 1);
    assert!(!report.to_string().contains("fixture-secret"));
    task.abort();
}

#[tokio::test]
async fn other_redis_mismatches_do_not_claim_missing_authentication() {
    for (field, value, authenticate) in [
        ("database", serde_json::json!(1), false),
        ("resp_version", serde_json::json!(3), false),
        ("command", serde_json::json!("EXISTS"), false),
        (
            "args",
            serde_json::json!([{"encoding": "utf8", "data": "other-key"}]),
            false,
        ),
        ("username", serde_json::json!("another-user"), true),
        ("username", serde_json::Value::Null, true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"$1\r\n1\r\n");
        dependency["username"] = serde_json::json!("default");
        dependency[field] = value;
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            serde_json::to_vec(&dependency).unwrap(),
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        if authenticate {
            client
                .write_all(b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut client).await, "+OK\r\n");
        }
        client
            .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut client).await,
            "-ERR no recorded Redis dependency matched\r\n",
            "{field}"
        );
        let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
        assert!(
            !report["redis"]["unmatched"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("authentication state mismatch"),
            "{field}"
        );
        task.abort();
    }
}
