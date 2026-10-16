use super::*;

fn exchange(
    connection: Uuid,
    sequence: u64,
    command: &str,
    args: &[&str],
    response: &[u8],
) -> Value {
    let mut record = redis_dependency(connection, sequence, "unused", response);
    record["command"] = command.into();
    record["args"] = args
        .iter()
        .map(|arg| capture_json(arg.as_bytes()))
        .collect();
    record["response_kind"] = match response[0] {
        b'+' => "simple_string",
        b'-' => "error",
        b'*' => "array",
        b':' => "integer",
        _ => "bulk_string",
    }
    .into();
    record
}

fn request(args: &[&str]) -> Vec<u8> {
    let mut bytes = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        bytes.extend_from_slice(format!("${}\r\n{arg}\r\n", arg.len()).as_bytes());
    }
    bytes
}

async fn assert_reply(client: &mut TcpStream, args: &[&str], expected: &[u8]) {
    client.write_all(&request(args)).await.unwrap();
    let mut response = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, expected, "{args:?}");
}

async fn assert_unmatched(client: &mut TcpStream, args: &[&str]) {
    assert_reply(
        client,
        args,
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
}

async fn fixture(
    records: Vec<Value>,
) -> (
    crate::replay::policy::test_fixture::ManagedFixtureDirectory,
    PathBuf,
    SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case");
    tokio::fs::create_dir_all(&case).await.unwrap();
    tokio::fs::write(
        case.join("dependencies.jsonl"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .await
    .unwrap();
    let report = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case, Some(report.clone())).await;
    (temp, report, addr, task)
}

#[tokio::test]
async fn single_subject_unsubscriptions_replay_exact_confirmations_and_keep_connection_open() {
    for (subscribe, unsubscribe) in [
        ("SUBSCRIBE", "UNSUBSCRIBE"),
        ("PSUBSCRIBE", "PUNSUBSCRIBE"),
        ("SSUBSCRIBE", "SUNSUBSCRIBE"),
    ] {
        let connection = Uuid::new_v4();
        let subject = "celery-task-meta-task-id";
        let subscribe_response = format!(
            "*3\r\n${}\r\n{}\r\n${}\r\n{subject}\r\n:1\r\n",
            subscribe.len(),
            subscribe.to_ascii_lowercase(),
            subject.len()
        );
        let unsubscribe_response = format!(
            "*3\r\n${}\r\n{}\r\n${}\r\n{subject}\r\n:0\r\n",
            unsubscribe.len(),
            unsubscribe.to_ascii_lowercase(),
            subject.len()
        );
        let (_temp, report_path, addr, task) = fixture(vec![
            exchange(
                connection,
                1,
                subscribe,
                &[subject],
                subscribe_response.as_bytes(),
            ),
            exchange(
                connection,
                2,
                unsubscribe,
                &[subject],
                unsubscribe_response.as_bytes(),
            ),
            exchange(connection, 3, "GET", &["key"], b"$5\r\nvalue\r\n"),
        ])
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert_reply(
            &mut client,
            &[subscribe, subject],
            subscribe_response.as_bytes(),
        )
        .await;
        assert_reply(
            &mut client,
            &[unsubscribe, subject],
            unsubscribe_response.as_bytes(),
        )
        .await;
        assert_reply(&mut client, &["PING"], b"+PONG\r\n").await;
        assert_reply(&mut client, &["GET", "key"], b"$5\r\nvalue\r\n").await;
        let report = wait_for_matched_count(&report_path, "redis", 3).await;
        for field in ["unsupported", "unmatched", "unsafe_events", "unused_case"] {
            assert!(
                report["redis"][field].as_array().unwrap().is_empty(),
                "{field}"
            );
        }
        task.abort();
    }
}

#[tokio::test]
async fn unsubscription_retains_exact_arguments_and_stateful_lane_ownership() {
    let connection = Uuid::new_v4();
    let subscribe = b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n";
    let unsubscribe = b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:0\r\n";
    let (_temp, report_path, addr, task) = fixture(vec![
        exchange(connection, 1, "SUBSCRIBE", &["events"], subscribe),
        exchange(connection, 2, "UNSUBSCRIBE", &["events"], unsubscribe),
        exchange(connection, 3, "GET", &["key"], b"$5\r\nvalue\r\n"),
    ])
    .await;
    let mut owner = TcpStream::connect(addr).await.unwrap();
    let mut other = TcpStream::connect(addr).await.unwrap();
    assert_reply(&mut owner, &["SUBSCRIBE", "events"], subscribe).await;
    assert_unmatched(&mut other, &["UNSUBSCRIBE", "events"]).await;
    assert_unmatched(&mut owner, &["UNSUBSCRIBE", "other"]).await;
    assert_reply(&mut owner, &["UNSUBSCRIBE", "events"], unsubscribe).await;
    assert_unmatched(&mut other, &["GET", "key"]).await;
    assert_reply(&mut owner, &["GET", "key"], b"$5\r\nvalue\r\n").await;
    let report = wait_for_matched_count(&report_path, "redis", 3).await;
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        report["redis"]["unsupported"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn devices_style_short_source_connections_replay_on_one_pooled_connection() {
    let mut records = Vec::new();
    let mut expected = Vec::new();
    let mut requests = Vec::new();
    for index in 0..10 {
        let connection = Uuid::new_v4();
        // Old captures include rejected SDK announcements on each connection.
        // They must neither pin the lane nor count as a business dependency.
        for (sequence, field) in [(1, "LIB-NAME"), (2, "LIB-VER")] {
            records.push(exchange(
                connection,
                sequence,
                "CLIENT",
                &["SETINFO", field, "source-sdk"],
                b"-ERR unknown command\r\n",
            ));
        }
        let value = index.to_string();
        let (args, response) = if index == 6 || index == 9 {
            (
                vec!["MGET", "online-a", "online-b"],
                format!("*2\r\n$1\r\n{value}\r\n$-1\r\n"),
            )
        } else {
            // Repeated identical requests retain distinct recorded responses.
            (vec!["GET", "online"], format!("$1\r\n{value}\r\n"))
        };
        records.push(exchange(
            connection,
            3,
            args[0],
            &args[1..],
            response.as_bytes(),
        ));
        requests.extend(request(&args));
        expected.extend_from_slice(response.as_bytes());
    }
    let (_temp, report_path, addr, task) = fixture(records).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // Pipeline the actual RESP commands through one long-lived socket.
    client.write_all(&requests).await.unwrap();
    let mut response = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, expected);
    let report = wait_for_matched_count(&report_path, "redis", 10).await;
    assert_eq!(report["redis"]["connections"], 1);
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_unmatched(&mut client, &["GET", "online"]).await;
    let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
    assert_eq!(report["redis"]["matched_count"], 10);
    task.abort();
}

#[tokio::test]
async fn multiple_target_connections_preserve_source_order_and_share_finite_inventory() {
    let connection = Uuid::new_v4();
    let (_temp, report_path, addr, task) = fixture(vec![
        exchange(connection, 1, "SET", &["key", "value"], b"+OK\r\n"),
        exchange(connection, 2, "GET", &["key"], b"$5\r\nvalue\r\n"),
        exchange(connection, 3, "DEL", &["key"], b":1\r\n"),
    ])
    .await;
    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    assert_unmatched(&mut second, &["GET", "key"]).await;
    let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
    assert_eq!(
        report["redis"]["unmatched"][0]["diagnostic"]["kind"],
        "lane_blocked"
    );
    assert_reply(&mut first, &["SET", "key", "value"], b"+OK\r\n").await;
    assert_reply(&mut second, &["GET", "key"], b"$5\r\nvalue\r\n").await;
    drop(first);
    let mut third = TcpStream::connect(addr).await.unwrap();
    assert_reply(&mut third, &["DEL", "key"], b":1\r\n").await;
    assert_unmatched(&mut second, &["GET", "key"]).await;
    let report = wait_for_unmatched_count(&report_path, "redis", 2).await;
    assert_eq!(report["redis"]["matched_count"], 3);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn a_recorded_transaction_lane_is_owned_by_one_target_connection() {
    let transaction = Uuid::new_v4();
    let ordinary = Uuid::new_v4();
    let (_temp, report_path, addr, task) = fixture(vec![
        exchange(transaction, 1, "GET", &["before"], b"$1\r\n1\r\n"),
        exchange(transaction, 2, "WATCH", &["key"], b"+OK\r\n"),
        exchange(transaction, 3, "MULTI", &[], b"+OK\r\n"),
        exchange(transaction, 4, "GET", &["key"], b"+QUEUED\r\n"),
        exchange(transaction, 5, "EXEC", &[], b"*1\r\n$1\r\n2\r\n"),
        exchange(ordinary, 1, "GET", &["independent"], b"$1\r\n3\r\n"),
    ])
    .await;
    let mut owner = TcpStream::connect(addr).await.unwrap();
    let mut other = TcpStream::connect(addr).await.unwrap();
    // A later WATCH/MULTI in the recording pins the whole lane, even its prefix.
    assert_reply(&mut owner, &["GET", "before"], b"$1\r\n1\r\n").await;
    assert_unmatched(&mut other, &["WATCH", "key"]).await;
    assert_reply(&mut owner, &["WATCH", "key"], b"+OK\r\n").await;
    assert_reply(&mut owner, &["MULTI"], b"+OK\r\n").await;
    assert_unmatched(&mut other, &["GET", "key"]).await;
    assert_unmatched(&mut owner, &["GET", "independent"]).await;
    assert_reply(&mut owner, &["GET", "key"], b"+QUEUED\r\n").await;
    assert_reply(&mut owner, &["EXEC"], b"*1\r\n$1\r\n2\r\n").await;
    assert_reply(&mut other, &["GET", "independent"], b"$1\r\n3\r\n").await;
    let report = wait_for_matched_count(&report_path, "redis", 6).await;
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 3);
    for mismatch in report["redis"]["unmatched"].as_array().unwrap() {
        assert_eq!(
            mismatch["diagnostic"]["fields"],
            serde_json::json!(["connection"])
        );
    }
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn pool_compatibility_does_not_relax_database_or_authentication() {
    let mut records = vec![
        exchange(Uuid::new_v4(), 1, "GET", &["one"], b"$1\r\n1\r\n"),
        exchange(Uuid::new_v4(), 1, "GET", &["two"], b"$1\r\n2\r\n"),
    ];
    for record in &mut records {
        record["username"] = "alice".into();
        record["database"] = 2.into();
    }
    let (_temp, report_path, addr, task) = fixture(records).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert_reply(
        &mut client,
        &["AUTH", "alice", "fixture-password"],
        b"+OK\r\n",
    )
    .await;
    assert_unmatched(&mut client, &["GET", "one"]).await;
    assert_reply(&mut client, &["SELECT", "2"], b"+OK\r\n").await;
    assert_reply(&mut client, &["GET", "one"], b"$1\r\n1\r\n").await;
    assert_reply(
        &mut client,
        &["AUTH", "bob", "fixture-password"],
        b"+OK\r\n",
    )
    .await;
    assert_unmatched(&mut client, &["GET", "two"]).await;
    assert_reply(
        &mut client,
        &["AUTH", "alice", "fixture-password"],
        b"+OK\r\n",
    )
    .await;
    assert_reply(&mut client, &["GET", "two"], b"$1\r\n2\r\n").await;
    let report = wait_for_matched_count(&report_path, "redis", 2).await;
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 2);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn simultaneous_pool_requests_cannot_claim_the_same_exchange() {
    let mut record = exchange(Uuid::new_v4(), 1, "GET", &["key"], b"$1\r\n1\r\n");
    record["duration_ms"] = 50.into();
    let (_temp, report_path, addr, task) = fixture(vec![record]).await;
    async fn read(addr: SocketAddr) -> Vec<u8> {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&request(&["GET", "key"])).await.unwrap();
        let mut reader = crate::redis::BufferedReader::new(client, 1024);
        tokio::time::timeout(
            Duration::from_secs(5),
            crate::redis::read_frame(&mut reader),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .raw
        .to_vec()
    }
    let (first, second) = tokio::join!(read(addr), read(addr));
    let mut replies = [first, second];
    replies.sort();
    assert_eq!(
        replies,
        [
            b"$1\r\n1\r\n".to_vec(),
            b"-ERR no recorded Redis dependency matched\r\n".to_vec()
        ]
    );
    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 1);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn subscription_and_blocking_source_lanes_keep_connection_binding() {
    for (command, args, response) in [
        (
            "PSUBSCRIBE",
            vec!["events.*"],
            b"*3\r\n$10\r\npsubscribe\r\n$8\r\nevents.*\r\n:1\r\n".as_slice(),
        ),
        ("BLPOP", vec!["queue", "1"], b"*-1\r\n".as_slice()),
        ("WAIT", vec!["1", "10"], b":1\r\n".as_slice()),
        ("SCRIPT", vec!["DEBUG", "YES"], b"+OK\r\n".as_slice()),
        (
            "SCRIPT",
            vec!["UNKNOWN"],
            b"-ERR unknown subcommand\r\n".as_slice(),
        ),
        ("SCRIPT", vec![], b"-ERR missing subcommand\r\n".as_slice()),
        ("MODULE.UNKNOWN", vec!["value"], b"+OK\r\n".as_slice()),
    ] {
        let source = Uuid::new_v4();
        let (_temp, report_path, addr, task) = fixture(vec![
            exchange(source, 1, "GET", &["before"], b"$1\r\n1\r\n"),
            exchange(source, 2, command, &args, response),
        ])
        .await;
        let mut owner = TcpStream::connect(addr).await.unwrap();
        let mut other = TcpStream::connect(addr).await.unwrap();
        assert_reply(&mut owner, &["GET", "before"], b"$1\r\n1\r\n").await;
        let mut args = args;
        args.insert(0, command);
        assert_unmatched(&mut other, &args).await;
        assert_reply(&mut owner, &args, response).await;
        let report = wait_for_matched_count(&report_path, "redis", 2).await;
        assert_eq!(
            report["redis"]["unmatched"][0]["diagnostic"]["fields"],
            serde_json::json!(["connection"]),
            "{command}"
        );
        task.abort();
    }
}

#[tokio::test]
async fn script_commands_share_source_lane_across_target_connections() {
    for (command, args, response) in [
        ("EVAL", vec!["return 1", "0"], b":1\r\n".as_slice()),
        ("EVALSHA", vec!["script-sha", "0"], b":1\r\n".as_slice()),
        ("EVAL_RO", vec!["return 1", "0"], b":1\r\n".as_slice()),
        ("evalsha_ro", vec!["script-sha", "0"], b":1\r\n".as_slice()),
        (
            "script",
            vec!["load", "return 1"],
            b"$3\r\nsha\r\n".as_slice(),
        ),
        (
            "SCRIPT",
            vec!["EXISTS", "script-sha"],
            b"*1\r\n:1\r\n".as_slice(),
        ),
        ("SCRIPT", vec!["FLUSH", "ASYNC"], b"+OK\r\n".as_slice()),
        ("SCRIPT", vec!["KILL"], b"+OK\r\n".as_slice()),
        ("SCRIPT", vec!["HELP"], b"*1\r\n$4\r\nhelp\r\n".as_slice()),
    ] {
        let source = Uuid::new_v4();
        let (_temp, report_path, addr, task) = fixture(vec![
            exchange(source, 1, "GET", &["before"], b"$1\r\n1\r\n"),
            exchange(source, 2, command, &args, response),
            exchange(source, 3, "GET", &["after"], b"$1\r\n2\r\n"),
        ])
        .await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut request_args = args;
        request_args.insert(0, command);
        assert_unmatched(&mut second, &request_args).await;
        let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
        assert_eq!(
            report["redis"]["unmatched"][0]["diagnostic"]["kind"],
            "lane_blocked"
        );
        assert_reply(&mut first, &["GET", "before"], b"$1\r\n1\r\n").await;
        assert_reply(&mut second, &request_args, response).await;
        drop(first);
        let mut third = TcpStream::connect(addr).await.unwrap();
        assert_reply(&mut third, &["GET", "after"], b"$1\r\n2\r\n").await;
        assert_unmatched(&mut second, &request_args).await;
        let report = wait_for_unmatched_count(&report_path, "redis", 2).await;
        assert_eq!(report["redis"]["matched_count"], 3);
        assert!(
            report["redis"]["unused_case"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }
}

#[tokio::test]
async fn script_cache_miss_load_and_retry_replay_across_connections() {
    let source = Uuid::new_v4();
    let script = "return ARGV[1]";
    let sha = "0123456789abcdef0123456789abcdef0123456789";
    let loaded = format!("$40\r\n{sha}\r\n");
    let missing = b"-NOSCRIPT No matching script\r\n";
    let (_temp, report_path, addr, task) = fixture(vec![
        exchange(source, 1, "EVALSHA", &[sha, "0", "value"], missing),
        exchange(source, 2, "SCRIPT", &["LOAD", script], loaded.as_bytes()),
        exchange(
            source,
            3,
            "EVALSHA",
            &[sha, "0", "value"],
            b"$5\r\nvalue\r\n",
        ),
    ])
    .await;
    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut loader = TcpStream::connect(addr).await.unwrap();
    assert_reply(&mut first, &["EVALSHA", sha, "0", "value"], missing).await;
    assert_unmatched(&mut loader, &["EVALSHA", sha, "0", "value"]).await;
    assert_unmatched(&mut loader, &["SCRIPT", "LOAD", "return 'changed'"]).await;
    assert_reply(&mut loader, &["SCRIPT", "LOAD", script], loaded.as_bytes()).await;
    drop(first);
    let mut retry = TcpStream::connect(addr).await.unwrap();
    assert_unmatched(&mut retry, &["EVALSHA", "wrong-sha", "0", "value"]).await;
    assert_reply(
        &mut retry,
        &["EVALSHA", sha, "0", "value"],
        b"$5\r\nvalue\r\n",
    )
    .await;
    assert_unmatched(&mut loader, &["EVALSHA", sha, "0", "value"]).await;
    let report = wait_for_unmatched_count(&report_path, "redis", 4).await;
    assert_eq!(report["redis"]["matched_count"], 3);
    assert_eq!(
        report["redis"]["unmatched"][0]["diagnostic"]["kind"],
        "lane_blocked"
    );
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn script_commands_in_transaction_lanes_remain_connection_bound() {
    for command in ["EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO"] {
        let source = Uuid::new_v4();
        let script = if command.contains("SHA") {
            "script-sha"
        } else {
            "return 1"
        };
        let (_temp, report_path, addr, task) = fixture(vec![
            exchange(source, 1, "WATCH", &["key"], b"+OK\r\n"),
            exchange(source, 2, "MULTI", &[], b"+OK\r\n"),
            exchange(source, 3, command, &[script, "1", "key"], b"+QUEUED\r\n"),
            exchange(source, 4, "EXEC", &[], b"*1\r\n:1\r\n"),
        ])
        .await;
        let mut owner = TcpStream::connect(addr).await.unwrap();
        let mut other = TcpStream::connect(addr).await.unwrap();
        assert_reply(&mut owner, &["WATCH", "key"], b"+OK\r\n").await;
        assert_unmatched(&mut other, &["MULTI"]).await;
        assert_reply(&mut owner, &["MULTI"], b"+OK\r\n").await;
        assert_unmatched(&mut other, &[command, script, "1", "key"]).await;
        assert_reply(&mut owner, &[command, script, "1", "key"], b"+QUEUED\r\n").await;
        assert_unmatched(&mut other, &["EXEC"]).await;
        assert_reply(&mut owner, &["EXEC"], b"*1\r\n:1\r\n").await;
        let report = wait_for_unmatched_count(&report_path, "redis", 3).await;
        assert_eq!(report["redis"]["matched_count"], 4);
        for mismatch in report["redis"]["unmatched"].as_array().unwrap() {
            assert_eq!(
                mismatch["diagnostic"]["fields"],
                serde_json::json!(["connection"])
            );
        }
        assert!(
            report["redis"]["unused_case"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }
}

#[tokio::test]
async fn recorded_authentication_failure_keeps_its_session_and_error() {
    let connection = Uuid::new_v4();
    let mut auth = exchange(
        connection,
        1,
        "AUTH",
        &["<redacted>"],
        b"-WRONGPASS invalid credentials\r\n",
    );
    auth["session_setup"] = true.into();
    let (_temp, report_path, addr, task) = fixture(vec![
        auth,
        exchange(
            connection,
            2,
            "GET",
            &["key"],
            b"-NOAUTH Authentication required.\r\n",
        ),
    ])
    .await;
    let mut owner = TcpStream::connect(addr).await.unwrap();
    let mut other = TcpStream::connect(addr).await.unwrap();
    assert_reply(
        &mut owner,
        &["AUTH", "fixture-password"],
        b"-WRONGPASS invalid credentials\r\n",
    )
    .await;
    assert_unmatched(&mut other, &["GET", "key"]).await;
    assert_reply(
        &mut owner,
        &["GET", "key"],
        b"-NOAUTH Authentication required.\r\n",
    )
    .await;
    let report = wait_for_matched_count(&report_path, "redis", 2).await;
    assert_eq!(
        report["redis"]["unmatched"][0]["diagnostic"]["fields"],
        serde_json::json!(["connection"])
    );
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!report.to_string().contains("fixture-password"));
    task.abort();
}
