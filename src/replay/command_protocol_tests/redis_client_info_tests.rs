use super::*;

const SETINFO_ERROR: &[u8] =
    b"-ERR Unknown subcommand or wrong number of arguments for 'SETINFO'. Try CLIENT HELP\r\n";

fn client_info(
    connection: Uuid,
    sequence: u64,
    attribute: &str,
    value: &str,
    response: &[u8],
) -> Value {
    let mut record = redis_dependency(connection, sequence, "unused", response);
    record["command"] = serde_json::json!("CLIENT");
    record["args"] = serde_json::json!([
        capture_json(b"SETINFO"),
        capture_json(attribute.as_bytes()),
        capture_json(value.as_bytes())
    ]);
    record["session_setup"] = serde_json::json!(true);
    record["response_kind"] = serde_json::json!(if response.starts_with(b"-") {
        "error"
    } else {
        "simple_string"
    });
    record
}

#[tokio::test]
async fn redis_client_info_is_optional_for_all_sdk_identities_and_server_results() {
    for response in [SETINFO_ERROR, b"+OK\r\n".as_slice()] {
        for target_announces in [false, true] {
            let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
            let case_dir = temp.path().join("case");
            tokio::fs::create_dir_all(&case_dir).await.unwrap();
            let connection = Uuid::new_v4();
            let raw = [
                client_info(connection, 1, "LIB-NAME", "redis-py", response),
                client_info(connection, 2, "LIB-VER", "6.4.0", response),
                redis_dependency(connection, 3, "key", b"$1\r\n1\r\n"),
            ]
            .map(|record| record.to_string())
            .join("\n");
            let path = case_dir.join("dependencies.jsonl");
            tokio::fs::write(&path, &raw).await.unwrap();
            let report_path = temp.path().join("report.json");
            let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
            let mut client = TcpStream::connect(addr).await.unwrap();
            if target_announces {
                client.write_all(b"*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$9\r\nbrz-redis\r\n*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$7\r\nLIB-VER\r\n$5\r\n0.0.3\r\n").await.unwrap();
                let mut result = [0; 10];
                tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut result))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&result, b"+OK\r\n+OK\r\n");
            }
            client
                .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
                .await
                .unwrap();
            let mut result = [0; 7];
            tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut result))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&result, b"$1\r\n1\r\n");
            let report = wait_for_matched_count(&report_path, "redis", 1).await;
            for field in [
                "unused_case",
                "unused_global",
                "unmatched",
                "unsafe_events",
                "unsupported",
            ] {
                assert!(
                    report["redis"][field].as_array().unwrap().is_empty(),
                    "{field}: {report}"
                );
            }
            assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), raw);
            task.abort();
        }
    }
}
