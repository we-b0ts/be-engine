use super::*;
use serde_json::json;

async fn query_flags(client: &mut TcpStream, sql: &str) -> u16 {
    write_packet_bytes(
        client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![3], sql.as_bytes().to_vec()].concat(),
        },
    )
    .await;
    let response = read_packet(client).await.unwrap().unwrap();
    assert_eq!(response.payload[0], 0, "{sql}");
    u16::from_le_bytes(response.payload[3..5].try_into().unwrap())
}

#[tokio::test]
async fn autocommit_status_is_connection_local_and_respects_explicit_transactions() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let temp = tempdir().unwrap();
        let case = temp.path().join("case-id");
        std::fs::create_dir(&case).unwrap();
        std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
        let (addr, _, task) = spawn_replay(&case).await;
        let mut client = connect_login(addr).await;
        let mut other = connect_login(addr).await;
        for (sql, flags) in [
            ("BEGIN", 3),
            ("SET AUTOCOMMIT=1", 3),
            ("SET SESSION AUTOCOMMIT=0", 1),
            ("SET @@session.autocommit=1", 2),
            ("SET AUTOCOMMIT=0", 0),
            ("BEGIN", 1),
            ("ROLLBACK", 0),
            ("BEGIN", 1),
            ("COMMIT", 0),
            ("SET AUTOCOMMIT=1", 2),
        ] {
            assert_eq!(query_flags(&mut client, sql).await, flags, "{sql}");
        }
        assert_eq!(query_flags(&mut other, "ROLLBACK").await, 2);
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_set_does_not_change_state_and_implicit_reads_preserve_source_status() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let temp = tempdir().unwrap();
        let case = temp.path().join("case-id");
        std::fs::create_dir(&case).unwrap();
        let records = [
            json!({"event_type":"mysql_exchange","target_host":"127.0.0.1","target_port":3306,"database":"appdb","username":"root",
                "command":"COM_QUERY","sql":"SELECT id FROM users","response":{"status":"resultset","server_status":1,
                "columns":[{"name":"id","family":"integer","sql_type":"INT"}],"rows":[[{"kind":"integer","value":1}]]}}),
            json!({"event_type":"mysql_exchange","target_host":"127.0.0.1","target_port":3306,"database":"appdb","username":"root",
                "command":"COM_QUERY","sql":"SET AUTOCOMMIT=1","response":{"status":"error","error_code":1205,"error_message":"failure"}}),
        ];
        std::fs::write(case.join("dependencies.jsonl"), records.iter().map(Value::to_string).collect::<Vec<_>>().join("\n")).unwrap();
        let (addr, _, task) = spawn_replay(&case).await;
        let mut client = connect_login(addr).await;
        assert_eq!(query_flags(&mut client,"SET AUTOCOMMIT=0").await,0);
        write_packet_bytes(&mut client,MysqlPacket{sequence_id:0,payload:[vec![3],b"SELECT id FROM users".to_vec()].concat()}).await;
        for index in 0..5 {
            let packet = read_packet(&mut client).await.unwrap().unwrap();
            if index == 2 || index == 4 {
                assert_eq!(packet.payload[0], 0xfe);
                assert_eq!(u16::from_le_bytes(packet.payload[3..5].try_into().unwrap()), 1);
            }
        }
        write_packet_bytes(&mut client,MysqlPacket{sequence_id:0,payload:[vec![3],b"SET AUTOCOMMIT=1".to_vec()].concat()}).await;
        assert_eq!(read_packet(&mut client).await.unwrap().unwrap().payload[0], 0xff);
        assert_eq!(query_flags(&mut client,"ROLLBACK").await, 0);
        task.abort();
    }).await.unwrap();
}
