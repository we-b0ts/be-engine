#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn handshake_packet_auth_plugin_is_sqlx_compatible() {
        let packet = handshake_packet(7);
        assert_eq!(packet.sequence_id, 0);

        let mut offset = 0;
        assert_eq!(packet.payload[offset], 0x0a);
        offset += 1;
        offset += nul_terminated_len(&packet.payload[offset..]) + 1;
        offset += 4;
        assert_eq!(
            &packet.payload[offset..offset + MYSQL_REPLAY_AUTH_PLUGIN_DATA_1.len()],
            MYSQL_REPLAY_AUTH_PLUGIN_DATA_1
        );
        offset += MYSQL_REPLAY_AUTH_PLUGIN_DATA_1.len();
        assert_eq!(packet.payload[offset], 0);
        offset += 1;

        let capabilities_1 =
            u16::from_le_bytes([packet.payload[offset], packet.payload[offset + 1]]);
        offset += 2;
        offset += 1;
        offset += 2;
        let capabilities_2 =
            u16::from_le_bytes([packet.payload[offset], packet.payload[offset + 1]]);
        offset += 2;
        let capabilities = capabilities_1 as u32 | ((capabilities_2 as u32) << 16);
        assert_ne!(capabilities & CLIENT_SECURE_CONNECTION, 0);
        assert_ne!(capabilities & CLIENT_PLUGIN_AUTH, 0);

        let auth_plugin_data_len = packet.payload[offset];
        offset += 1;
        offset += 10;

        let sqlx_auth_plugin_data_2_len =
            std::cmp::max(auth_plugin_data_len.saturating_sub(9), 12) as usize;
        assert_eq!(
            sqlx_auth_plugin_data_2_len,
            MYSQL_REPLAY_AUTH_PLUGIN_DATA_2.len()
        );
        assert_eq!(
            &packet.payload[offset..offset + sqlx_auth_plugin_data_2_len],
            MYSQL_REPLAY_AUTH_PLUGIN_DATA_2
        );
        offset += sqlx_auth_plugin_data_2_len;
        assert_eq!(packet.payload[offset], 0);
        offset += 1;

        let plugin_len = nul_terminated_len(&packet.payload[offset..]);
        assert_eq!(
            &packet.payload[offset..offset + plugin_len],
            MYSQL_REPLAY_AUTH_PLUGIN
        );
        assert_eq!(offset + plugin_len + 1, packet.payload.len());
    }

    #[test]
    fn binary_replay_column_sets_binary_flag() {
        let payload = column_definition_payload(&RecordedMysqlColumn {
            name: "department_id".to_string(),
            table: Some("user".to_string()),
            column: Some("department_id".to_string()),
            family: "binary".to_string(),
            sql_type: "VARBINARY".to_string(),
            unsigned: None,
            bits: None,
            nullable: Some(true),
            scale: None,
        });
        let (type_code, flags) = replay_column_type_and_flags(&payload);

        assert_eq!(type_code, MYSQL_TYPE_VAR_STRING);
        assert_ne!(flags & MYSQL_FLAG_BINARY, 0);
    }

    #[tokio::test]
    async fn replays_text_query_from_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_QUERY","sql":"SELECT id, name FROM user WHERE id = 1","response":{"status":"resultset","columns":[{"name":"id","table":"user","column":"id","family":"integer","sql_type":"INT","unsigned":false,"bits":32,"nullable":false},{"name":"name","table":"user","column":"name","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"integer","value":1},{"kind":"string","value":"alice"}]]}}"#,
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [
                    vec![0x03],
                    b" select  id, name  from `user` where id = 1 ".to_vec(),
                ]
                .concat(),
            },
        )
        .await;

        let column_count = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(column_count.payload, vec![2]);
        let _id_column = read_packet(&mut client).await.unwrap().unwrap();
        let _name_column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(
            row.payload,
            [lenenc_bytes(b"1"), lenenc_bytes(b"alice")].concat()
        );
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

        wait_for_report_contains(&report_path, r#""command": "COM_QUERY""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["matched_queries"][0]["source"], "case");
        assert_eq!(report["matched_queries"][0]["command"], "COM_QUERY");
        assert!(report["unmatched_queries"].as_array().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn replays_large_resultset_with_wrapped_sequence_ids() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        let rows = (0..300)
            .map(|value| serde_json::json!([{ "kind": "integer", "value": value }]))
            .collect::<Vec<_>>();
        let dependency = serde_json::json!({
            "event_type": "mysql_exchange",
            "target_host": "mysql.internal",
            "target_port": 3306,
            "target_addr": "mysql.internal:3306",
            "database": "appdb",
            "username": "root",
            "command": "COM_QUERY",
            "sql": "SELECT id FROM many_rows",
            "response": {
                "status": "resultset",
                "columns": [{
                    "name": "id",
                    "table": "many_rows",
                    "column": "id",
                    "family": "integer",
                    "sql_type": "INT",
                    "unsigned": false,
                    "bits": 32,
                    "nullable": false
                }],
                "rows": rows
            }
        });
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            serde_json::to_string(&dependency).unwrap(),
        )
        .await
        .unwrap();
        let (addr, task) = spawn_replay(&case_dir, None).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT id FROM many_rows".to_vec()].concat(),
            },
        )
        .await;

        let mut sequence_ids = Vec::new();
        for _ in 0..304 {
            sequence_ids.push(read_packet(&mut client).await.unwrap().unwrap().sequence_id);
        }

        assert_eq!(sequence_ids[0], 1);
        assert_eq!(sequence_ids[254], 255);
        assert_eq!(sequence_ids[255], 0);
        assert_eq!(sequence_ids[256], 1);
        assert_eq!(sequence_ids[303], 48);
        task.abort();
    }

    #[tokio::test]
    async fn builtin_query_consumes_matching_recorded_exchange() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_QUERY","sql":"SET NAMES utf8","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}"#,
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SET NAMES utf8".to_vec()].concat(),
            },
        )
        .await;
        let ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(ok.payload[0], 0x00);

        wait_for_report_contains(&report_path, r#""recorded_source": "case""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["builtin_queries"][0]["command"], "COM_QUERY");
        assert_eq!(report["builtin_queries"][0]["sql"], "SET NAMES utf8");
        assert_eq!(report["builtin_queries"][0]["recorded_source"], "case");
        assert_eq!(report["builtin_queries"][0]["recorded_index"], 0);
        assert!(
            report["unused_case_exchanges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }

    #[tokio::test]
    async fn builtin_query_without_recorded_exchange_is_not_dirty() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SET NAMES utf8".to_vec()].concat(),
            },
        )
        .await;
        let ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(ok.payload[0], 0x00);

        wait_for_report_contains(&report_path, r#""sql": "SET NAMES utf8""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["builtin_queries"][0]["command"], "COM_QUERY");
        assert_eq!(report["builtin_queries"][0]["sql"], "SET NAMES utf8");
        assert!(report["builtin_queries"][0]["recorded_source"].is_null());
        assert!(report["unmatched_queries"].as_array().unwrap().is_empty());
        assert!(
            report["unused_case_exchanges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }

    #[tokio::test]
    async fn non_builtin_set_without_recorded_exchange_is_unmatched() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SET @tenant_id = 1".to_vec()].concat(),
            },
        )
        .await;
        let err = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(err.payload[0], 0xff);

        wait_for_report_contains(&report_path, r#""unmatched_queries""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert!(report["builtin_queries"].as_array().unwrap().is_empty());
        assert_eq!(report["unmatched_queries"][0]["command"], "COM_QUERY");
        assert_eq!(report["unmatched_queries"][0]["sql"], "SET @tenant_id = 1");
        task.abort();
    }

    #[tokio::test]
    async fn replays_prepared_execute_from_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_STMT_EXECUTE","sql":"SELECT name FROM user WHERE id=?","params":[{"kind":"integer","value":42}],"response":{"status":"resultset","columns":[{"name":"name","table":"user","column":"name","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"string","value":"alice"}]]}}"#,
        )
        .await
        .unwrap();
        let (addr, task) = spawn_replay(&case_dir, None).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x16], b" select name from user where id = ? ".to_vec()].concat(),
            },
        )
        .await;
        let prepare_ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(prepare_ok.payload[0], 0x00);
        let statement_id = read_u32_le(&prepare_ok.payload, 1).unwrap();
        assert_eq!(read_u16_le(&prepare_ok.payload, 5), Some(1));
        assert_eq!(read_u16_le(&prepare_ok.payload, 7), Some(1));
        let _param = read_packet(&mut client).await.unwrap().unwrap();
        let _param_eof = read_packet(&mut client).await.unwrap().unwrap();
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _column_eof = read_packet(&mut client).await.unwrap().unwrap();

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: stmt_execute_long_param(statement_id, 42),
            },
        )
        .await;
        let column_count = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(column_count.payload, vec![1]);
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(
            row.payload,
            [vec![0x00, 0x00], lenenc_bytes(b"alice")].concat()
        );
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn does_not_match_same_sql_on_different_database() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"otherdb","username":"root","command":"COM_QUERY","sql":"SELECT value FROM config","response":{"status":"resultset","columns":[{"name":"value","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"string","value":"wrong-db"}]]}}"#,
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT value FROM config".to_vec()].concat(),
            },
        )
        .await;
        let error = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(error.payload[0], 0xff);

        wait_for_report_contains(
            &report_path,
            r#""reason": "no recorded semantic dependency matched this SQL""#,
        )
        .await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["unmatched_queries"][0]["database"], "appdb");
        assert_eq!(report["unused_case_exchanges"][0]["database"], "otherdb");
        task.abort();
    }

    #[tokio::test]
    async fn loads_bootstrap_dependencies_from_parent_directory() {
        let temp = tempfile::tempdir().unwrap();
        let group_dir = temp.path().join("record-api").join("api-user");
        let case_dir = group_dir.join("case-id");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            group_dir.join("bootstrap-dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_QUERY","sql":"SELECT value FROM app_config","response":{"status":"resultset","columns":[{"name":"value","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"string","value":"on"}]]}}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT value FROM app_config".to_vec()].concat(),
            },
        )
        .await;
        assert_eq!(
            read_packet(&mut client).await.unwrap().unwrap().payload,
            vec![1]
        );
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(row.payload, lenenc_bytes(b"on"));
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

        wait_for_report_contains(&report_path, r#""source": "bootstrap""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(
            report["bootstrap_dependencies_path"],
            group_dir
                .join("bootstrap-dependencies.jsonl")
                .display()
                .to_string()
        );
        assert_eq!(report["matched_queries"][0]["source"], "bootstrap");
        task.abort();
    }

    #[tokio::test]
    async fn discovers_target_from_mysql_connection_and_reports_mapping() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        let connection_id = Uuid::new_v4();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            format!(
                r#"{{"event_type":"mysql_connection","id":"{connection_id}","target_host":"mysql-user.internal","target_port":3306,"target_addr":"mysql-user.internal:3306","upstream_addr":"10.1.2.3:3306","database":"appdb","username":"root"}}
{{"event_type":"mysql_exchange","connection_id":"{connection_id}","command":"COM_QUERY","sql":"SELECT id FROM user","response":{{"status":"resultset","columns":[{{"name":"id","family":"integer","sql_type":"INT","nullable":false}}],"rows":[[{{"kind":"integer","value":7}}]]}}}}"#
            ),
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT id FROM user".to_vec()].concat(),
            },
        )
        .await;
        assert_eq!(
            read_packet(&mut client).await.unwrap().unwrap().payload,
            vec![1]
        );
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(row.payload, lenenc_bytes(b"7"));
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

        wait_for_report_contains(&report_path, "mysql-user.internal").await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["targets"][0]["host"], "mysql-user.internal");
        assert_eq!(report["targets"][0]["port"], 3306);
        assert_eq!(report["targets"][0]["fake_ip"], "198.18.0.1");
        assert_eq!(
            report["matched_queries"][0]["target"]["host"],
            "mysql-user.internal"
        );
        task.abort();
    }

    #[tokio::test]
    async fn replay_dns_answers_recorded_mysql_target() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            format!(
                r#"{{"event_type":"mysql_connection","id":"{}","target_host":"mysql-user.internal","target_port":3306,"target_addr":"mysql-user.internal:3306","upstream_addr":"10.1.2.3:3306"}}"#,
                Uuid::new_v4()
            ),
        )
        .await
        .unwrap();
        let dns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns_socket.local_addr().unwrap();
        let runtime = MysqlReplayRuntime::load(
            MysqlReplayConfig {
                case_dir,
                dns_listen: dns_addr,
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
            },
            dns_addr,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let task = tokio::spawn(async move {
            let _ = runtime.run_dns(dns_socket).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&dns_query("mysql-user.internal"), dns_addr)
            .await
            .unwrap();
        let mut buf = [0_u8; 512];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        assert!(
            buf[..len]
                .windows(4)
                .any(|window| window == [198, 18, 0, 1])
        );
        task.abort();
    }

    #[tokio::test]
    async fn replay_control_reports_single_case_as_active() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("single-case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        let session_path = temp.path().join(".replay").join("session.json");
        let control_socket_path = temp.path().join(".replay").join("control.sock");
        let (_addr, tasks) = spawn_replay_with_control(
            &case_dir,
            None,
            session_path.clone(),
            control_socket_path,
        )
        .await;

        let response = run_mysql_replay_control(MysqlReplayControlConfig {
            session_path,
            command: "wait_ready".to_string(),
            case_id: None,
            fail_on_dirty: false,
        })
        .await
        .unwrap();

        assert_eq!(response["ready"], true);
        assert_eq!(response["session"]["mode"], "single");
        assert_eq!(response["session"]["active_case_id"], "single-case");
        abort_tasks(tasks);
    }

    #[tokio::test]
    async fn collection_replay_uses_begin_end_case_lifecycle() {
        let temp = tempfile::tempdir().unwrap();
        let collection_dir = temp.path().join("record-api").join("api-user");
        let case_a = collection_dir.join("case-a");
        let case_b = collection_dir.join("case-b");
        tokio::fs::create_dir_all(&case_a).await.unwrap();
        tokio::fs::create_dir_all(&case_b).await.unwrap();
        write_string_dependency(&case_a, "SELECT name FROM user WHERE id = 1", "alice").await;
        write_string_dependency(&case_b, "SELECT name FROM user WHERE id = 2", "bob").await;

        let session_path = temp.path().join(".replay").join("session.json");
        let control_socket_path = temp.path().join(".replay").join("control.sock");
        let report_path = temp.path().join("report.json");
        let (addr, tasks) = spawn_replay_with_control(
            &collection_dir,
            Some(report_path),
            session_path.clone(),
            control_socket_path,
        )
        .await;

        run_control(&session_path, "wait_ready", None, false)
            .await
            .unwrap();
        let cases = run_control(&session_path, "cases", None, false)
            .await
            .unwrap();
        assert_eq!(cases["active_case_id"], Value::Null);
        assert_eq!(cases["cases"].as_array().unwrap().len(), 2);

        run_control(&session_path, "begin", Some("case-a"), false)
            .await
            .unwrap();
        query_one_string(addr, "SELECT name FROM user WHERE id = 1", "alice").await;
        run_control(&session_path, "end", Some("case-a"), true)
            .await
            .unwrap();

        run_control(&session_path, "begin", Some("case-b"), false)
            .await
            .unwrap();
        query_one_string(addr, "SELECT name FROM user WHERE id = 2", "bob").await;
        run_control(&session_path, "end", Some("case-b"), true)
            .await
            .unwrap();

        let report = run_control(&session_path, "report", None, true)
            .await
            .unwrap();
        assert_eq!(report["dirty"], false);
        assert_eq!(report["report"]["matched_queries"].as_array().unwrap().len(), 2);
        abort_tasks(tasks);
    }

    async fn spawn_replay(
        case_dir: &Path,
        report_path: Option<PathBuf>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = MysqlReplayRuntime::load(
            MysqlReplayConfig {
                case_dir: case_dir.to_path_buf(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path,
                session_path: None,
                control_socket_path: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
        )
        .await
        .unwrap();
        runtime.write_report().await.unwrap();
        let task = tokio::spawn(async move {
            let _ = runtime.run_tcp(listener).await;
        });
        (addr, task)
    }

    async fn spawn_replay_with_control(
        case_dir: &Path,
        report_path: Option<PathBuf>,
        session_path: PathBuf,
        control_socket_path: PathBuf,
    ) -> (SocketAddr, Vec<tokio::task::JoinHandle<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = Arc::new(
            MysqlReplayRuntime::load(
                MysqlReplayConfig {
                    case_dir: case_dir.to_path_buf(),
                    dns_listen: "127.0.0.1:0".parse().unwrap(),
                    tcp_listen: addr,
                    fake_cidr: "198.18.0.0/15".to_string(),
                    report_path,
                    session_path: Some(session_path),
                    control_socket_path: Some(control_socket_path),
                },
                "127.0.0.1:0".parse().unwrap(),
                addr,
            )
            .await
            .unwrap(),
        );
        runtime.write_report().await.unwrap();
        let tcp_runtime = runtime.clone();
        let tcp_task = tokio::spawn(async move {
            let _ = tcp_runtime.run_tcp(listener).await;
        });
        let control_runtime = runtime;
        let control_task = tokio::spawn(async move {
            let _ = control_runtime.run_control().await;
        });
        (addr, vec![tcp_task, control_task])
    }

    async fn run_control(
        session_path: &Path,
        command: &str,
        case_id: Option<&str>,
        fail_on_dirty: bool,
    ) -> Result<Value> {
        run_mysql_replay_control(MysqlReplayControlConfig {
            session_path: session_path.to_path_buf(),
            command: command.to_string(),
            case_id: case_id.map(ToOwned::to_owned),
            fail_on_dirty,
        })
        .await
    }

    async fn write_string_dependency(case_dir: &Path, sql: &str, value: &str) {
        let dependency = serde_json::json!({
            "event_type": "mysql_exchange",
            "target_host": "mysql.internal",
            "target_port": 3306,
            "target_addr": "mysql.internal:3306",
            "database": "appdb",
            "username": "root",
            "command": "COM_QUERY",
            "sql": sql,
            "response": {
                "status": "resultset",
                "columns": [{
                    "name": "name",
                    "table": "user",
                    "column": "name",
                    "family": "string",
                    "sql_type": "VARCHAR",
                    "nullable": false
                }],
                "rows": [[{"kind": "string", "value": value}]]
            }
        });
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            serde_json::to_string(&dependency).unwrap(),
        )
        .await
        .unwrap();
    }

    async fn query_one_string(addr: SocketAddr, sql: &str, expected: &str) {
        let mut client = connect_login(addr).await;
        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
            },
        )
        .await;
        assert_eq!(
            read_packet(&mut client).await.unwrap().unwrap().payload,
            vec![1]
        );
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(row.payload, lenenc_bytes(expected.as_bytes()));
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();
    }

    fn abort_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
        for task in tasks {
            task.abort();
        }
    }

    async fn connect_login(addr: SocketAddr) -> TcpStream {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let handshake = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(handshake.sequence_id, 0);
        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 1,
                payload: login_payload("appdb"),
            },
        )
        .await;
        let ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(ok.payload[0], 0x00);
        client
    }

    async fn write_packet_bytes(stream: &mut TcpStream, packet: MysqlPacket) {
        stream.write_all(&packet.to_wire_bytes()).await.unwrap();
    }

    fn nul_terminated_len(bytes: &[u8]) -> usize {
        bytes
            .iter()
            .position(|byte| *byte == 0)
            .expect("missing NUL terminator")
    }

    fn replay_column_type_and_flags(payload: &[u8]) -> (u8, u16) {
        let mut offset = 0;
        for _ in 0..6 {
            let (_, next) = read_lenenc_bytes(payload, offset).expect("lenenc column field");
            offset = next;
        }
        let (_, offset) = read_lenenc_int(payload, offset).expect("column fixed length marker");
        let type_code = *payload.get(offset + 6).expect("column type code");
        let flags = u16::from_le_bytes([
            *payload.get(offset + 7).expect("column flags low byte"),
            *payload.get(offset + 8).expect("column flags high byte"),
        ]);
        (type_code, flags)
    }

    fn login_payload(database: &str) -> Vec<u8> {
        let flags = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_CONNECT_WITH_DB
            | CLIENT_PLUGIN_AUTH;
        let mut payload = Vec::new();
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0; 23]);
        payload.extend_from_slice(b"root\0");
        payload.push(0);
        payload.extend_from_slice(database.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"mysql_native_password\0");
        payload
    }

    fn stmt_execute_long_param(statement_id: u32, value: u32) -> Vec<u8> {
        let mut payload = vec![0x17];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.push(0);
        payload.push(1);
        payload.push(MYSQL_TYPE_LONG);
        payload.push(0);
        payload.extend_from_slice(&value.to_le_bytes());
        payload
    }

    fn dns_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234_u16.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    async fn wait_for_report_contains(path: &Path, expected: &str) {
        for _ in 0..50 {
            if tokio::fs::read_to_string(path)
                .await
                .is_ok_and(|raw| raw.contains(expected))
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("replay report was not written");
    }
}
