use super::*;
use crate::mysql::wire::continuation::MAX_PACKET_PAYLOAD_LEN;
use sqlx::Executor;

#[tokio::test]
async fn sqlx_tls_reads_large_text_and_prepared_rows_and_the_following_row() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let sql = "SELECT id,image FROM contexts";
        // Match the incident's field size and exercise exact-boundary payloads.
        let columns = json!([
            {"name":"id","family":"integer","sql_type":"INT"},
            {"name":"image","family":"string","sql_type":"LONGTEXT"}
        ]);
        let mut records = Vec::new();
        for len in [
            19_795_000,
            MAX_PACKET_PAYLOAD_LEN - 7,
            MAX_PACKET_PAYLOAD_LEN - 10,
        ] {
            let response = result(
                columns.clone(),
                json!([
                    [{"kind":"integer","value":42},{"kind":"string","value":"a".repeat(len)}],
                    [{"kind":"integer","value":43},{"kind":"string","value":"next"}]
                ]),
            );
            records.push(exchange(sql, response.clone()));
            records.push(exchange(sql, response));
        }
        let (temp, addr, runtime, task) = fixture(&records, false).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        for len in [
            19_795_000,
            MAX_PACKET_PAYLOAD_LEN - 7,
            MAX_PACKET_PAYLOAD_LEN - 10,
        ] {
            let text = (&mut client).fetch_all(sql).await.unwrap();
            let binary = sqlx::query(sql).fetch_all(&mut client).await.unwrap();
            for rows in [text, binary] {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].get::<i32, _>("id"), 42);
                let image = rows[0].get::<String, _>("image");
                assert_eq!(image.len(), len);
                assert!(image.bytes().all(|byte| byte == b'a'));
                assert_eq!(rows[1].get::<i32, _>("id"), 43);
                assert_eq!(rows[1].get::<String, _>("image"), "next");
            }
        }
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 6);
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert!(state.mysql.events.metadata_warnings.is_empty());
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        task.abort();
    })
    .await
    .expect("large-row SQLx replay timed out");
}
