//! A genuine TLS driver can trigger another dependency after an early result row.
use super::*;
use futures_util::TryStreamExt;
use traffic_replay::{EventKind, SequencePlan, SequenceRuntime, SourceEvent};

#[tokio::test]
async fn streamed_mysql_rows_keep_interleaved_dependency_barriers() {
    let columns = json!([{"name":"id","family":"integer","sql_type":"BIGINT"}]);
    let records = [
        exchange(
            "SELECT id FROM first_table",
            result(
                columns.clone(),
                json!([[{"kind":"integer","value":11}], [{"kind":"integer","value":12}]]),
            ),
        ),
        exchange(
            "SELECT id FROM second_table",
            result(columns, json!([[{"kind":"integer","value":21}]])),
        ),
    ];
    let (root, addr, runtime, task) = fixture(&records, false).await;
    let ca = root
        .path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
    let mut first = connect(addr, &ca).await;
    let mut second = connect(addr, &ca).await;
    let sequence = SequenceRuntime::new(
        SequencePlan::compile(
            [
                (1, 1, EventKind::Request),
                (2, 1, EventKind::ResponseHeaders),
                (3, 1, EventKind::ResponsePart),
                (4, 2, EventKind::Request),
                (5, 2, EventKind::ResponseHeaders),
                (6, 2, EventKind::ResponsePart),
                (7, 2, EventKind::ResponseEnd),
                (8, 1, EventKind::ResponsePart),
                (9, 1, EventKind::ResponseEnd),
            ]
            .into_iter()
            .map(|(sequence, dependency_sequence, kind)| SourceEvent {
                sequence,
                dependency_sequence,
                kind,
                offset_micros: sequence,
            }),
        )
        .unwrap(),
    );
    {
        let mut state = runtime.state.lock().await;
        state.active_sequence = Some(sequence.clone());
        state.protocols.mysql.lifecycle.sequence =
            crate::replay::sequence::Binding::new(sequence.clone(), [(0, 1), (1, 2)].into_iter());
    }
    let mut rows = sqlx::query("SELECT id FROM first_table").fetch(&mut first);
    let row = tokio::time::timeout(Duration::from_secs(3), rows.try_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(row.get::<i64, _>(0), 11);
    assert_eq!(sequence.expected().unwrap().kind, EventKind::Request);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), rows.try_next())
            .await
            .is_err()
    );
    let row = tokio::time::timeout(
        Duration::from_secs(3),
        sqlx::query("SELECT id FROM second_table").fetch_one(&mut second),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.get::<i64, _>(0), 21);
    let row = tokio::time::timeout(Duration::from_secs(3), rows.try_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(row.get::<i64, _>(0), 12);
    assert!(rows.try_next().await.unwrap().is_none());
    assert!(sequence.complete());
    task.abort();
}
