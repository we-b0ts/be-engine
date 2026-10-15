use super::*;

#[tokio::test]
async fn global_mysql_rows_are_delivered_once_through_the_real_wire() {
    let dir = tempdir().unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    std::fs::write(
        dir.path().join("global-dependencies.jsonl"),
        execute_dependency("global", true),
    )
    .unwrap();
    let (addr, _runtime, task) = spawn_replay(&case).await;
    let mut client = connect_login(addr).await;
    let query = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x03], b"SELECT value FROM settings".to_vec()].concat(),
    };
    write_packet_bytes(&mut client, query.clone()).await;
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload,
        vec![1]
    );
    for _ in 0..2 {
        read_packet(&mut client).await.unwrap().unwrap();
    }
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload,
        [vec![6], b"global".to_vec()].concat()
    );
    read_packet(&mut client).await.unwrap().unwrap();
    write_packet_bytes(&mut client, query).await;
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0xff
    );
    task.abort();
}
