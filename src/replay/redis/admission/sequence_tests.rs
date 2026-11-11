use super::*;
use crate::replay::redis::append::tests::event;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use traffic_replay::{EventKind, SequencePlan, SequenceRuntime, SourceEvent};

fn request(command: &str, args: &[&[u8]]) -> RedisCommand {
    RedisCommand {
        name: command.into(),
        args: args.iter().map(|arg| arg.to_vec()).collect(),
    }
}

async fn fixture() -> (
    tempfile::TempDir,
    crate::replay::ReplayRuntime,
    Arc<SequenceRuntime>,
) {
    let events = [
        event(1, "GET", &[b"a"], b"$1\r\na\r\n"),
        event(2, "GET", &[b"b"], b"$1\r\nb\r\n"),
    ];
    let (directory, runtime) = super::tests::runtime_with_source(
        &events,
        json!({"format":"traffic-policy/v3","rules":[]}),
    )
    .await;
    let plan = SequencePlan::compile(
        [
            (1, 1, EventKind::Request),
            (2, 1, EventKind::ResponseEnd),
            (3, 2, EventKind::Request),
            (4, 2, EventKind::ResponseEnd),
        ]
        .into_iter()
        .map(|(sequence, dependency_sequence, kind)| SourceEvent {
            sequence,
            dependency_sequence,
            kind,
            offset_micros: sequence,
        }),
    )
    .unwrap();
    let sequence = SequenceRuntime::new(plan);
    {
        let mut state = runtime.state.lock().await;
        state.active_sequence = Some(sequence.clone());
        state.redis.lifecycle.sequence =
            crate::replay::sequence::Binding::new(sequence.clone(), [(0, 1), (1, 2)].into_iter());
    }
    (directory, runtime, sequence)
}

async fn delivered(runtime: &crate::replay::ReplayRuntime, matched: &MatchedRedisExchange) {
    let Claim::Finite(ticket) = &matched.claim else {
        panic!("finite Source dependency")
    };
    ticket.wait_sequence_delivery().await.unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    writer.write_all(&matched.response).await.unwrap();
    writer.flush().await.unwrap();
    let mut actual = vec![0; matched.response.len()];
    reader.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, matched.response);
    matched.publish_wire();
    assert!(runtime.state.lock().await.redis.complete_exchange(matched));
}

#[tokio::test]
async fn early_native_request_waits_for_the_exact_recorded_predecessor_and_real_delivery() {
    let (_directory, runtime, sequence) = fixture().await;
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let mut early_binding = CaseConnectionBinding::default();
    let early_command = request("GET", &[b"b"]);
    let early = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut early_binding,
        2,
        0,
        None,
        &early_command,
    );
    tokio::pin!(early);
    tokio::select! {biased; result=&mut early=>panic!("later request must wait: {result:?}"),_=std::future::ready(())=>{}}
    assert_eq!(sequence.expected().unwrap().dependency_sequence, 1);
    let mut first_binding = CaseConnectionBinding::default();
    let first_command = request("GET", &[b"a"]);
    let first = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut first_binding,
        2,
        0,
        None,
        &first_command,
    )
    .await
    .unwrap();
    tokio::select! {biased; result=&mut early=>panic!("undelivered predecessor must remain a barrier: {result:?}"),_=std::future::ready(())=>{}}
    delivered(&runtime, &first).await;
    let second = tokio::time::timeout(Duration::from_secs(5), early)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.index, 1);
    assert_eq!(second.report.target_event_index, Some(0));
    delivered(&runtime, &second).await;
    assert!(sequence.complete());
    let state = runtime.state.lock().await;
    assert!(state.redis.events.unmatched.is_empty());
    assert!(state.sequence_missing.is_empty());
}

#[tokio::test]
async fn missing_predecessor_produces_one_review_for_the_same_scope_revision() {
    let (_directory, runtime, _sequence) = fixture().await;
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let mut first = CaseConnectionBinding::default();
    let mut second = CaseConnectionBinding::default();
    let command = request("GET", &[b"b"]);
    let (first, second) = tokio::join!(
        match_command(
            &runtime.state,
            &target,
            Uuid::new_v4(),
            &mut first,
            2,
            0,
            None,
            &command
        ),
        match_command(
            &runtime.state,
            &target,
            Uuid::new_v4(),
            &mut second,
            2,
            0,
            None,
            &command
        )
    );
    assert!(first.is_err() && second.is_err());
    let state = runtime.state.lock().await;
    assert_eq!(state.sequence_missing.len(), 1);
    assert_eq!(state.sequence_missing[0].expected.dependency_sequence, 1);
    assert_eq!(state.sequence_missing[0].attribution_review, "required");
}

#[tokio::test]
async fn pipelined_requests_are_admitted_before_the_first_response_on_one_socket() {
    let (_directory, runtime, _) = fixture().await;
    let sequence = SequenceRuntime::new(
        SequencePlan::compile(
            [
                (1, 1, EventKind::Request),
                (2, 2, EventKind::Request),
                (3, 1, EventKind::ResponseEnd),
                (4, 2, EventKind::ResponseEnd),
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
        state.redis.lifecycle.sequence =
            crate::replay::sequence::Binding::new(sequence.clone(), [(0, 1), (1, 2)].into_iter());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(super::super::handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    let mut client = RedisBufferedReader::new(stream, 1024);
    client
        .inner
        .write_all(
            &[
                crate::redis::encode_array(&[b"GET", b"a"]),
                crate::redis::encode_array(&[b"GET", b"b"]),
            ]
            .concat(),
        )
        .await
        .unwrap();
    for expected in [b"$1\r\na\r\n", b"$1\r\nb\r\n"] {
        let frame = tokio::time::timeout(Duration::from_secs(3), read_redis_frame(&mut client))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.raw.as_ref(), expected);
    }
    assert!(sequence.complete());
    drop(client);
    task.await.unwrap().unwrap();
}
