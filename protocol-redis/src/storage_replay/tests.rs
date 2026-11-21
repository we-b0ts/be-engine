use traffic_protocol::message::ProtocolMessage;

use super::*;
use crate::message::ResponseMessage;

fn request(command: &str, args: &[&str]) -> RequestMessage {
    RequestMessage {
        command: command.into(),
        args: args
            .iter()
            .map(|arg| Bytes::copy_from_slice(arg.as_bytes()))
            .collect(),
        resp_version: 2,
        database: 0,
        username: None,
    }
}

fn response(value: &'static [u8]) -> ProjectedMessage {
    ResponseMessage::decode(Bytes::from_static(value))
        .unwrap()
        .project()
        .unwrap()
}

#[test]
fn direct_writes_bind_only_the_last_successful_value_per_position() {
    let hset = request(
        "HSET",
        &["key", "first", "old", "second", "kept", "first", "new"],
    );
    let Mutation::Write(slots) = hset.storage_mutation(&response(b":0\r\n")) else {
        panic!("overwriting existing fields should be tracked");
    };
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].argument, 4);
    assert_eq!(slots[1].argument, 6);
    assert_eq!(slots[1].position.key.as_ref(), b"key");
    assert_eq!(slots[1].position.field.unwrap().as_ref(), b"first");
    assert_eq!(
        hset.storage_mutation(&response(b"-WRONGTYPE no\r\n")),
        Mutation::None
    );

    let mset = request("MSET", &["key", "old", "key", "new"]);
    let Mutation::Write(slots) = mset.storage_mutation(&response(b"+OK\r\n")) else {
        panic!("successful MSET should be tracked");
    };
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].argument, 3);
    assert_eq!(slots[0].position.field, None);
}

#[test]
fn hash_reads_use_the_actual_field_and_distinguish_nil_from_empty_bytes() {
    let hmget = request("HMGET", &["key", "absent", "empty"]);
    let reply = response(b"*2\r\n$-1\r\n$0\r\n\r\n");
    let slots = hmget.storage_read_slots(&reply);
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].position.field.unwrap().as_ref(), b"absent");
    assert_eq!(slots[0].value, None);
    assert_eq!(slots[1].value.unwrap().as_ref(), b"");
    assert_eq!(slots[1].path, "/1");

    let hgetall = request("HGETALL", &["key"]);
    let reply = response(b"*2\r\n$5\r\nfield\r\n$5\r\nvalue\r\n");
    let slots = hgetall.storage_read_slots(&reply);
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].position.field.unwrap().as_ref(), b"field");
    assert_eq!(slots[0].path, "/1");
    assert_eq!(slots[0].value.unwrap().as_ref(), b"value");
    assert!(hgetall.storage_read_slots(&response(b"*0\r\n")).is_empty());
    assert!(
        hgetall
            .storage_read_slots(&response(b"-WRONGTYPE no\r\n"))
            .is_empty()
    );
}

#[test]
fn other_mutations_invalidate_only_proven_positions() {
    let hdel = request("HDEL", &["key", "gone"]);
    let Mutation::Slots(fields) = hdel.storage_mutation(&response(b":1\r\n")) else {
        panic!("HDEL must fence the affected fields");
    };
    assert_eq!(fields[0].field.unwrap().as_ref(), b"gone");

    let set = request("SET", &["key", "value", "EX", "1"]);
    assert_eq!(
        set.storage_mutation(&response(b"+OK\r\n")),
        Mutation::Keys(vec![&set.args[0]])
    );
    assert_eq!(
        request("FLUSHALL", &[]).storage_mutation(&response(b"+OK\r\n")),
        Mutation::Endpoint
    );
}
