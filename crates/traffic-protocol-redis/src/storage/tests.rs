use super::*;
use crate::session_binding::{ConnectionScopes, RecordedSession};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

struct Exchange {
    native: RecordedExchange,
    arguments: Vec<Vec<u8>>,
    response: Vec<u8>,
}

impl RecordedSession for Exchange {
    fn connection_id(&self) -> Uuid {
        self.native.connection_id
    }
    fn sequence(&self) -> u64 {
        self.native.sequence
    }
    fn command(&self) -> &str {
        &self.native.command
    }
    fn session_setup(&self) -> bool {
        self.native.session_setup
    }
}

impl SessionExchange for Exchange {
    type Record = Self;
    fn record(&self) -> &Self::Record {
        self
    }
    fn source(&self) -> DependencyScope {
        DependencyScope::Case
    }
    fn case_id(&self) -> Option<&str> {
        Some("case")
    }
    fn connection_independent(&self) -> bool {
        false
    }
}

impl StorageExchange for Exchange {
    fn native_record(&self) -> &RecordedExchange {
        &self.native
    }
    fn arguments(&self) -> &[Vec<u8>] {
        &self.arguments
    }
    fn response_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.response.clone())
    }
    fn explicitly_shared(&self) -> bool {
        false
    }
}

fn exchange(sequence: u64, command: &str, arguments: &[&[u8]], response: &[u8]) -> Exchange {
    let clock = format!("2020-01-01T00:00:{sequence:02}Z");
    let native = serde_json::from_value(json!({
        "connection_id": Uuid::nil(), "sequence": sequence,
        "target_host": "redis.test", "target_port": 6379,
        "database": 0, "resp_version": 2, "command": command,
        "timestamp": clock, "request_started_at": clock,
        "args": [], "response": {"encoding": "utf8", "data": ""},
        "response_kind": "integer", "replay_safe": true,
    }))
    .unwrap();
    Exchange {
        native,
        arguments: arguments.iter().map(|value| value.to_vec()).collect(),
        response: response.to_vec(),
    }
}

#[test]
fn append_proof_preserves_physical_offsets_and_reset_fences_through_the_storage_port() {
    let exchanges = [
        exchange(1, "APPEND", &[b"key", b"ab"], b":2\r\n"),
        exchange(2, "APPEND", &[b"key", b"cd"], b":4\r\n"),
        exchange(3, "DEL", &[b"key"], b":1\r\n"),
        exchange(4, "APPEND", &[b"key", b"ef"], b":2\r\n"),
    ];
    let trace = append::prepare(&exchanges, "case", "append", &exchanges[0]).unwrap();
    assert_eq!(trace.bytes, b"abcdef");
    assert_eq!(trace.proof.barriers, [(2, 4)]);
    let pieces = trace
        .proof
        .pieces
        .iter()
        .map(|piece| {
            (
                piece.index,
                piece.start,
                piece.end,
                piece.epoch_start,
                piece.base,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(pieces, [(0, 0, 2, 0, 0), (1, 2, 4, 0, 0), (3, 4, 6, 4, 0)]);
}

struct CounterValues;

impl activity::ValueModel for CounterValues {
    type Value = (u8, u8);
    type Fields = u8;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Value> {
        ensure!(bytes.len() == 2, "two-byte counter value required");
        Ok((bytes[0], bytes[1]))
    }
    fn fields(&self, value: &Self::Value, _clock: DateTime<Utc>) -> Result<Self::Fields> {
        Ok(value.0)
    }
    fn same_stable(&self, before: &Self::Value, after: &Self::Value, _: &u8) -> Result<bool> {
        Ok(before.0 == after.0)
    }
}

#[test]
fn activity_lifetimes_delegate_value_semantics_to_an_independent_implementation() {
    let mut exchanges = [
        exchange(1, "SET", &[b"key", b"u1", b"EX", b"60"], b"+OK\r\n"),
        exchange(2, "GET", &[b"key"], b"$2\r\nu1\r\n"),
        exchange(3, "SET", &[b"key", b"u2", b"EX", b"60"], b"+OK\r\n"),
        exchange(4, "GET", &[b"key"], b"$2\r\nu2\r\n"),
        exchange(5, "DEL", &[b"key"], b":1\r\n"),
    ];
    let prepare = |exchanges: &[Exchange]| {
        activity::prepare(
            exchanges,
            &ConnectionScopes::default(),
            "case",
            "refresh",
            &CounterValues,
            &exchanges[0],
        )
    };
    let proof = prepare(&exchanges).unwrap().unwrap();
    let lifetime = &proof.lifetimes[0];
    assert_eq!(lifetime.reference, (b'u', b'1'));
    assert_eq!(lifetime.fields, b'u');
    assert_eq!(lifetime.creation, 0);
    assert_eq!(lifetime.deletion, Some(4));
    assert_eq!(lifetime.reads, [1, 3]);
    assert_eq!(lifetime.writes, [2]);
    exchanges[2].arguments[1] = b"v2".to_vec();
    assert!(prepare(&exchanges).is_err());
}
