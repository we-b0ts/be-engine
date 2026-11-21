//! RESP storage effects used by finite replay to relate a read to a direct write.
use std::collections::HashSet;

use bytes::Bytes;
use serde_json::Value;
use traffic_protocol::{connection::Operation, message::ProjectedMessage};

use crate::message::RequestMessage;

pub mod delivered;
mod facts;
mod history;
pub use facts::{
    Location, ReadLink, ReadQuery, SourceFacts, WriteEffect, delivered_writes, request,
    source_facts,
};
pub use history::{ScopeHistory, Stamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Position<'a> {
    pub key: &'a Bytes,
    pub field: Option<&'a Bytes>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct WriteSlot<'a> {
    pub position: Position<'a>,
    pub argument: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReadSlot<'a> {
    pub position: Position<'a>,
    pub path: String,
    pub value: Option<&'a Bytes>,
}

/// Operations outside direct writes supply invalidation boundaries only.
#[derive(Debug, PartialEq, Eq)]
pub enum Mutation<'a> {
    None,
    Write(Vec<WriteSlot<'a>>),
    Keys(Vec<&'a Bytes>),
    Slots(Vec<Position<'a>>),
    Database,
    Endpoint,
}

#[derive(Clone, Copy)]
enum DirectWrite {
    String,
    Hash,
}

impl RequestMessage {
    pub fn storage_read(&self) -> bool {
        matches!(
            self.command.as_str(),
            "GET" | "MGET" | "HGET" | "HMGET" | "HGETALL"
        )
    }

    fn direct_write(&self) -> Option<DirectWrite> {
        match (self.command.as_str(), self.args.len()) {
            ("SET", 2) => Some(DirectWrite::String),
            ("MSET", len) if len >= 2 && len.is_multiple_of(2) => Some(DirectWrite::String),
            ("HSET" | "HMSET", len) if len >= 3 && !len.is_multiple_of(2) => {
                Some(DirectWrite::Hash)
            }
            _ => None,
        }
    }

    pub fn storage_mutation(&self, response: &ProjectedMessage) -> Mutation<'_> {
        if let Some(write) = self.direct_write() {
            let kind = response.structure["kind"].as_str();
            if kind == Some("error") {
                return Mutation::None;
            }
            let value = response.values.get("").map(|value| value.bytes.as_ref());
            let successful = if self.command == "HSET" {
                // Redis counts added fields here. Zero also permits overwrites.
                kind == Some("integer")
                    && value
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .and_then(|count| count.parse::<u64>().ok())
                        .is_some()
            } else {
                kind == Some("simple") && value == Some(b"OK".as_slice())
            };
            if successful {
                return Mutation::Write(self.write_slots(write));
            }
        }

        match self.command.as_str() {
            "HDEL" if self.args.len() >= 2 => field_mutations(&self.args[0], &self.args[1..]),
            "HSETNX" | "HINCRBY" | "HINCRBYFLOAT" if self.args.len() >= 2 => {
                field_mutations(&self.args[0], &self.args[1..2])
            }
            "DEL" | "UNLINK" => Mutation::Keys(self.args.iter().collect()),
            "FLUSHDB" => Mutation::Database,
            "MOVE" | "MIGRATE" | "SWAPDB" | "FLUSHALL" | "XREADGROUP" => Mutation::Endpoint,
            "COPY"
                if self.args.len() > 2
                    && self.args[2..]
                        .iter()
                        .any(|arg| arg.eq_ignore_ascii_case(b"DB")) =>
            {
                Mutation::Endpoint
            }
            "PUBLISH" | "SPUBLISH" | "TOUCH" => Mutation::None,
            "EVAL" | "EVALSHA" | "FCALL" | "EXEC" => Mutation::Endpoint,
            "PEXPIRE" | "EXPIREAT" | "PEXPIREAT" | "HEXPIRE" | "HPEXPIRE" | "HEXPIREAT"
            | "HPEXPIREAT" | "HPERSIST" | "HGETDEL" | "HGETEX" | "HSETEX"
                if !self.args.is_empty() =>
            {
                Mutation::Keys(vec![&self.args[0]])
            }
            _ => {
                if matches!(
                    crate::access::classify(&self.command, &self.args),
                    Operation::Read | Operation::Session
                ) {
                    return Mutation::None;
                }
                // Conditional SET, expiry options, and other unmodeled writes
                // invalidate their known keys without supplying write values.
                match crate::key_slots::key_indices(&self.command, &self.args) {
                    Ok(keys) if !keys.is_empty() => {
                        Mutation::Keys(keys.into_iter().map(|key| &self.args[key]).collect())
                    }
                    _ => Mutation::Endpoint,
                }
            }
        }
    }

    fn write_slots(&self, write: DirectWrite) -> Vec<WriteSlot<'_>> {
        let is_hash = matches!(write, DirectWrite::Hash);
        let pairs = (usize::from(is_hash)..self.args.len()).step_by(2);
        let repeated_positions_possible = pairs.len() > 1;
        let mut slots = Vec::with_capacity(pairs.len());
        let mut seen = HashSet::new();
        for index in pairs.rev() {
            // Redis processes repeated targets in order. Only their final
            // value can supply a later read.
            let key_argument = if is_hash { 0 } else { index };
            let field_argument = is_hash.then_some(index);
            let position = Position {
                key: &self.args[key_argument],
                field: field_argument.map(|argument| &self.args[argument]),
            };
            if !repeated_positions_possible || seen.insert(position) {
                slots.push(WriteSlot {
                    position,
                    argument: index + 1,
                });
            }
        }
        slots.reverse();
        slots
    }

    pub fn storage_read_slots<'a>(&'a self, response: &'a ProjectedMessage) -> Vec<ReadSlot<'a>> {
        match (self.command.as_str(), self.args.as_slice()) {
            ("GET", [key]) => read_slot(
                response,
                &response.structure,
                String::new(),
                Position { key, field: None },
            )
            .into_iter()
            .collect(),
            ("HGET", [key, field]) => read_slot(
                response,
                &response.structure,
                String::new(),
                Position {
                    key,
                    field: Some(field),
                },
            )
            .into_iter()
            .collect(),
            ("MGET", keys) => read_array(
                response,
                keys.iter().map(|key| Position { key, field: None }),
            ),
            ("HMGET", [key, fields @ ..]) => read_array(
                response,
                fields.iter().map(|field| Position {
                    key,
                    field: Some(field),
                }),
            ),
            ("HGETALL", [key]) => read_hash(response, key),
            _ => Vec::new(),
        }
    }

    /// Absence invalidates the corresponding Source write lineage, even if an
    /// unobserved write later happens to restore the old bytes.
    pub fn storage_absence<'a>(&'a self, response: &'a ProjectedMessage) -> Mutation<'a> {
        let shape = &response.structure;
        if self.command == "HGETALL"
            && shape["items"].as_array().is_some_and(Vec::is_empty)
            && let [key] = self.args.as_slice()
        {
            // A non-hash value would produce WRONGTYPE instead.
            return Mutation::Keys(vec![key]);
        }
        let has_nil = shape["kind"] == "null"
            || shape["items"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["kind"] == "null"));
        if has_nil {
            Mutation::Slots(
                self.storage_read_slots(response)
                    .into_iter()
                    .filter_map(|slot| slot.value.is_none().then_some(slot.position))
                    .collect(),
            )
        } else {
            Mutation::None
        }
    }
}

fn field_mutations<'a>(key: &'a Bytes, fields: &'a [Bytes]) -> Mutation<'a> {
    Mutation::Slots(
        fields
            .iter()
            .map(|field| Position {
                key,
                field: Some(field),
            })
            .collect(),
    )
}

fn read_slot<'a>(
    response: &'a ProjectedMessage,
    shape: &Value,
    path: String,
    position: Position<'a>,
) -> Option<ReadSlot<'a>> {
    let value = match shape["kind"].as_str()? {
        "bulk" => Some(&response.values.get(&path)?.bytes),
        "null" => None,
        _ => return None,
    };
    Some(ReadSlot {
        position,
        path,
        value,
    })
}

fn read_array<'a>(
    response: &'a ProjectedMessage,
    positions: impl ExactSizeIterator<Item = Position<'a>>,
) -> Vec<ReadSlot<'a>> {
    let Some(items) = response.structure["items"].as_array() else {
        return Vec::new();
    };
    if items.len() != positions.len() {
        return Vec::new();
    }
    items
        .iter()
        .zip(positions)
        .enumerate()
        .filter_map(|(index, (shape, position))| {
            read_slot(response, shape, format!("/{index}"), position)
        })
        .collect()
}

fn read_hash<'a>(response: &'a ProjectedMessage, key: &'a Bytes) -> Vec<ReadSlot<'a>> {
    let Some(items) = response.structure["items"].as_array() else {
        return Vec::new();
    };
    if !items.len().is_multiple_of(2) {
        return Vec::new();
    }
    items
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
        .filter_map(|(index, pair)| {
            let field_location = index * 2;
            let field = &response.values.get(&format!("/{field_location}"))?.bytes;
            if pair[0]["kind"] != "bulk" {
                return None;
            }
            read_slot(
                response,
                &pair[1],
                format!("/{}", field_location + 1),
                Position {
                    key,
                    field: Some(field),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests;
