//! Native SQL session continuity over immutable, location-free summaries.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Member {
    pub file: usize,
    pub record: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub connection: String,
    pub known_start: bool,
    pub closed: bool,
    pub members: Vec<Member>,
}

pub fn intervals(files: &[Vec<&serde_json::Value>]) -> (Vec<Transaction>, usize) {
    let mut connections = BTreeMap::<String, BTreeMap<u64, Member>>::new();
    let mut ambiguous = BTreeSet::new();
    for (file, source) in files.iter().enumerate() {
        for (record, entry) in source.iter().enumerate() {
            let summary = entry;
            let Some(connection) = summary["connection_id"].as_str() else {
                continue;
            };
            let Some(sequence) = summary["query_sequence"].as_u64() else {
                ambiguous.insert(connection.to_owned());
                continue;
            };
            if connections
                .entry(connection.into())
                .or_default()
                .insert(sequence, Member { file, record })
                .is_some()
            {
                ambiguous.insert(connection.to_owned());
            }
        }
    }
    let mut transactions = Vec::new();
    for (connection, entries) in connections {
        if ambiguous.contains(&connection) {
            continue;
        }
        let mut group = Vec::new();
        let mut known_start = false;
        let mut previous: Option<(u64, Option<u64>, Member)> = None;
        for (sequence, member) in entries {
            let current = &files[member.file][member.record];
            let before = current["server_status_before"].as_u64();
            let after = current["server_status_after"].as_u64();
            let consecutive = previous.is_some_and(|(seq, flags, prior)| {
                let prior = &files[prior.file][prior.record];
                seq.checked_add(1) == Some(sequence)
                    && flags
                        .zip(before)
                        .is_some_and(|(a, b)| a & 0x200b == b & 0x200b)
                    && ["target_host", "target_port", "database", "username"]
                        .iter()
                        .all(|key| prior[*key] == current[*key])
            });
            let start =
                before.is_some_and(|s| s & 0x2009 == 0) && after.is_some_and(|s| s & 0x2009 == 1);
            if (!consecutive || start) && !group.is_empty() {
                transactions.push(Transaction {
                    connection: connection.clone(),
                    known_start,
                    closed: false,
                    members: std::mem::take(&mut group),
                });
                known_start = false;
            }
            if start {
                known_start = true;
            }
            if start || !group.is_empty() || before.is_some_and(|s| s & 0x2009 == 1) {
                group.push(member);
            }
            if after.is_some_and(|s| s & 0x2009 == 0) && !group.is_empty() {
                // Retain the immediate following control as a candidate too;
                // the protocol proof still decides whether it is cleanup.
                transactions.push(Transaction {
                    connection: connection.clone(),
                    known_start,
                    closed: true,
                    members: std::mem::take(&mut group),
                });
                known_start = false;
            }
            previous = Some((sequence, after, member));
        }
        if !group.is_empty() {
            transactions.push(Transaction {
                connection,
                known_start,
                closed: false,
                members: group,
            });
        }
    }
    (transactions, ambiguous.len())
}
