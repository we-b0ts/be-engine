//! Select complete wire-state intervals before reading authoritative row payloads.
use super::*;

type Sequences = BTreeSet<(String, u64)>;

pub(super) fn selected(summary: &Value, sequences: &Sequences) -> bool {
    summary["connection_id"]
        .as_str()
        .zip(summary["query_sequence"].as_u64())
        .is_some_and(|(conn, seq)| sequences.contains(&(conn.to_owned(), seq)))
}

pub(super) fn candidates(files: &[EvidenceFile], index: &OriginIndex) -> Result<Sequences> {
    let mut connections =
        BTreeMap::<String, BTreeMap<u64, (Option<u64>, Option<u64>, bool)>>::new();
    let mut duplicates = BTreeSet::new();
    for file in files {
        let case = case_id(&file.path)?;
        for record in file.index.mysql.iter().flatten() {
            let e = &record.summary;
            let Some((connection, sequence)) = e["connection_id"]
                .as_str()
                .zip(e["query_sequence"].as_u64())
            else {
                continue;
            };
            let state = (
                e["server_status_before"].as_u64(),
                e["server_status_after"].as_u64(),
                index.witness(&case, e).is_some(),
            );
            if connections
                .entry(connection.into())
                .or_default()
                .insert(sequence, state)
                .is_some()
            {
                duplicates.insert(connection.to_owned());
            }
        }
    }
    let mut selected = Sequences::new();
    for (connection, records) in connections {
        if duplicates.contains(&connection) {
            continue;
        }
        let mut group = Vec::new();
        let mut anchored = false;
        let mut previous: Option<(u64, u64)> = None;
        for (seq, (before, after, anchor)) in records {
            let consecutive = previous.is_some_and(|(p, state)| {
                p.checked_add(1) == Some(seq)
                    && before.is_some_and(|b| b & 0x200b == state & 0x200b)
            });
            if !consecutive {
                group.clear();
                anchored = false;
            }
            if before.is_some_and(|b| b & 0x2009 == 0) && after.is_some_and(|a| a & 0x2009 == 1) {
                group.clear();
                anchored = false;
                group.push(seq);
            } else if !group.is_empty() {
                group.push(seq);
            }
            if !group.is_empty() {
                anchored |= anchor;
            }
            if after.is_some_and(|a| a & 0x2009 == 0) && !group.is_empty() {
                if anchored {
                    selected.extend(group.iter().map(|s| (connection.clone(), *s)));
                    if let Some(cleanup) = seq.checked_add(1) {
                        selected.insert((connection.clone(), cleanup));
                    }
                }
                group.clear();
                anchored = false;
            }
            previous = after.map(|a| (seq, a));
        }
    }
    Ok(selected)
}
