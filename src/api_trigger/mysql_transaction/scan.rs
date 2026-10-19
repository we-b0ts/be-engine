//! Select proven Source intervals from the shared rule-independent transaction index.
use super::*;
use crate::dependency_index::mysql_transactions::Facts;

type Sequences = BTreeSet<(String, u64)>;

pub(super) fn selected(summary: &Value, sequences: &Sequences) -> bool {
    summary["connection_id"]
        .as_str()
        .zip(summary["query_sequence"].as_u64())
        .is_some_and(|(conn, seq)| sequences.contains(&(conn.to_owned(), seq)))
}

pub(super) fn candidates(
    files: &[EvidenceFile],
    index: &mut OriginIndex,
    facts: &Facts,
) -> Result<Sequences> {
    let by_path: BTreeMap<_, _> = files.iter().map(|file| (&file.relative, file)).collect();
    let mut selected = Sequences::new();
    for transaction in &facts.transactions {
        if !transaction.closed {
            continue;
        }
        let mut members = Vec::new();
        let mut anchors = BTreeSet::new();
        let mut unavailable = false;
        for member in &transaction.members {
            let source = &facts.files[member.file];
            let Some(file) = by_path.get(&source.path) else {
                unavailable = true;
                break;
            };
            let summary = &source.records[member.record].summary;
            let case = file.scope_key()?;
            anchors.extend(index.witness(&case, summary).map(|w| w.rule.clone()));
            members.push((case, summary));
        }
        if unavailable || anchors.is_empty() {
            continue;
        }
        let count = if transaction.known_start {
            members.len()
        } else {
            2
        };
        selected.extend(members.iter().rev().take(count).filter_map(|(_, summary)| {
            Some((
                transaction.connection.clone(),
                summary["query_sequence"].as_u64()?,
            ))
        }));
        if let Some((case, end)) = members.last() {
            if transaction.known_start {
                if let Some(sequence) = end["query_sequence"]
                    .as_u64()
                    .and_then(|s| s.checked_add(1))
                {
                    selected.insert((transaction.connection.clone(), sequence));
                }
            } else {
                for rule in &anchors {
                    for key in [
                        crate::config::api_trigger::mysql::key(case, end),
                        crate::config::api_trigger::mysql::wire_key(case, end),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        index.selector_rejections.entry(rule.clone()).or_default().insert(key,
                            "transaction start or contiguous prefix is missing from immutable dependencies; boundary remains required".into());
                    }
                }
            }
        }
    }
    Ok(selected)
}
