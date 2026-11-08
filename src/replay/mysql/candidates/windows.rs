//! Source-time MySQL postings for ordered fast replay.
use super::*;
use std::collections::{BTreeSet, HashMap};
type Clock = chrono::DateTime<chrono::Utc>;
type Posting = BTreeSet<(Clock, usize)>;

pub(in crate::replay::mysql) struct Selection {
    pub(in crate::replay::mysql) indices: Vec<usize>,
    pub(in crate::replay::mysql) candidate_first: bool,
    pub(super) cutoff: Clock,
}

#[derive(Debug, Default)]
pub(super) struct Windows {
    scopes: HashMap<MysqlKey, Scope>,
    members: HashMap<usize, Member>,
}

#[derive(Debug, Default)]
struct Scope {
    tables: HashMap<String, TablePosting>,
    unknown: Posting,
    last_matched: Option<Clock>,
}

#[derive(Debug, Default)]
struct TablePosting {
    available: Posting,
    last_matched: Option<Clock>,
}

#[derive(Debug)]
struct Member {
    key: MysqlKey,
    table: Option<String>,
    at: Clock,
}

impl Scope {
    fn bucket(&mut self, table: Option<&str>) -> &mut Posting {
        match table {
            Some(table) => &mut self.tables.entry(table.to_owned()).or_default().available,
            None => &mut self.unknown,
        }
    }
}

impl Windows {
    pub(super) fn register(
        &mut self,
        key: MysqlKey,
        table: Option<&str>,
        index: usize,
        exchange: &ReplayExchange,
    ) {
        if exchange.source != ReplaySource::Case || key.command != MysqlCommand::Sql {
            return;
        }
        let scope = self.scopes.entry(key.clone()).or_default();
        let Some(at) = exchange.record.request_started_at else {
            return;
        };
        let posting = scope.bucket(table);
        if exchange.status.is_available() {
            posting.insert((at, index));
        }
        self.members.insert(
            index,
            Member {
                key,
                table: table.map(str::to_owned),
                at,
            },
        );
    }

    pub(super) fn claimed(&mut self, index: usize) {
        let Some(member) = self.members.get(&index) else {
            return;
        };
        let scope = self
            .scopes
            .get_mut(&member.key)
            .expect("indexed MySQL scope");
        let bucket = match member.table.as_deref() {
            Some(table) => {
                let table = scope.tables.get_mut(table).expect("indexed MySQL table");
                table.last_matched = table.last_matched.max(Some(member.at));
                &mut table.available
            }
            None => &mut scope.unknown,
        };
        bucket.remove(&(member.at, index));
        scope.last_matched = scope.last_matched.max(Some(member.at));
    }

    pub(super) fn select(
        &self,
        key: &MysqlKey,
        table: Option<&str>,
        cutoff: impl FnOnce(Option<Clock>) -> Option<Clock>,
    ) -> Option<Selection> {
        let scope = self.scopes.get(key)?;
        let cutoff = cutoff(scope.last_matched)?;
        let mut indices = Vec::new();
        let mut append = |posting: &Posting| {
            indices.extend(
                posting
                    .range(..=(cutoff, usize::MAX))
                    .map(|&(_, index)| index),
            );
        };
        match table {
            Some(table) => {
                if let Some(table) = scope.tables.get(table) {
                    append(&table.available);
                }
            }
            None => scope
                .tables
                .values()
                .for_each(|table| append(&table.available)),
        }
        append(&scope.unknown);
        // Time controls membership. Native order still chooses among members.
        indices.sort_unstable();
        Some(Selection {
            indices,
            candidate_first: false,
            cutoff,
        })
    }

    pub(super) fn optimistic(
        &self,
        key: &MysqlKey,
        table: &str,
        dispatch_prefix: Option<std::ops::Range<Clock>>,
        anchor: impl Fn(Option<Clock>) -> Option<Clock>,
    ) -> Option<Selection> {
        let scope = self.scopes.get(key)?;
        let table = scope.tables.get(table)?;
        let known = &table.available;
        // Traffic on another table can run ahead of this table's first read.
        let table_anchor = anchor(table.last_matched)?;
        let next = known
            .range((table_anchor, 0)..)
            .next()
            .map(|&(time, _)| time);
        let cutoff = match next {
            Some(t1) => t1.checked_add_signed(chrono::TimeDelta::seconds(3))?,
            None => anchor(scope.last_matched)?,
        };
        let mut due = Vec::new();
        let mut forward = Vec::new();
        let mut earlier = Vec::new();
        for posting in [known, &scope.unknown] {
            for &(at, index) in posting.range(..=(cutoff, usize::MAX)) {
                if dispatch_prefix
                    .as_ref()
                    .is_some_and(|prefix| prefix.contains(&at))
                {
                    // Later identical SQL cannot replace an exchange that the next input awaits.
                    due.push(index);
                } else if next.is_some_and(|t1| at >= t1) {
                    forward.push((at, index));
                } else {
                    earlier.push(index);
                }
            }
        }
        due.sort_unstable();
        forward.sort_unstable();
        earlier.sort_unstable();
        Some(Selection {
            indices: due
                .into_iter()
                .chain(forward.into_iter().map(|(_, index)| index))
                .chain(earlier)
                .collect(),
            candidate_first: true,
            cutoff,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(offset: i64) -> Clock {
        Clock::from_timestamp(offset, 0).unwrap()
    }

    fn bucket(entries: &[(i64, usize)]) -> Posting {
        entries.iter().map(|&(t, index)| (at(t), index)).collect()
    }

    fn table(entries: &[(i64, usize)], last_matched: Option<Clock>) -> TablePosting {
        TablePosting {
            available: bucket(entries),
            last_matched,
        }
    }

    #[test]
    fn cutoff_keeps_old_unclaimed_slots_and_excludes_newer_clock_inversions() {
        let key = MysqlKey {
            scope: ScopePartition::new(ReplaySource::Case, Some("case")),
            host: "mysql".into(),
            port: 3306,
            database: None,
            username: None,
            command: MysqlCommand::Sql,
        };
        let mut windows = Windows::default();
        windows.scopes.insert(
            key.clone(),
            Scope {
                tables: [
                    (
                        "orders".into(),
                        table(&[(3, 1), (9, 2), (4, 5), (5, 7)], None),
                    ),
                    ("unrelated".into(), table(&[(3, 4)], None)),
                ]
                .into(),
                unknown: bucket(&[(2, 3), (11, 6)]),
                last_matched: None,
            },
        );
        windows.members.insert(
            5,
            Member {
                key: key.clone(),
                table: Some("orders".into()),
                at: at(4),
            },
        );
        windows.claimed(5);
        let selection = windows
            .select(&key, Some("orders"), |anchor| {
                assert_eq!(anchor, Some(at(4)));
                Some(at(5))
            })
            .unwrap();
        assert_eq!(selection.indices, [1, 3, 7]);
    }

    #[test]
    fn optimistic_window_starts_at_next_same_table_and_then_checks_older_slots() {
        let key = MysqlKey {
            scope: ScopePartition::new(ReplaySource::Case, Some("case")),
            host: "mysql".into(),
            port: 3306,
            database: None,
            username: None,
            command: MysqlCommand::Sql,
        };
        let mut windows = Windows::default();
        windows.scopes.insert(
            key.clone(),
            Scope {
                tables: [
                    (
                        "orders".into(),
                        table(&[(3, 1), (12, 7), (15, 2), (16, 3)], Some(at(9))),
                    ),
                    ("unrelated".into(), table(&[(14, 4)], None)),
                ]
                .into(),
                unknown: bucket(&[(8, 5), (14, 6), (18, 8)]),
                last_matched: Some(at(9)),
            },
        );
        windows.members.insert(
            4,
            Member {
                key: key.clone(),
                table: Some("unrelated".into()),
                at: at(14),
            },
        );
        windows.claimed(4);
        let selection = windows
            .optimistic(&key, "orders", None, |anchor| anchor)
            .unwrap();
        assert!(selection.candidate_first);
        assert_eq!(selection.cutoff, at(15));
        assert_eq!(selection.indices, [7, 6, 2, 1, 5]);
        let due = windows
            .optimistic(&key, "orders", Some(at(2)..at(10)), |anchor| anchor)
            .unwrap();
        assert_eq!(due.indices, [1, 5, 7, 6, 2]);
    }
}
