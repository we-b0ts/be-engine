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
    tables: HashMap<String, Posting>,
    unknown: Posting,
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
            Some(table) => self.tables.entry(table.to_owned()).or_default(),
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
            Some(table) => scope.tables.get_mut(table).expect("indexed MySQL table"),
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
                if let Some(posting) = scope.tables.get(table) {
                    append(posting);
                }
            }
            None => scope.tables.values().for_each(&mut append),
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
        anchor: impl FnOnce(Option<Clock>) -> Option<Clock>,
    ) -> Option<Selection> {
        let scope = self.scopes.get(key)?;
        let known = scope.tables.get(table)?;
        let anchor = anchor(scope.last_matched)?;
        let next = known.range((anchor, 0)..).next().map(|&(time, _)| time);
        let cutoff = match next {
            Some(t1) => t1.checked_add_signed(chrono::TimeDelta::seconds(3))?,
            None => anchor,
        };
        let postings = [known, &scope.unknown];
        let mut forward = Vec::new();
        if let Some(t1) = next {
            for posting in postings {
                forward.extend(posting.range((t1, 0)..=(cutoff, usize::MAX)).copied());
            }
            forward.sort_unstable();
        }
        let mut earlier = Vec::new();
        for posting in postings {
            earlier.extend(
                posting
                    .range(..=(next.unwrap_or(anchor), usize::MAX))
                    .take_while(|(at, _)| next.is_none_or(|t1| *at < t1))
                    .map(|&(_, index)| index),
            );
        }
        earlier.sort_unstable();
        Some(Selection {
            indices: forward
                .into_iter()
                .map(|(_, index)| index)
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
                    ("orders".into(), bucket(&[(3, 1), (9, 2), (4, 5), (5, 7)])),
                    ("unrelated".into(), bucket(&[(3, 4)])),
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
                        bucket(&[(3, 1), (12, 7), (15, 2), (16, 3)]),
                    ),
                    ("unrelated".into(), bucket(&[(9, 4)])),
                ]
                .into(),
                unknown: bucket(&[(8, 5), (14, 6), (18, 8)]),
                last_matched: Some(at(9)),
            },
        );
        let selection = windows.optimistic(&key, "orders", |anchor| anchor).unwrap();
        assert!(selection.candidate_first);
        assert_eq!(selection.cutoff, at(15));
        assert_eq!(selection.indices, [7, 6, 2, 1, 5]);
    }
}
