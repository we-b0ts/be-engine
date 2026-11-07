//! Source-time fences and live MySQL postings for ordered fast replay.
use super::*;
use std::collections::{BTreeSet, HashMap};
use std::ops::Bound::{Excluded, Unbounded};

type Clock = chrono::DateTime<chrono::Utc>;

#[derive(Debug, Default)]
pub(super) struct Windows {
    scopes: HashMap<MysqlKey, Scope>,
    members: HashMap<usize, Member>,
}

#[derive(Debug, Default)]
struct Scope {
    tables: HashMap<String, Bucket>,
    unknown: Bucket,
    last_matched: Option<Clock>,
}

#[derive(Debug, Default)]
struct Bucket {
    live: BTreeSet<usize>,
    fences: Vec<(Clock, usize)>,
    prefix_ranks: Vec<usize>,
}

#[derive(Debug)]
struct Member {
    key: MysqlKey,
    table: Option<String>,
    at: Option<Clock>,
}

impl Scope {
    fn bucket(&mut self, table: Option<&str>) -> &mut Bucket {
        match table {
            Some(table) => self.tables.entry(table.to_owned()).or_default(),
            None => &mut self.unknown,
        }
    }
}

impl Bucket {
    fn seal(&mut self) {
        if self.prefix_ranks.len() == self.fences.len() {
            return;
        }
        self.fences.sort_unstable();
        self.prefix_ranks.clear();
        let mut maximum = 0;
        for (_, index) in &self.fences {
            maximum = maximum.max(*index);
            self.prefix_ranks.push(maximum);
        }
    }

    fn last_rank_before(&self, cutoff: Clock) -> Option<usize> {
        let end = self.fences.partition_point(|(at, _)| *at <= cutoff);
        end.checked_sub(1).map(|index| self.prefix_ranks[index])
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
        let at = contracts::source_started(&exchange.record);
        let bucket = self.scopes.entry(key.clone()).or_default().bucket(table);
        if exchange.status.is_available() {
            bucket.live.insert(index);
        }
        if let Some(at) = at {
            bucket.fences.push((at, index));
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

    pub(super) fn seal(&mut self) {
        for scope in self.scopes.values_mut() {
            scope.unknown.seal();
            for bucket in scope.tables.values_mut() {
                bucket.seal();
            }
        }
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
        bucket.live.remove(&index);
        scope.last_matched = scope.last_matched.max(member.at);
    }

    pub(super) fn select(
        &self,
        key: &MysqlKey,
        table: &str,
        cutoff: impl FnOnce(Option<Clock>) -> Option<Clock>,
    ) -> Option<Selection<'_>> {
        let scope = self.scopes.get(key)?;
        let cutoff = cutoff(scope.last_matched)?;
        let known = scope.tables.get(table);
        let unknown = &scope.unknown;
        // Preserve original candidate order across overlapping Source requests.
        // An earlier native rank stays in the prefix even if its clock is later.
        let last_rank = known
            .and_then(|bucket| bucket.last_rank_before(cutoff))
            .max(unknown.last_rank_before(cutoff));
        Some(Selection {
            known: known.map(|bucket| &bucket.live),
            unknown: &unknown.live,
            last_rank,
        })
    }
}

pub(in crate::replay::mysql) struct Selection<'a> {
    known: Option<&'a BTreeSet<usize>>,
    unknown: &'a BTreeSet<usize>,
    last_rank: Option<usize>,
}

impl Selection<'_> {
    pub(in crate::replay::mysql) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        let prefix = self.last_rank.into_iter().flat_map(|last| {
            merge(
                self.known
                    .into_iter()
                    .flat_map(move |set| set.range(..=last)),
                self.unknown.range(..=last),
            )
        });
        let after = self.last_rank.map_or(Unbounded, Excluded);
        prefix.chain(merge(
            self.known
                .into_iter()
                .flat_map(move |set| set.range((after, Unbounded))),
            self.unknown.range((after, Unbounded)),
        ))
    }
}

fn merge<'a>(
    left: impl Iterator<Item = &'a usize>,
    right: impl Iterator<Item = &'a usize>,
) -> impl Iterator<Item = usize> {
    let mut left = left.copied().peekable();
    let mut right = right.copied().peekable();
    std::iter::from_fn(move || match (left.peek(), right.peek()) {
        (Some(a), Some(b)) if a <= b => left.next(),
        (_, Some(_)) => right.next(),
        _ => left.next(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(offset: i64) -> Clock {
        Clock::from_timestamp(offset, 0).unwrap()
    }

    fn bucket(entries: &[(i64, usize)]) -> Bucket {
        let mut bucket = Bucket {
            live: entries.iter().map(|(_, index)| *index).collect(),
            fences: entries.iter().map(|&(t, index)| (at(t), index)).collect(),
            prefix_ranks: Vec::new(),
        };
        bucket.seal();
        bucket
    }

    #[test]
    fn cutoff_keeps_older_unclaimed_slots_and_native_order_with_clock_inversions() {
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
                    ("orders".into(), bucket(&[(2, 1), (9, 2), (4, 5), (8, 7)])),
                    ("unrelated".into(), bucket(&[(3, 4)])),
                ]
                .into(),
                unknown: bucket(&[(3, 3), (11, 6)]),
                last_matched: None,
            },
        );
        windows.members.insert(
            5,
            Member {
                key: key.clone(),
                table: Some("orders".into()),
                at: Some(at(4)),
            },
        );
        windows.claimed(5);
        let selection = windows
            .select(&key, "orders", |anchor| {
                assert_eq!(anchor, Some(at(4)));
                Some(at(5))
            })
            .unwrap();
        assert_eq!(selection.last_rank, Some(5));
        // Both previous unclaimed requests and clock-ambiguous requests
        // precede the suffix in the original native order.
        assert_eq!(selection.iter().collect::<Vec<_>>(), [1, 2, 3, 6, 7]);
    }
}
