//! Disjoint Source publication intervals identify finite repeated adapter echoes.
use super::*;
use chrono::{DateTime, Utc};

pub(super) type WireIdentity = (Uuid, u64);

#[derive(Debug, Clone)]
pub(super) struct Publication {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}
impl Publication {
    pub(super) fn from_record(record: &RecordedExchange) -> Self {
        Self {
            start: record.earliest_start(),
            end: record.timestamp,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Bounds {
    start: DateTime<Utc>,
    next: Option<DateTime<Utc>>,
}
impl Bounds {
    pub(super) fn all(
        publications: &BTreeMap<WireIdentity, Publication>,
    ) -> Result<BTreeMap<WireIdentity, Self>> {
        let mut clocks = publications
            .iter()
            .map(|(id, p)| {
                let start = p.start.context("Source PUBLISH clock unavailable")?;
                let end = p
                    .end
                    .context("Source PUBLISH completion clock unavailable")?;
                ensure!(start <= end, "invalid Source PUBLISH clocks");
                Ok((*id, start, end))
            })
            .collect::<Result<Vec<_>>>()?;
        clocks.sort_by_key(|(_, start, _)| *start);
        for pair in clocks.windows(2) {
            ensure!(
                pair[0].2 < pair[1].1,
                "overlapping Source publications cannot disambiguate adapter echoes"
            );
        }
        let mut last_sequence = BTreeMap::new();
        for ((connection, sequence), _, _) in &clocks {
            ensure!(
                last_sequence
                    .insert(*connection, *sequence)
                    .is_none_or(|previous| previous < *sequence),
                "Source publication clocks disagree with wire order"
            );
        }
        Ok(clocks
            .iter()
            .enumerate()
            .map(|(position, (id, start, _))| {
                (
                    *id,
                    Self {
                        start: *start,
                        next: clocks.get(position + 1).map(|(_, start, _)| *start),
                    },
                )
            })
            .collect())
    }

    pub(super) fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && self.next.is_none_or(|next| timestamp < next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn another_publisher_cannot_hide_a_source_wire_clock_inversion() {
        let first = Uuid::new_v4();
        let other = Uuid::new_v4();
        let span = |second: u32| {
            let start = format!("2026-10-28T00:00:{second:02}Z")
                .parse::<DateTime<Utc>>()
                .unwrap();
            Publication {
                start: Some(start),
                end: Some(start),
            }
        };
        let publications = BTreeMap::from([
            ((first, 2), span(1)),
            ((other, 1), span(2)),
            ((first, 1), span(3)),
        ]);
        assert!(
            Bounds::all(&publications)
                .unwrap_err()
                .to_string()
                .contains("wire order")
        );
    }
}
