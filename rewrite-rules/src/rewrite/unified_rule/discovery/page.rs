//! Stateless bounded scan windows and independently paged public summaries.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub primary_case: usize,
    pub primary_event: usize,
    pub dependency: usize,
    pub summary: usize,
    pub primary_first: bool,
}

impl Cursor {
    pub fn initial(state: &RewriteState) -> Self {
        Self {
            primary_first: state.active_issue.as_ref().is_some_and(|issue| {
                issue.kind == super::super::super::model::RewriteIssueKind::Response
            }),
            ..Self::default()
        }
    }

    pub fn encode(self) -> String {
        format!(
            "{}.{}.{}.{}.{}",
            self.primary_case,
            self.primary_event,
            self.dependency,
            self.summary,
            u8::from(self.primary_first)
        )
    }

    pub fn parse(value: &str) -> Option<Self> {
        if value.len() > 128 {
            return None;
        }
        let parts = value.split('.').collect::<Vec<_>>();
        let [case, event, dependency, summary, first] = parts.as_slice() else {
            return None;
        };
        let cursor = Self {
            primary_case: case.parse().ok()?,
            primary_event: event.parse().ok()?,
            dependency: dependency.parse().ok()?,
            summary: summary.parse().ok()?,
            primary_first: match *first {
                "0" => false,
                "1" => true,
                _ => return None,
            },
        };
        (cursor.encode() == value
            && cursor.summary.is_multiple_of(LIMIT)
            && cursor.summary.checked_add(LIMIT).is_some())
        .then_some(cursor)
    }
}

impl Drafts {
    pub fn add_entry(&mut self, identity: String, entry: Value) {
        if self.entry_ids.insert(identity)
            && self.entry_ids.len() > self.summary_offset
            && self.entries.len() < LIMIT
        {
            self.entries.push(entry);
        }
    }

    pub fn summary_limited(&self) -> bool {
        self.seen.len() > self.values.len() || self.entry_ids.len() > self.entries.len()
    }

    pub fn has_summary_page(&self) -> bool {
        self.seen.len().max(self.entry_ids.len()) > self.summary_offset + LIMIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_cursor_requires_canonical_bounded_arithmetic() {
        for invalid in [
            "",
            "0.0.0.0",
            "00.0.0.0.1",
            "0.0.0.1.1",
            "0.0.0.20.2",
            "-1.0.0.0.1",
        ] {
            assert!(Cursor::parse(invalid).is_none(), "{invalid}");
        }
        let cursor = Cursor {
            primary_case: 7,
            primary_event: 256,
            dependency: 300,
            summary: 20,
            primary_first: true,
        };
        assert_eq!(Cursor::parse(&cursor.encode()), Some(cursor));
    }
}
