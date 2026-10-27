//! Bounded failure evidence distinguishes absent members from reordered delivery.
use super::*;
use serde::Serialize;

const MEMBER_LIMIT: usize = 32;

#[derive(Debug, Serialize)]
pub(super) struct MemberComparison {
    source_member_count: usize,
    target_member_count: usize,
    source_members: Vec<MemberReference>,
    target_members: Vec<MemberReference>,
    source_members_omitted: usize,
    target_members_omitted: usize,
    first_difference: Option<MemberDifference>,
    observed_end: String,
    target_trace_valid: bool,
}

#[derive(Debug, Serialize)]
struct MemberReference {
    recorded_index: usize,
    source_connection_id: Option<Uuid>,
    source_query_sequence: Option<u64>,
}

#[derive(Debug, Serialize)]
struct MemberDifference {
    member_position: usize,
    expected: Option<MemberReference>,
    actual: Option<MemberReference>,
}

impl Registry {
    pub(super) fn retain_member_comparison(
        &mut self,
        (r, t): (usize, usize),
        trace: &Trace,
        observed_end: &str,
    ) {
        if self.requirements[r].blocked {
            return;
        }
        let expected = &self.requirements[r].transactions[t].members;
        let actual = &trace.members;
        let first_difference = (0..expected.len().max(actual.len()))
            .find(|&position| expected.get(position) != actual.get(position))
            .map(|member_position| MemberDifference {
                member_position,
                expected: expected
                    .get(member_position)
                    .map(|&i| self.member_reference(i)),
                actual: actual
                    .get(member_position)
                    .map(|&i| self.member_reference(i)),
            });
        let comparison = MemberComparison {
            source_member_count: expected.len(),
            target_member_count: actual.len(),
            source_members: expected
                .iter()
                .take(MEMBER_LIMIT)
                .map(|&i| self.member_reference(i))
                .collect(),
            target_members: actual
                .iter()
                .take(MEMBER_LIMIT)
                .map(|&i| self.member_reference(i))
                .collect(),
            source_members_omitted: expected.len().saturating_sub(MEMBER_LIMIT),
            target_members_omitted: actual.len().saturating_sub(MEMBER_LIMIT),
            first_difference,
            observed_end: observed_end.to_owned(),
            target_trace_valid: trace.valid,
        };
        self.requirements[r].transactions[t].member_comparison = Some(comparison);
    }

    fn member_reference(&self, recorded_index: usize) -> MemberReference {
        let source = self
            .members
            .get(&recorded_index)
            .or_else(|| self.ends.get(&recorded_index))
            .and_then(|&(r, t)| {
                let group = &self.requirements[r].transactions[t];
                let position = group
                    .members
                    .iter()
                    .position(|&index| index == recorded_index)?;
                Some((group.source_connection_id, group.member_sequences[position]))
            });
        MemberReference {
            recorded_index,
            source_connection_id: source.map(|(connection, _)| connection),
            source_query_sequence: source.map(|(_, sequence)| sequence),
        }
    }
}
