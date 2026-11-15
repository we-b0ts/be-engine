//! Allow a pending request's ACK to cross independent text business frames.
use std::ops::Range;

use super::*;

// Bound the pairwise check per changed span, including in long streams.
const MAX_CHANGED_SPAN: usize = 128;

impl Context {
    pub(super) fn align_mixed_runs(
        &self,
        source: &[Frame],
        target: &[Frame],
        offsets: &[u64],
        alignment: &mut [usize],
    ) -> Vec<Range<usize>> {
        if source.len() != target.len() || source.len() != offsets.len() {
            return Vec::new();
        }
        let mut ambiguous = BTreeSet::new();
        for frames in [source, target] {
            let mut unique = BTreeSet::new();
            for key in frames.iter().filter_map(Frame::ack) {
                if !unique.insert(key) {
                    ambiguous.insert(key);
                }
            }
        }
        let mut aligned = Vec::new();
        let mut start = 0;
        while start < source.len() {
            if matches!(source[start], Frame::Fence) {
                start += 1;
                continue;
            }
            let end = source[start..]
                .iter()
                .position(|frame| matches!(frame, Frame::Fence))
                .map_or(source.len(), |length| start + length);
            let run = start..end;
            if run.len() >= 2
                && source[run.clone()]
                    .iter()
                    .any(|frame| matches!(frame, Frame::Business(_)))
                && source[run.clone()]
                    .iter()
                    .filter_map(Frame::ack)
                    .all(|key| !ambiguous.contains(key))
                && let Some(pairs) = pair(&source[run.clone()], &target[run.clone()])
                && self.valid_crossings(&source[run.clone()], &offsets[run.clone()], &pairs)
            {
                for (slot, target_index) in alignment[run.clone()].iter_mut().zip(pairs) {
                    *slot = start + target_index;
                }
                aligned.push(run);
            }
            start = end;
        }
        aligned
    }

    fn valid_crossings(&self, source: &[Frame], offsets: &[u64], pairs: &[usize]) -> bool {
        let mut crossed_business = false;
        let mut start = 0;
        let mut furthest_target = 0;
        for (index, &target_index) in pairs.iter().enumerate() {
            furthest_target = furthest_target.max(target_index);
            if furthest_target != index {
                continue;
            }
            if start < index {
                let span = start..index + 1;
                let Some(mixed) = self.check_span(source, offsets, pairs, span) else {
                    return false;
                };
                crossed_business |= mixed;
            }
            start = index + 1;
        }
        crossed_business
    }

    fn check_span(
        &self,
        source: &[Frame],
        offsets: &[u64],
        pairs: &[usize],
        span: Range<usize>,
    ) -> Option<bool> {
        if span.len() > MAX_CHANGED_SPAN {
            return None;
        }
        let mut crossed_business = false;
        let mut crossed_acks = BTreeSet::new();
        for left in span.clone() {
            for right in left + 1..span.end {
                if pairs[left] < pairs[right] {
                    continue;
                }
                let (ack, namespace) = match (&source[left], &source[right]) {
                    (Frame::Ack(a), Frame::Ack(b)) => {
                        crossed_acks.extend([a, b]);
                        continue;
                    }
                    (Frame::Ack(ack), Frame::Business(namespace))
                    | (Frame::Business(namespace), Frame::Ack(ack)) => (ack, namespace),
                    _ => return None,
                };
                if &ack.0 != namespace || !self.can_cross(ack, offsets[left], offsets[right]) {
                    return None;
                }
                crossed_business = true;
            }
        }
        (crossed_acks.is_empty() || self.independent(&crossed_acks.into_iter().collect::<Vec<_>>()))
            .then_some(crossed_business)
    }

    fn can_cross(&self, ack: &Key, first_output: u64, last_output: u64) -> bool {
        let Some(request) = self.request(ack) else {
            return false;
        };
        // The client must already have issued the request before either
        // output. Keep the order when the Source input uses the completion
        // before the other frame or crosses an input transport boundary.
        request.offset_ms < first_output
            && first_output <= last_output
            && self
                .first_completion_uses
                .get(&request.sequence)
                .is_none_or(|&offset| offset > last_output)
            && self
                .control_offsets
                .get(
                    self.control_offsets
                        .partition_point(|&offset| offset < request.offset_ms),
                )
                .is_none_or(|&offset| offset > last_output)
    }
}

fn pair(source: &[Frame], target: &[Frame]) -> Option<Vec<usize>> {
    let mut acks = BTreeMap::new();
    let mut business = Vec::new();
    for (index, frame) in target.iter().enumerate() {
        match frame {
            Frame::Ack(key) => {
                acks.insert(key, index);
            }
            Frame::Business(namespace) => business.push((index, namespace)),
            Frame::Fence => return None,
        }
    }
    let mut business = business.into_iter();
    let pairs = source
        .iter()
        .map(|frame| match frame {
            Frame::Ack(key) => acks.remove(key),
            Frame::Business(namespace) => {
                let (index, target_namespace) = business.next()?;
                (namespace == target_namespace).then_some(index)
            }
            Frame::Fence => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (acks.is_empty() && business.next().is_none()).then_some(pairs)
}
