//! Source ordering for writes and invalidation boundaries at Redis storage locations.
use std::{collections::HashMap, sync::OnceLock};

use chrono::{DateTime, Utc};
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::Endpoint;
use uuid::Uuid;

use super::Location;

type Clock = DateTime<Utc>;

#[derive(Debug, Clone, Copy)]
pub struct Stamp {
    pub(super) index: usize,
    connection: Option<Uuid>,
    sequence: Option<u64>,
    start: Option<Clock>,
    end: Option<Clock>,
}

impl Stamp {
    pub fn from_record(index: usize, reference: &ProtocolRef, event: &Value) -> Self {
        let clock = |value: &Value| value.as_str()?.parse().ok();
        let start = clock(&event["request_started_at"]);
        let end = clock(&event["timestamp"]);
        let (start, end) = if matches!((start, end), (Some(start), Some(end)) if end < start) {
            (None, None)
        } else {
            (start, end)
        };
        Self {
            index,
            connection: reference.fields()["connection_id"]
                .as_str()
                .and_then(|value| value.parse().ok()),
            sequence: reference.fields()["sequence"].as_u64(),
            start,
            end,
        }
    }

    fn bounds(self) -> Bounds {
        Bounds {
            start: self.start,
            end: self.end,
            lane: self
                .connection
                .zip(self.sequence)
                .map(|(connection, sequence)| Lane {
                    connection,
                    first: sequence,
                    last: sequence,
                }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Effect {
    pub(super) stamp: Stamp,
    // A fence has no stored argument to read.
    pub(super) argument: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct Lane {
    connection: Uuid,
    first: u64,
    last: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bounds {
    start: Option<Clock>,
    end: Option<Clock>,
    lane: Option<Lane>,
}

impl Bounds {
    fn precedes(self, other: Self) -> bool {
        if let (Some(left), Some(right)) = (self.lane, other.lane)
            && left.connection == right.connection
        {
            return left.last < right.first;
        }
        self.end
            .zip(other.start)
            .is_some_and(|(end, start)| end < start)
    }

    fn union(self, other: Self) -> Self {
        Self {
            start: self
                .start
                .zip(other.start)
                .map(|(left, right)| left.min(right)),
            end: self.end.zip(other.end).map(|(left, right)| left.max(right)),
            lane: self.lane.zip(other.lane).and_then(|(left, right)| {
                (left.connection == right.connection).then_some(Lane {
                    connection: left.connection,
                    first: left.first.min(right.first),
                    last: left.last.max(right.last),
                })
            }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Span {
    Effect(Effect),
    Overlap(Bounds),
}

impl Span {
    fn bounds(self) -> Bounds {
        match self {
            Self::Effect(effect) => effect.stamp.bounds(),
            Self::Overlap(bounds) => bounds,
        }
    }

    fn does_not_supersede(self, write: Effect) -> bool {
        if let Self::Effect(effect) = self
            && effect.stamp.index == write.stamp.index
        {
            return effect.argument.is_some();
        }
        self.bounds().precedes(write.stamp.bounds())
    }
}

/// An earlier known boundary implies one for all its ordered predecessors.
/// Keep only boundaries that improve the corresponding prefix or suffix.
#[derive(Debug)]
struct Cutoffs<T> {
    starts: Vec<(T, usize)>,
    ends: Vec<(T, usize)>,
}

impl<T> Default for Cutoffs<T> {
    fn default() -> Self {
        Self {
            starts: Vec::new(),
            ends: Vec::new(),
        }
    }
}

impl<T: Copy + Ord> Cutoffs<T> {
    fn record(&mut self, index: usize, start: Option<T>, end: Option<T>) {
        if let Some(start) = start
            && self
                .starts
                .last()
                .is_none_or(|(previous, _)| *previous < start)
        {
            self.starts.push((start, index));
        }
        if let Some(end) = end {
            while self
                .ends
                .last()
                .is_some_and(|(previous, _)| *previous >= end)
            {
                self.ends.pop();
            }
            self.ends.push((end, index));
        }
    }

    fn before(&self, start: Option<T>) -> Option<usize> {
        let start = start?;
        let cut = self.ends.partition_point(|(end, _)| *end < start);
        cut.checked_sub(1).map(|index| self.ends[index].1)
    }

    fn after(&self, end: Option<T>) -> Option<usize> {
        let end = end?;
        let cut = self.starts.partition_point(|(start, _)| *start <= end);
        self.starts.get(cut).map(|(_, index)| *index)
    }
}

#[derive(Debug, Default)]
struct Search {
    clock: Cutoffs<Clock>,
    lanes: HashMap<Uuid, Cutoffs<u64>>,
}

impl Search {
    fn new(spans: &[Span], uniform_lane: Option<Uuid>) -> Self {
        let mut search = Self::default();
        for (index, span) in spans.iter().enumerate() {
            let bounds = span.bounds();
            search.clock.record(index, bounds.start, bounds.end);
            if uniform_lane.is_none()
                && let Some(lane) = bounds.lane
            {
                search.lanes.entry(lane.connection).or_default().record(
                    index,
                    Some(lane.first),
                    Some(lane.last),
                );
            }
        }
        search
    }

    fn cuts(&self, spans: &[Span], read: Stamp) -> (usize, usize) {
        let bounds = read.bounds();
        let lane = read
            .connection
            .and_then(|connection| self.lanes.get(&connection));
        let before = self
            .clock
            .before(read.start)
            .filter(|index| spans[*index].bounds().precedes(bounds))
            .max(lane.and_then(|lane| lane.before(read.sequence)));
        let after = self
            .clock
            .after(read.end)
            .filter(|index| bounds.precedes(spans[*index].bounds()));
        let after = match (after, lane.and_then(|lane| lane.after(read.sequence))) {
            (Some(clock), Some(lane)) => clock.min(lane),
            (Some(index), None) | (None, Some(index)) => index,
            (None, None) => spans.len(),
        };
        (before.map_or(0, |index| index + 1), after)
    }
}

#[derive(Debug, Default)]
struct Timeline {
    spans: Vec<Span>,
    last_index: Option<usize>,
    uniform_lane: Option<Uuid>,
    has_wall_bounds: bool,
    search: OnceLock<Box<Search>>,
}

impl Timeline {
    fn record(&mut self, effect: Effect) {
        if self.last_index == Some(effect.stamp.index) {
            return;
        }
        let lane = effect.stamp.bounds().lane.map(|lane| lane.connection);
        if self.last_index.is_none() {
            self.uniform_lane = lane;
            self.spans.reserve_exact(1);
        } else if self.uniform_lane != lane {
            self.uniform_lane = None;
        }
        self.has_wall_bounds |= effect.stamp.start.is_some() || effect.stamp.end.is_some();
        self.last_index = Some(effect.stamp.index);
        self.search.take();
        let mut span = Span::Effect(effect);
        while let Some(previous) = self.spans.last().copied() {
            if previous.bounds().precedes(span.bounds()) {
                break;
            }
            self.spans.pop();
            span = Span::Overlap(previous.bounds().union(span.bounds()));
        }
        self.spans.push(span);
    }

    fn prepare(&self) {
        if self.spans.len() > 1 && (self.uniform_lane.is_none() || self.has_wall_bounds) {
            self.search
                .get_or_init(|| Box::new(Search::new(&self.spans, self.uniform_lane)));
        }
    }

    fn before(&self, read: Stamp) -> Result<Option<Span>, Ambiguous> {
        let bounds = read.bounds();
        let span = match self.spans.as_slice() {
            [] => return Ok(None),
            [span] => {
                if matches!(span, Span::Effect(effect) if effect.stamp.index == read.index)
                    || bounds.precedes(span.bounds())
                {
                    return Ok(None);
                }
                return span
                    .bounds()
                    .precedes(bounds)
                    .then_some(Some(*span))
                    .ok_or(Ambiguous);
            }
            spans => spans,
        };
        let (before, after) = if read.connection.is_some()
            && read.connection == self.uniform_lane
            && let Some(sequence) = read.sequence
        {
            let lane = |span: &Span| span.bounds().lane.expect("uniform Source lane");
            (
                span.partition_point(|span| lane(span).last < sequence),
                span.partition_point(|span| lane(span).first <= sequence),
            )
        } else {
            self.prepare();
            let search = self.search.get().ok_or(Ambiguous)?;
            search.cuts(span, read)
        };
        if before != after {
            return Err(Ambiguous);
        }
        Ok(before.checked_sub(1).map(|index| span[index]))
    }
}

#[derive(Debug)]
struct Ambiguous;

#[derive(Debug, Default)]
pub struct ScopeHistory {
    locations: HashMap<Endpoint, HashMap<Location, Timeline>>,
    prepared: bool,
}

impl ScopeHistory {
    pub fn record(
        &mut self,
        endpoint: &Endpoint,
        location: Location,
        stamp: Stamp,
        argument: Option<usize>,
    ) {
        self.prepared = false;
        let locations = match self.locations.get_mut(endpoint) {
            Some(locations) => locations,
            None => self.locations.entry(endpoint.clone()).or_default(),
        };
        locations
            .entry(location)
            .or_default()
            .record(Effect { stamp, argument });
    }

    pub fn prepare(&mut self) {
        if !self.prepared {
            for timeline in self.locations.values().flat_map(HashMap::values) {
                timeline.prepare();
            }
            self.prepared = true;
        }
    }

    /// Return the single latest write when it follows all completed related
    /// operations and the read precedes all operations outside that prefix.
    pub(super) fn writer(
        &self,
        run: &Self,
        endpoint: &Endpoint,
        read: Stamp,
        value: &Location,
    ) -> Option<Effect> {
        let mut tails = Vec::new();
        for location in value.related() {
            for scope in [self, run] {
                if let Some(timeline) = scope
                    .locations
                    .get(endpoint)
                    .and_then(|keys| keys.get(&location))
                    && let Some(tail) = timeline.before(read).ok()?
                {
                    tails.push(tail);
                }
            }
        }
        tails.iter().find_map(|span| {
            let Span::Effect(write) = *span else {
                return None;
            };
            (write.argument.is_some() && tails.iter().all(|tail| tail.does_not_supersede(write)))
                .then_some(write)
        })
    }
}

#[cfg(test)]
mod tests;
