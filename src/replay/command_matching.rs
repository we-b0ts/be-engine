use uuid::Uuid;

use super::ReplaySource;
use super::report::command::{CommandExchangeRefReport, CommandMatchDiagnostic};

pub(super) trait CommandExchangeScope {
    fn source(&self) -> ReplaySource;
    fn case_id(&self) -> Option<&str>;
    fn connection_id(&self) -> Uuid;
    fn sequence(&self) -> u64;
    fn command(&self) -> &str;
    fn is_available(&self) -> bool;
    fn is_consumed(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreferredMatch {
    Matched(usize),
    LaneBlocked { candidate: usize, blocker: usize },
    NotFound,
}

#[derive(Debug, Default)]
pub(super) struct CaseConnectionBinding {
    active_case_id: Option<String>,
    connection_id: Option<Uuid>,
}

impl CaseConnectionBinding {
    pub(super) fn connection(&mut self, active_case_id: Option<&str>) -> Option<Uuid> {
        self.synchronize(active_case_id);
        self.connection_id
    }

    pub(super) fn bind(&mut self, active_case_id: Option<&str>, connection_id: Uuid) {
        self.synchronize(active_case_id);
        self.connection_id.get_or_insert(connection_id);
    }

    fn synchronize(&mut self, active_case_id: Option<&str>) {
        if self.active_case_id.as_deref() != active_case_id {
            self.active_case_id = active_case_id.map(ToOwned::to_owned);
            self.connection_id = None;
        }
    }
}

pub(super) fn preferred_match<T>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    matches: impl Fn(&T) -> bool,
) -> PreferredMatch
where
    T: CommandExchangeScope,
{
    let case_match = match_in_scope(exchanges, ReplaySource::Case, active_case_id, &matches);
    if matches!(case_match, PreferredMatch::Matched(_)) {
        return case_match;
    }

    let global_match = match_in_scope(exchanges, ReplaySource::Global, None, &matches);
    if matches!(global_match, PreferredMatch::Matched(_)) {
        return global_match;
    }

    match (case_match, global_match) {
        (blocked @ PreferredMatch::LaneBlocked { .. }, _) => blocked,
        (_, blocked @ PreferredMatch::LaneBlocked { .. }) => blocked,
        _ => PreferredMatch::NotFound,
    }
}

pub(super) fn unmatched_diagnostic<T>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    mismatch_fields: impl Fn(&T) -> Vec<&'static str>,
) -> CommandMatchDiagnostic
where
    T: CommandExchangeScope,
{
    let candidates = preferred_available_scope(exchanges, active_case_id);
    let Some((_, fields)) = candidates
        .into_iter()
        .map(|index| (index, mismatch_fields(&exchanges[index])))
        .min_by_key(|(index, fields)| (fields.len(), *index))
    else {
        return CommandMatchDiagnostic::NoScopedCandidate;
    };
    CommandMatchDiagnostic::Mismatch {
        fields: fields.into_iter().map(ToOwned::to_owned).collect(),
    }
}

pub(super) fn lane_blocked_diagnostic<T>(
    exchanges: &[T],
    candidate: usize,
    blocker: usize,
) -> CommandMatchDiagnostic
where
    T: CommandExchangeScope,
{
    CommandMatchDiagnostic::LaneBlocked {
        candidate: Box::new(exchange_ref(&exchanges[candidate])),
        blocked_by: Box::new(exchange_ref(&exchanges[blocker])),
    }
}

fn match_in_scope<T>(
    exchanges: &[T],
    source: ReplaySource,
    case_id: Option<&str>,
    matches: &impl Fn(&T) -> bool,
) -> PreferredMatch
where
    T: CommandExchangeScope,
{
    let mut first_blocked = None;
    for (index, exchange) in exchanges.iter().enumerate() {
        if !scope_matches(exchange, source, case_id) || !matches(exchange) {
            continue;
        }
        if let Some(blocker) = lane_blocker(exchanges, index) {
            first_blocked.get_or_insert((index, blocker));
        } else {
            return PreferredMatch::Matched(index);
        }
    }
    first_blocked.map_or(PreferredMatch::NotFound, |(candidate, blocker)| {
        PreferredMatch::LaneBlocked { candidate, blocker }
    })
}

fn preferred_available_scope<T>(exchanges: &[T], active_case_id: Option<&str>) -> Vec<usize>
where
    T: CommandExchangeScope,
{
    let case = exchanges
        .iter()
        .enumerate()
        .filter(|(_, exchange)| {
            exchange.is_available() && scope_matches(*exchange, ReplaySource::Case, active_case_id)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if !case.is_empty() {
        return case;
    }
    exchanges
        .iter()
        .enumerate()
        .filter(|(_, exchange)| {
            exchange.is_available() && scope_matches(*exchange, ReplaySource::Global, None)
        })
        .map(|(index, _)| index)
        .collect()
}

fn lane_blocker<T>(exchanges: &[T], candidate: usize) -> Option<usize>
where
    T: CommandExchangeScope,
{
    let exchange = &exchanges[candidate];
    exchanges.iter().enumerate().find_map(|(index, other)| {
        (!other.is_consumed()
            && other.source() == exchange.source()
            && other.case_id() == exchange.case_id()
            && other.connection_id() == exchange.connection_id()
            && other.sequence() < exchange.sequence())
        .then_some(index)
    })
}

fn scope_matches<T>(exchange: &T, source: ReplaySource, case_id: Option<&str>) -> bool
where
    T: CommandExchangeScope,
{
    exchange.source() == source && (source == ReplaySource::Global || exchange.case_id() == case_id)
}

fn exchange_ref<T>(exchange: &T) -> CommandExchangeRefReport
where
    T: CommandExchangeScope,
{
    CommandExchangeRefReport {
        case_id: exchange.case_id().map(ToOwned::to_owned),
        source: exchange.source(),
        connection_id: exchange.connection_id(),
        sequence: exchange.sequence(),
        command: exchange.command().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Exchange {
        source: ReplaySource,
        case_id: Option<&'static str>,
        connection_id: Uuid,
        sequence: u64,
        consumed: bool,
    }

    impl CommandExchangeScope for Exchange {
        fn source(&self) -> ReplaySource {
            self.source
        }

        fn case_id(&self) -> Option<&str> {
            self.case_id
        }

        fn connection_id(&self) -> Uuid {
            self.connection_id
        }

        fn sequence(&self) -> u64 {
            self.sequence
        }

        fn command(&self) -> &str {
            "GET"
        }

        fn is_available(&self) -> bool {
            !self.consumed
        }

        fn is_consumed(&self) -> bool {
            self.consumed
        }
    }

    #[test]
    fn an_earlier_exchange_from_another_case_does_not_block_the_lane() {
        let connection_id = Uuid::new_v4();
        let exchanges = [
            Exchange {
                source: ReplaySource::Case,
                case_id: Some("earlier-case"),
                connection_id,
                sequence: 1,
                consumed: false,
            },
            Exchange {
                source: ReplaySource::Case,
                case_id: Some("active-case"),
                connection_id,
                sequence: 2,
                consumed: false,
            },
        ];

        assert_eq!(
            preferred_match(&exchanges, Some("active-case"), |_| true),
            PreferredMatch::Matched(1)
        );
    }

    #[test]
    fn an_earlier_exchange_in_the_same_case_blocks_the_lane() {
        let connection_id = Uuid::new_v4();
        let exchanges = [
            Exchange {
                source: ReplaySource::Case,
                case_id: Some("active-case"),
                connection_id,
                sequence: 1,
                consumed: false,
            },
            Exchange {
                source: ReplaySource::Case,
                case_id: Some("active-case"),
                connection_id,
                sequence: 2,
                consumed: false,
            },
        ];

        assert_eq!(
            preferred_match(&exchanges, Some("active-case"), |exchange| {
                exchange.sequence == 2
            }),
            PreferredMatch::LaneBlocked {
                candidate: 1,
                blocker: 0,
            }
        );
    }

    #[test]
    fn connection_binding_resets_when_the_active_case_changes() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut binding = CaseConnectionBinding::default();

        binding.bind(Some("first"), first);
        assert_eq!(binding.connection(Some("first")), Some(first));
        assert_eq!(binding.connection(Some("second")), None);
        binding.bind(Some("second"), second);
        assert_eq!(binding.connection(Some("second")), Some(second));
    }
}
