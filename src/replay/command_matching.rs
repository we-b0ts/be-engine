use uuid::Uuid;

use super::ReplaySource;
use super::report::command::{CommandExchangeRefReport, CommandMatchDiagnostic};
mod selection;
pub(super) use selection::preferred_match_indexed_with_priority;

pub(super) trait CommandExchangeScope {
    fn source(&self) -> ReplaySource;
    /// Protocol control evidence can alias its original finite slot at startup.
    /// This never changes the slot's owner or connection-order barriers.
    fn available_in_global_scope(&self) -> bool {
        self.source().is_run_owned()
    }
    fn case_id(&self) -> Option<&str>;
    fn connection_id(&self) -> Uuid;
    fn sequence(&self) -> u64;
    fn command(&self) -> &str;
    fn is_available(&self) -> bool;
    fn is_consumed(&self) -> bool;
    /// Ordering admission can precede successful response delivery. Protocols
    /// opt in explicitly; final consumption still tracks delivery and failures.
    fn satisfies_lane_order(&self) -> bool {
        self.is_consumed()
    }
    fn preserves_connection_order(&self) -> bool {
        true
    }
}

pub(super) fn is_process_lane(source: ReplaySource) -> bool {
    source == ReplaySource::Process
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreferredMatch {
    Matched(usize),
    LaneBlocked { candidate: usize, blocker: usize },
    NotFound,
}

#[derive(Debug, Default, Clone)]
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
    preferred_match_with_priority(exchanges, active_case_id, matches, |_| true)
}

/// Prefer protocol-required candidates within each ownership scope. A required
/// candidate's lane barrier remains visible instead of selecting an unrelated
/// eligible lane. Equal priorities retain recording order.
pub(super) fn preferred_match_with_priority<T>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    matches: impl Fn(&T) -> bool,
    priority: impl Fn(&T) -> bool,
) -> PreferredMatch
where
    T: CommandExchangeScope,
{
    let case_match = match_in_scope(
        exchanges,
        ReplaySource::Case,
        active_case_id,
        &matches,
        &priority,
    );
    selection::prefer_scopes(case_match, || {
        match_in_scope(exchanges, ReplaySource::Startup, None, &matches, &priority)
    })
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
    priority: &impl Fn(&T) -> bool,
) -> PreferredMatch
where
    T: CommandExchangeScope,
{
    selection::match_candidates_in_scope(
        exchanges,
        0..exchanges.len(),
        source,
        case_id,
        matches,
        priority,
        &|index| lane_blocker(exchanges, index),
    )
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
            exchange.is_available() && scope_matches(*exchange, ReplaySource::Startup, None)
        })
        .map(|(index, _)| index)
        .collect()
}

fn lane_blocker<T>(exchanges: &[T], candidate: usize) -> Option<usize>
where
    T: CommandExchangeScope,
{
    let exchange = &exchanges[candidate];
    if !exchange.preserves_connection_order() {
        return None;
    }
    exchanges.iter().enumerate().find_map(|(index, other)| {
        (other.preserves_connection_order()
            && !other.satisfies_lane_order()
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
    match source {
        ReplaySource::Startup | ReplaySource::Process => exchange.available_in_global_scope(),
        ReplaySource::Case => exchange.source() == source && exchange.case_id() == case_id,
        ReplaySource::Unattributed => false,
    }
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
        preserves_connection_order: bool,
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

        fn preserves_connection_order(&self) -> bool {
            self.preserves_connection_order
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
                preserves_connection_order: true,
            },
            Exchange {
                source: ReplaySource::Case,
                case_id: Some("active-case"),
                connection_id,
                sequence: 2,
                consumed: false,
                preserves_connection_order: true,
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
                preserves_connection_order: true,
            },
            Exchange {
                source: ReplaySource::Case,
                case_id: Some("active-case"),
                connection_id,
                sequence: 2,
                consumed: false,
                preserves_connection_order: true,
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
    fn connection_independent_background_ignores_earlier_lane_entries() {
        let connection_id = Uuid::new_v4();
        let exchanges = [
            Exchange {
                source: ReplaySource::Startup,
                case_id: None,
                connection_id,
                sequence: 1,
                consumed: false,
                preserves_connection_order: true,
            },
            Exchange {
                source: ReplaySource::Startup,
                case_id: None,
                connection_id,
                sequence: 2,
                consumed: false,
                preserves_connection_order: false,
            },
        ];

        assert_eq!(
            preferred_match(&exchanges, None, |exchange| exchange.sequence == 2),
            PreferredMatch::Matched(1)
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
