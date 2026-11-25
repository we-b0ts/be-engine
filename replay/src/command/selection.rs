//! Native candidate traversal preserves the common scope and lane precedence.
use super::*;

pub fn prefer_scopes(
    case_match: PreferredMatch,
    run: impl FnOnce() -> PreferredMatch,
) -> PreferredMatch {
    if matches!(case_match, PreferredMatch::Matched(_)) {
        return case_match;
    }
    let run_match = run();
    if matches!(run_match, PreferredMatch::Matched(_)) {
        return run_match;
    }
    match (case_match, run_match) {
        (blocked @ PreferredMatch::LaneBlocked { .. }, _) => blocked,
        (_, blocked @ PreferredMatch::LaneBlocked { .. }) => blocked,
        _ => PreferredMatch::NotFound,
    }
}

pub fn match_candidates_in_scope<T: CommandExchangeScope>(
    exchanges: &(impl std::ops::Index<usize, Output = T> + ?Sized),
    candidates: impl IntoIterator<Item = usize>,
    source: ReplaySource,
    case_id: Option<&str>,
    matches: &impl Fn(&T, Option<&T>) -> bool,
    priority: &impl Fn(&T) -> bool,
    lane_blocker: &impl Fn(usize) -> Option<usize>,
) -> PreferredMatch {
    let mut first_blocked = None;
    let mut first_match = None;
    let mut priority_blocked = None;
    for index in candidates {
        let exchange = &exchanges[index];
        let blocker = priority_blocked.map(|(_, blocker)| &exchanges[blocker]);
        if !scope_matches(exchange, source, case_id) || !matches(exchange, blocker) {
            continue;
        }
        if let Some(blocker) = lane_blocker(index) {
            first_blocked.get_or_insert((index, blocker));
            if priority(exchange) {
                priority_blocked.get_or_insert((index, blocker));
            }
        } else if priority(exchange) {
            return PreferredMatch::Matched(index);
        } else {
            first_match.get_or_insert(index);
        }
    }
    if let Some((candidate, blocker)) = priority_blocked {
        return PreferredMatch::LaneBlocked { candidate, blocker };
    }
    if let Some(index) = first_match {
        return PreferredMatch::Matched(index);
    }
    first_blocked.map_or(PreferredMatch::NotFound, |(candidate, blocker)| {
        PreferredMatch::LaneBlocked { candidate, blocker }
    })
}

pub fn preferred_match_indexed_with_priority<T: CommandExchangeScope>(
    exchanges: &(impl std::ops::Index<usize, Output = T> + ?Sized),
    active_case_id: Option<&str>,
    case_candidates: impl IntoIterator<Item = usize>,
    run_candidates: impl IntoIterator<Item = usize>,
    matches: impl Fn(&T, Option<&T>) -> bool,
    priority: impl Fn(&T) -> bool,
    lane_blocker: impl Fn(usize) -> Option<usize>,
) -> PreferredMatch {
    let case_match = match_candidates_in_scope(
        exchanges,
        case_candidates,
        ReplaySource::Case,
        active_case_id,
        &matches,
        &priority,
        &lane_blocker,
    );
    prefer_scopes(case_match, || {
        match_candidates_in_scope(
            exchanges,
            run_candidates,
            ReplaySource::Startup,
            None,
            &matches,
            &priority,
            &lane_blocker,
        )
    })
}
