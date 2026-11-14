//! Bound idle business waits independently of real resource delivery time.
use super::*;

pub(super) struct NoProgress {
    timeout: Duration,
    idle_since: Option<Instant>,
    counts: Option<Vec<usize>>,
}

impl NoProgress {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            idle_since: None,
            counts: None,
        }
    }

    pub(super) fn observe(
        &mut self,
        now: Instant,
        in_flight: bool,
        counts: impl Into<Vec<usize>>,
    ) -> bool {
        let counts = counts.into();
        if in_flight
            || self
                .counts
                .as_ref()
                .is_some_and(|previous| *previous != counts)
        {
            self.idle_since = None;
        }
        self.counts = Some(counts);
        if in_flight {
            return false;
        }
        let since = *self.idle_since.get_or_insert(now);
        now.saturating_duration_since(since) >= self.timeout
    }

    pub(super) fn failure_reason(&self, remaining: usize) -> String {
        format!(
            "recorded dependencies remain unconsumed (pending: {remaining}); check whether Target executes the recorded calls. Replay stopped waiting after {} ms without Case dependency progress and with no resource I/O in flight",
            self.timeout.as_millis()
        )
    }
}

pub(in crate::replay::control) fn counts(state: &ReplayState, case: &str) -> Vec<usize> {
    let case = Some(case);
    let mut counts = vec![
        state
            .protocols
            .mysql
            .events
            .matched_query_details
            .next_event_index(case),
        state
            .protocols
            .http_events
            .matched_details
            .next_event_index(case),
        state
            .protocols
            .redis
            .events
            .matched_details
            .next_event_index(case),
        state
            .protocols
            .memcached
            .events
            .matched_details
            .next_event_index(case),
        state
            .protocols
            .motan
            .events
            .matched_details
            .next_event_index(case),
        state
            .protocols
            .kafka
            .events
            .matched_details
            .next_event_index(case),
    ];
    if !state.native.core.exchanges.is_empty() {
        counts.push(
            state
                .native
                .core
                .exchanges
                .iter()
                .filter(|exchange| {
                    exchange.source.case_id.as_deref() == case
                        && state
                            .native
                            .core
                            .lifecycle
                            .live_status(exchange.index, exchange.status)
                            .is_consumed()
                })
                .count(),
        );
    }
    counts
}

pub(super) fn waiting(
    tail: &CaseTail,
    state: &ReplayState,
    progress: &NoProgress,
    now: Instant,
    remaining: usize,
    in_flight: bool,
) -> serde_json::Value {
    let pending: Vec<_> = tail.selected.iter().filter_map(|selected| {
        let status = exchange_status(state, selected.exchange)?;
        (!status.is_consumed()
            && !permits_tail_omission(state, selected)
)
            .then(|| serde_json::json!({"reference":selected.reference,"state":format!("{status:?}")}))
    }).take(8).collect();
    serde_json::json!({
        "no_progress_timeout_ms":progress.timeout.as_millis(),
        "source_post_input_allowance_ms":tail.interaction_post_input.map(|allowance| allowance.as_millis()),
        "idle_ms":progress.idle_since.map(|since| now.saturating_duration_since(since).as_millis()).unwrap_or_default(),
        "actual_io_in_flight":in_flight,
        "pending_source_dependencies":remaining,
        "returned":pending.len(),"omitted":remaining.saturating_sub(pending.len()),
        "references":pending,
        "matched_dependency_counts":progress.counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_renews_idle_but_resource_io_uses_its_own_time_budget() {
        let mut idle = NoProgress::new(Duration::from_secs(5));
        let start = Instant::now();
        assert!(!idle.observe(start, false, [101; 6]));
        assert!(!idle.observe(start + Duration::from_secs(4), false, [102; 6]));
        assert!(!idle.observe(start + Duration::from_secs(8), false, [102; 6]));
        assert!(!idle.observe(start + Duration::from_secs(9), true, [102; 6]));
        assert!(!idle.observe(start + Duration::from_secs(90), true, [102; 6]));
        assert!(!idle.observe(start + Duration::from_secs(91), false, [102; 6]));
        assert!(idle.observe(start + Duration::from_secs(96), false, [102; 6]));
    }

    #[tokio::test]
    async fn progress_is_case_scoped_and_survives_the_success_detail_limit() {
        let fixture = super::super::tests::fixture_empty().await;
        let mut state = fixture.runtime.state.lock().await;
        let mut total = 0;
        let mut details = Vec::new();
        for _ in 0..125 {
            crate::replay::push_success_detail(
                &mut total,
                &mut details,
                &mut state.protocols.redis.events.matched_details,
                Some("case-a"),
                |_| (),
            );
        }
        let before = counts(&state, "case-a");
        assert_eq!(before[2], 125);
        assert_eq!(details.len(), 100);
        for _ in 0..30 {
            crate::replay::push_success_detail(
                &mut total,
                &mut details,
                &mut state.protocols.redis.events.matched_details,
                None,
                |_| (),
            );
        }
        assert_eq!(counts(&state, "case-a"), before);
        assert_eq!(counts(&state, "case-b"), [0; 6]);
    }
}
