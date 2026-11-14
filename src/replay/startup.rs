//! A single primary-input boundary closes restart initialization admission.
use super::*;
#[cfg(test)]
mod tests;

#[derive(Debug, Default, Clone, Copy)]
pub(in crate::replay) struct Counts {
    pub required: usize,
    pub unstarted: usize,
}
impl Counts {
    pub(in crate::replay) fn observe(
        &mut self,
        source: ReplaySource,
        status: &mut ReplayExchangeStatus,
        mandatory: bool,
        close: bool,
    ) {
        if source != ReplaySource::Startup || !mandatory {
            return;
        }
        self.required += 1;
        if status.is_available() {
            self.unstarted += 1;
            if close {
                *status = ReplayExchangeStatus::StartupBlocked;
            }
        }
    }
    pub(in crate::replay) fn merge(&mut self, other: Self) {
        self.required += other.required;
        self.unstarted += other.unstarted;
    }
}
#[derive(Debug, Default)]
pub(super) struct StartupPhase {
    inventory: BTreeMap<String, usize>,
    boundary_case_id: Option<String>,
    unstarted: BTreeMap<String, usize>,
}
#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct StartupPhaseReport {
    pub status: &'static str,
    pub boundary_case_id: Option<String>,
    pub business_inventory: BTreeMap<String, usize>,
    pub unstarted_business_dependencies: BTreeMap<String, usize>,
}
impl StartupPhaseReport {
    pub(in crate::replay) fn is_dirty(&self) -> bool {
        self.status == "phase_unverified"
            || self
                .unstarted_business_dependencies
                .values()
                .any(|n| *n > 0)
    }
}
impl StartupPhase {
    pub(in crate::replay) fn admit_existing_http(&mut self) {
        if let Some(count) = self.unstarted.get_mut("http") {
            *count = count.saturating_sub(1);
        }
    }
    pub(super) fn report(&self) -> StartupPhaseReport {
        StartupPhaseReport {
            status: if self.inventory.values().all(|n| *n == 0) {
                "not_required"
            } else if self.boundary_case_id.is_some() {
                "verified"
            } else {
                "phase_unverified"
            },
            boundary_case_id: self.boundary_case_id.clone(),
            business_inventory: self.inventory.clone(),
            unstarted_business_dependencies: self.unstarted.clone(),
        }
    }
}
impl ReplayState {
    fn startup_counts(&mut self, close: bool) -> BTreeMap<String, Counts> {
        let mut counts = BTreeMap::from([
            ("mysql".into(), self.mysql.startup_counts(close)),
            (
                "http".into(),
                http::startup_counts(&mut self.http_exchanges, close),
            ),
            ("redis".into(), self.redis.startup_counts(close)),
            ("memcached".into(), self.memcached.startup_counts(close)),
            ("motan".into(), self.motan.startup_counts(close)),
            ("kafka".into(), self.kafka.startup_counts(close)),
        ]);
        for (protocol, native) in self.native.startup_counts(close) {
            counts.entry(protocol).or_default().merge(native);
        }
        counts
    }
    pub(super) fn initialize_startup_phase(&mut self) {
        self.startup_phase.inventory = self
            .startup_counts(false)
            .into_iter()
            .map(|(p, c)| (p, c.required))
            .collect();
    }
    pub(super) fn close_startup_phase(&mut self, case: &str) {
        if self.startup_phase.boundary_case_id.is_some() {
            return;
        }
        self.http_ingress.close_startup();
        let counts = self.startup_counts(true);
        self.startup_phase.inventory = counts
            .iter()
            .map(|(p, c)| (p.clone(), c.required))
            .collect();
        self.startup_phase.unstarted = counts.into_iter().map(|(p, c)| (p, c.unstarted)).collect();
        self.startup_phase.boundary_case_id = Some(case.into());
    }
}
