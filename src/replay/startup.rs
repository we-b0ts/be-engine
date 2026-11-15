//! A single primary-input boundary closes restart initialization admission.
use super::*;
#[cfg(test)]
mod tests;

pub(in crate::replay) use traffic_replay::StartupCounts as Counts;
#[derive(Debug, Default)]
pub(crate) struct StartupPhase {
    inventory: BTreeMap<String, usize>,
    boundary_case_id: Option<String>,
    unstarted: BTreeMap<String, usize>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StartupPhaseReport {
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
    pub(crate) fn admit_existing(&mut self, protocol: &str) {
        if let Some(count) = self.unstarted.get_mut(protocol) {
            *count = count.saturating_sub(1);
        }
    }
    pub(crate) fn report(&self) -> StartupPhaseReport {
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
impl<P: ReplayProtocolSet> RuntimeState<P> {
    fn startup_counts(&mut self, close: bool) -> BTreeMap<String, Counts> {
        let mut counts = self.protocols.startup_counts(close);
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
    pub(crate) fn close_startup_phase(&mut self, case: &str) {
        if self.startup_phase.boundary_case_id.is_some() {
            return;
        }
        self.protocols.close_startup();
        let counts = self.startup_counts(true);
        self.startup_phase.inventory = counts
            .iter()
            .map(|(p, c)| (p.clone(), c.required))
            .collect();
        self.startup_phase.unstarted = counts.into_iter().map(|(p, c)| (p, c.unstarted)).collect();
        self.startup_phase.boundary_case_id = Some(case.into());
    }
}
