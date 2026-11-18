//! Native timing facts and receipts enter the shared primary-input clock here.
use std::ops::Range;

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::time::{Duration, Instant};

use crate::interaction::replay::heartbeat_tail::Passive;
use crate::replay::control::input_timing::{DeliveryReference, Evidence};

pub(crate) trait InputTimingProjection: Send {
    fn evidence(&mut self, case: &str, start: DateTime<Utc>) -> Result<(Vec<Evidence>, bool)>;
    fn notifications(&self, case: &str, start: DateTime<Utc>) -> (Vec<Evidence>, bool);
    fn delivered(&self, case: &str, epoch: u64, reference: &DeliveryReference) -> bool;
    fn prepare_passive(
        &mut self,
        case: &str,
        proof: &Passive,
        cap_ms: u64,
        setup_finished_ms: u64,
    ) -> bool;
    fn prefix_active(&self, case: &str, epoch: DateTime<Utc>, now: Instant) -> bool;
    fn tail_ready(&mut self, case: &str, now: Instant) -> bool;
    fn plan_dispatch(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        window: Range<Duration>,
        cap: Duration,
    );
}

impl InputTimingProjection for () {
    fn evidence(&mut self, _: &str, _: DateTime<Utc>) -> Result<(Vec<Evidence>, bool)> {
        Ok((Vec::new(), false))
    }
    fn notifications(&self, _: &str, _: DateTime<Utc>) -> (Vec<Evidence>, bool) {
        (Vec::new(), false)
    }
    fn delivered(&self, _: &str, _: u64, _: &DeliveryReference) -> bool {
        false
    }
    fn prepare_passive(&mut self, _: &str, _: &Passive, _: u64, _: u64) -> bool {
        false
    }
    fn prefix_active(&self, _: &str, _: DateTime<Utc>, _: Instant) -> bool {
        false
    }
    fn tail_ready(&mut self, _: &str, _: Instant) -> bool {
        true
    }
    fn plan_dispatch(&mut self, _: &str, _: DateTime<Utc>, _: Range<Duration>, _: Duration) {}
}
