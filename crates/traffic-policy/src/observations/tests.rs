use super::*;
use crate::PolicyAction;

#[derive(Clone)]
struct Counter(usize);

impl ObservationState for Counter {
    fn clone_state(&self) -> Box<dyn ObservationState> {
        Box::new(self.clone())
    }
    fn merge(&mut self, other: &dyn ObservationState) -> Result<()> {
        self.0 += other.as_any().downcast_ref::<Self>().unwrap().0;
        ensure!(self.0 < 10, "counter budget exhausted");
        Ok(())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn descriptor(id: &'static str) -> PolicyDescriptor {
    PolicyDescriptor {
        id,
        version: 1,
        description: "test",
        actions: &[PolicyAction::Compare],
    }
}

fn count(state: &Observations, id: &str) -> usize {
    state.states[id]
        .1
        .as_any()
        .downcast_ref::<Counter>()
        .unwrap()
        .0
}

#[test]
fn snapshots_and_failed_merges_are_isolated() {
    let mut state = Observations::default();
    state
        .observe(&descriptor("a"), Box::new(Counter(2)))
        .unwrap();
    state
        .observe(&descriptor("b"), Box::new(Counter(3)))
        .unwrap();
    let checkpoint = state.clone();
    assert!(
        state
            .observe(&descriptor("a"), Box::new(Counter(8)))
            .is_err()
    );
    assert_eq!(count(&state, "a"), 2);

    let mut incoming = Observations::default();
    incoming
        .observe(&descriptor("a"), Box::new(Counter(1)))
        .unwrap();
    incoming
        .observe(&descriptor("b"), Box::new(Counter(8)))
        .unwrap();
    assert!(state.merge(incoming).is_err());
    assert_eq!(count(&state, "a"), 2);
    assert_eq!(count(&state, "b"), 3);
    state
        .observe(&descriptor("a"), Box::new(Counter(1)))
        .unwrap();
    assert_eq!(count(&state, "a"), 3);
    assert_eq!(count(&checkpoint, "a"), 2);
}

#[test]
fn observations_reject_version_changes() {
    let mut state = Observations::default();
    let mut descriptor = descriptor("a");
    state.observe(&descriptor, Box::new(Counter(2))).unwrap();
    descriptor.version = 2;
    assert!(state.observe(&descriptor, Box::new(Counter(1))).is_err());
    assert_eq!(count(&state, "a"), 2);
}
