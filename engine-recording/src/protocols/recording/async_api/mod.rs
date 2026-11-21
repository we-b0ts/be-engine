use crate::protocols::recording::events::RecorderEvent;
use traffic_engine_replay::protocols::recording::async_api::selection::NativeEvent;
pub use traffic_engine_replay::protocols::recording::async_api::*;
impl crate::active_case::ActiveCaseRegistry {
    pub fn observe_async_dependency_event(
        &self,
        event: &RecorderEvent,
        targets: &crate::active_case::DependencyTargets,
        recorded_in_case: bool,
    ) {
        self.observe_async_completion(
            &NativeEvent::new(event),
            targets,
            recorded_in_case,
            event.capture_complete(),
            event.kind(),
        );
    }
}
