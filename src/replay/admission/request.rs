//! Application contexts drive the protocol-independent request executor.
use super::super::{ReplayProtocolSet, RuntimeState};
use std::sync::Arc;
use tokio::{sync::Mutex, time::Instant};
pub(in crate::replay) use traffic_replay::request::{
    RequestAdapter as DependencyRequestAdapter, WaitDependency,
};

pub(in crate::replay) async fn execute<
    P: ReplayProtocolSet,
    A: DependencyRequestAdapter<RuntimeState<P>>,
>(
    shared: &Arc<Mutex<RuntimeState<P>>>,
    adapter: &mut A,
    deadline: Instant,
) -> Result<A::Matched, A::Error> {
    traffic_replay::request::execute(shared, adapter, deadline).await
}
