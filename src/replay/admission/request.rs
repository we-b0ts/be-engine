//! Application contexts drive the protocol-independent request executor.
use super::super::ReplayState;
use std::sync::Arc;
use tokio::{sync::Mutex, time::Instant};
pub(in crate::replay) use traffic_replay::request::{
    RequestAdapter as DependencyRequestAdapter, WaitDependency,
};

pub(in crate::replay) async fn execute<A: DependencyRequestAdapter<ReplayState>>(
    shared: &Arc<Mutex<ReplayState>>,
    adapter: &mut A,
    deadline: Instant,
) -> Result<A::Matched, A::Error> {
    traffic_replay::request::execute(shared, adapter, deadline).await
}
