mod memcached;
mod redis;

use crate::AppState;
use crate::recorder::{ProcessInfo, RecorderEvent};
use anyhow::Result;

pub(crate) use memcached::handle_connected_memcached;
pub(crate) use redis::handle_connected_redis;

#[derive(Debug, Clone)]
pub(crate) struct CacheConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) client_process: Option<ProcessInfo>,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
    pub(crate) upstream_addr: String,
}

pub(super) async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.recorder().record(event.clone()).await?;
    state.record_dependency_if_relevant(&event).await;
    Ok(())
}
