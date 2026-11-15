//! Authenticated Source preparation for native namespace-session observations.
use crate::replay::ReplayCase;
use anyhow::Result;
use std::collections::BTreeMap;
pub(crate) use traffic_protocol_http::interaction::sessions::{NamespaceSessions, Source};
mod source;

fn prepare(sessions: &mut NamespaceSessions, cases: &BTreeMap<String, ReplayCase>) -> Result<()> {
    sessions.install_source(source::load(cases)?);
    Ok(())
}

impl super::PubSubState {
    pub(crate) fn prepare_namespace_sessions(
        &mut self,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<()> {
        prepare(&mut self.namespace_sessions, cases)
    }
}

#[cfg(test)]
mod tests;
