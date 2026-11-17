//! Recording-only dial addresses, independent of logical dependency identity.

use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::{Result, anyhow, ensure};

use crate::{AppState, config::upstream_routes::normalize_host};

#[derive(Debug, Clone, Default)]
pub(crate) struct RecordingUpstreams(BTreeMap<String, BTreeMap<u16, SocketAddr>>);

impl RecordingUpstreams {
    pub(crate) fn insert(&mut self, host: &str, port: u16, address: SocketAddr) -> Result<()> {
        let ports = self.0.entry(normalize_host(host)).or_default();
        ensure!(
            ports.insert(port, address).is_none(),
            "duplicate recording upstream for {host}:{port}"
        );
        Ok(())
    }
}

impl AppState {
    pub(crate) fn recording_http_client(&self, host: &str) -> &crate::ProxyClient {
        if self.has_recording_upstream(host) {
            &self.inner.forwarded_http_client
        } else {
            self.client()
        }
    }

    pub(crate) fn install_recording_upstreams(&self, routes: RecordingUpstreams) -> Result<()> {
        for route in &self.config().upstream_routes {
            ensure!(
                routes
                    .0
                    .get(&normalize_host(&route.host))
                    .is_some_and(|ports| !ports.is_empty()),
                "recording upstreams were not prepared for {}",
                route.host
            );
        }
        self.inner
            .recording_upstreams
            .set(routes)
            .map_err(|_| anyhow!("recording upstreams were already installed"))
    }

    pub(crate) fn has_recording_upstream(&self, host: &str) -> bool {
        let host = normalize_host(host);
        if let Some(routes) = self.inner.recording_upstreams.get() {
            return routes.0.contains_key(&host);
        }
        self.config()
            .upstream_routes
            .iter()
            .any(|route| normalize_host(&route.host) == host)
    }

    pub(crate) fn recording_upstream(&self, host: &str, port: u16) -> Result<Option<SocketAddr>> {
        if !self.has_recording_upstream(host) {
            return Ok(None);
        }
        let routes = self
            .inner
            .recording_upstreams
            .get()
            .ok_or_else(|| anyhow!("recording upstreams are not ready for {host}"))?;
        let address = routes
            .0
            .get(&normalize_host(host))
            .and_then(|ports| ports.get(&port))
            .ok_or_else(|| {
                anyhow!("Kubernetes Service route has no forwarded TCP port for {host}:{port}")
            })?;
        Ok(Some(*address))
    }
}
