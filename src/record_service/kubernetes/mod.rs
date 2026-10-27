//! Startup-owned Service discovery and scoped port-forward process supervision.

mod diagnostics;
mod discovery;
mod process;
mod supervision;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, future::pending, time::Duration};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::{
    sync::{oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use tracing::info;

use crate::{AppConfig, config::UpstreamTransportConfig, recording_upstream::RecordingUpstreams};
use process::KubectlChild;

const MAX_FORWARD_PORTS: usize = 256;

pub(super) struct PortForwards {
    tasks: JoinSet<Result<()>>,
    stop: watch::Sender<bool>,
    pub(super) routes: RecordingUpstreams,
}

impl Default for PortForwards {
    fn default() -> Self {
        Self {
            tasks: JoinSet::new(),
            stop: watch::channel(false).0,
            routes: RecordingUpstreams::default(),
        }
    }
}

impl PortForwards {
    pub(super) async fn prepare(&mut self, config: &AppConfig, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut services = BTreeMap::new();
        let mut forwards = BTreeMap::new();
        for route in &config.upstream_routes {
            let UpstreamTransportConfig::KubernetesPortForward { namespace, service } = &route.via;
            let service_key = (namespace.clone(), service.clone());
            if !services.contains_key(&service_key) {
                let mut query = KubectlChild::spawn(
                    &config.kubernetes,
                    namespace,
                    &[
                        "get".into(),
                        "service".into(),
                        service.clone(),
                        "--output=json".into(),
                    ],
                )?;
                let bytes = tokio::select! {
                    result = tokio::time::timeout_at(deadline, query.output()) => result
                        .with_context(|| format!("Kubernetes Service discovery timed out for {namespace}/{service}"))?
                        .with_context(|| format!("failed discovering Service {namespace}/{service}"))?,
                    error = self.failure() => return Err(error),
                };
                services.insert(
                    service_key.clone(),
                    discovery::tcp_ports(&bytes, namespace, service)?,
                );
            }
            for port in &services[&service_key] {
                let key = (namespace.clone(), service.clone(), *port);
                let address = match forwards.get(&key) {
                    Some(address) => *address,
                    None => {
                        ensure!(
                            forwards.len() < MAX_FORWARD_PORTS,
                            "recording supports at most {MAX_FORWARD_PORTS} Kubernetes TCP forwards"
                        );
                        let identity = format!("{namespace}/{service}:{port}");
                        let child = KubectlChild::spawn(
                            &config.kubernetes,
                            namespace,
                            &[
                                "port-forward".into(),
                                "--address=127.0.0.1".into(),
                                format!("service/{service}"),
                                format!(":{port}"),
                            ],
                        )?;
                        let (ready, ready_rx) = oneshot::channel();
                        // Owned by recording startup, retained through dependency drain,
                        // and joined on shutdown; no request can create these tasks.
                        self.tasks.spawn(supervision::forward(
                            child,
                            identity.clone(),
                            ready,
                            self.stop.subscribe(),
                            timeout,
                        ));
                        let address = tokio::select! {
                            result = tokio::time::timeout_at(deadline, ready_rx) => result
                                .with_context(|| format!("kubectl port-forward readiness timed out for {identity}"))?
                                .with_context(|| format!("kubectl port-forward failed before readiness for {identity}"))?,
                            error = self.failure() => return Err(error),
                        };
                        info!(service = %identity, listen = %address, "Kubernetes recording port-forward ready");
                        forwards.insert(key, address);
                        address
                    }
                };
                self.routes.insert(&route.host, *port, address)?;
            }
        }
        Ok(())
    }

    pub(super) async fn failure(&mut self) -> anyhow::Error {
        match self.tasks.join_next().await {
            Some(result) => task_failure(result),
            None => pending().await,
        }
    }

    pub(super) fn try_failure(&mut self) -> Option<anyhow::Error> {
        self.tasks.try_join_next().map(task_failure)
    }

    pub(super) async fn shutdown(&mut self) -> Result<()> {
        let _ = self.stop.send(true);
        let draining = async {
            let mut first_error = None;
            while let Some(result) = self.tasks.join_next().await {
                if !matches!(result, Ok(Ok(()))) && first_error.is_none() {
                    first_error = Some(task_failure(result));
                }
            }
            first_error.map_or(Ok(()), Err)
        };
        tokio::time::timeout(Duration::from_secs(10), draining)
            .await
            .context("timed out cleaning up Kubernetes port-forward processes")?
    }
}

fn task_failure(result: std::result::Result<Result<()>, tokio::task::JoinError>) -> anyhow::Error {
    match result {
        Ok(Err(error)) => error,
        Err(error) => anyhow!("Kubernetes port-forward supervisor failed: {error}"),
        Ok(Ok(())) => anyhow!("Kubernetes port-forward stopped unexpectedly"),
    }
}
