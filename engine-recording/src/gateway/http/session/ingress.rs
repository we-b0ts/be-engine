//! Order shutdown cancellation records before closing the ingress transports.

use std::{collections::BTreeSet, sync::Mutex};

use anyhow::{Result, ensure};
use tokio::sync::watch;
use traffic_model::session::{ENGINE_SHUTDOWN_CANCEL_REASON, SessionEvent};
use uuid::Uuid;

use crate::AppState;

#[derive(Clone, Copy, Default)]
struct Connections {
    disconnected: bool,
    count: usize,
}

#[derive(Default)]
pub(crate) struct Ingress {
    exchanges: Mutex<BTreeSet<Uuid>>,
    connections: watch::Sender<Connections>,
}

impl Ingress {
    pub(crate) fn connect(&self) -> Option<Connection> {
        self.connections
            .send_if_modified(|connections| {
                if connections.disconnected {
                    return false;
                }
                connections.count += 1;
                true
            })
            .then(|| Connection(self.connections.clone()))
    }

    pub(crate) fn disconnected(&self) -> bool {
        self.connections.borrow().disconnected
    }

    pub(crate) async fn wait_for_disconnect(&self) {
        let _ = self
            .connections
            .subscribe()
            .wait_for(|connections| connections.disconnected)
            .await;
    }

    pub(super) fn record(&self, state: &AppState, event: SessionEvent) -> Result<()> {
        let mut exchanges = self.exchanges.lock().expect("session exchanges poisoned");
        ensure!(!self.disconnected(), "recording ingress closed at shutdown");
        let change = match &event {
            SessionEvent::PrimaryRequest { exchange, .. } => Some((*exchange, false)),
            SessionEvent::PrimaryCancel { exchange, .. }
            | SessionEvent::PrimaryResponseEnd { exchange } => Some((*exchange, true)),
            _ => None,
        };
        state.session_event(event)?;
        if let Some((exchange, terminal)) = change {
            if terminal {
                exchanges.remove(&exchange);
            } else {
                exchanges.insert(exchange);
            }
        }
        Ok(())
    }

    pub(crate) async fn disconnect(&self, state: &AppState) -> Result<()> {
        let result = {
            let mut exchanges = self.exchanges.lock().expect("session exchanges poisoned");
            let result = std::mem::take(&mut *exchanges)
                .into_iter()
                .try_for_each(|exchange| {
                    state.session_event(SessionEvent::PrimaryCancel {
                        exchange,
                        reason: ENGINE_SHUTDOWN_CANCEL_REASON.to_owned(),
                    })
                });
            // Publish every cancellation before any connection can observe shutdown.
            self.connections
                .send_modify(|connections| connections.disconnected = true);
            result
        };
        let _ = self
            .connections
            .subscribe()
            .wait_for(|connections| connections.count == 0)
            .await;
        result
    }
}

pub(crate) struct Connection(watch::Sender<Connections>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.send_modify(|connections| connections.count -= 1);
    }
}
