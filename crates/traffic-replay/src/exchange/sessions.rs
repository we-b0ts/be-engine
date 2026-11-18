//! Optional exclusive Source lanes requested by native stateful sessions.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use traffic_protocol::{ProtocolId, connection::Endpoint};
use uuid::Uuid;

type Lane = (ProtocolId, Endpoint, String);

#[derive(Clone, Debug, Default)]
pub struct SessionBindings(Arc<Mutex<BTreeMap<Lane, Uuid>>>);

impl SessionBindings {
    pub fn accepts(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        lane: Option<&str>,
        owner: Option<Uuid>,
    ) -> bool {
        let bindings = self.0.lock().expect("native session bindings");
        let Some(lane) = lane else {
            return owner.is_none();
        };
        let key = (protocol, endpoint.clone(), lane.to_owned());
        if bindings
            .get(&key)
            .is_some_and(|bound| Some(*bound) != owner)
        {
            return false;
        }
        owner.is_none_or(|owner| {
            bindings
                .iter()
                .all(|(bound, actual)| *actual != owner || *bound == key)
        })
    }

    pub fn bind(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        lane: &str,
        owner: Uuid,
    ) -> anyhow::Result<()> {
        let mut bindings = self.0.lock().expect("native session bindings");
        let key = (protocol, endpoint.clone(), lane.to_owned());
        anyhow::ensure!(
            bindings.get(&key).is_none_or(|actual| *actual == owner)
                && bindings
                    .iter()
                    .all(|(bound, actual)| *actual != owner || *bound == key),
            "native Source session is already bound to another physical connection"
        );
        bindings.insert(key, owner);
        Ok(())
    }

    pub fn release(&self, owner: Uuid) {
        self.0
            .lock()
            .expect("native session bindings")
            .retain(|_, actual| *actual != owner);
    }
}
