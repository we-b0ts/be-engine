//! Candidate-local observations are merged and scoped by their registered owner.
use anyhow::{Result, ensure};
use std::{any::Any, collections::BTreeMap};

use crate::PolicyDescriptor;

pub trait ObservationState: Send + Sync {
    fn clone_state(&self) -> Box<dyn ObservationState>;
    fn merge(&mut self, other: &dyn ObservationState) -> Result<()>;
    fn scope(&mut self, _context: &str) {}
    fn as_any(&self) -> &dyn Any;
}

#[derive(Default)]
pub struct Observations {
    states: BTreeMap<String, (u32, Box<dyn ObservationState>)>,
}

impl Clone for Observations {
    fn clone(&self) -> Self {
        Self {
            states: self
                .states
                .iter()
                .map(|(id, (version, state))| (id.clone(), (*version, state.clone_state())))
                .collect(),
        }
    }
}

impl std::fmt::Debug for Observations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_map()
            .entries(self.states.iter().map(|(id, (version, _))| (id, version)))
            .finish()
    }
}

impl Observations {
    pub fn observe(
        &mut self,
        descriptor: &PolicyDescriptor,
        incoming: Box<dyn ObservationState>,
    ) -> Result<()> {
        self.merge_one(descriptor.id.into(), descriptor.version, incoming)
    }

    fn merge_one(
        &mut self,
        id: String,
        version: u32,
        incoming: Box<dyn ObservationState>,
    ) -> Result<()> {
        let state = if let Some((existing_version, existing)) = self.states.get(&id) {
            ensure!(
                *existing_version == version,
                "policy observation versions differ"
            );
            let mut staged = existing.clone_state();
            staged.merge(incoming.as_ref())?;
            staged
        } else {
            incoming
        };
        self.states.insert(id, (version, state));
        Ok(())
    }

    pub fn merge(&mut self, other: Self) -> Result<()> {
        let mut staged = self.clone();
        for (id, (version, state)) in other.states {
            staged.merge_one(id, version, state)?;
        }
        *self = staged;
        Ok(())
    }

    pub fn scope(&mut self, context: &str) {
        for (_, state) in self.states.values_mut() {
            state.scope(context);
        }
    }
}

#[cfg(test)]
mod tests;
