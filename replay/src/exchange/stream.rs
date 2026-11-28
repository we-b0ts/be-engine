//! Retain only planned and active native exchanges in a live Session.
use std::{
    collections::BTreeMap,
    ops::{Index, IndexMut},
};

use anyhow::{Result, ensure};
use traffic_protocol::connection::RecordedInput;

use super::{CandidateKey, ExchangeInventory, PreparedExchange, SourceContext};
use crate::{index::ScopePartition, rules::RuleRuntime};

pub struct ExchangeEntries<R: RuleRuntime> {
    frozen: Vec<PreparedExchange<R>>,
    stream: Option<BTreeMap<usize, PreparedExchange<R>>>,
}

impl<R: RuleRuntime> Default for ExchangeEntries<R> {
    fn default() -> Self {
        Self {
            frozen: Vec::new(),
            stream: None,
        }
    }
}

impl<R: RuleRuntime> ExchangeEntries<R> {
    pub fn frozen(&self) -> &[PreparedExchange<R>] {
        &self.frozen
    }

    pub fn len(&self) -> usize {
        self.stream
            .as_ref()
            .map_or(self.frozen.len(), BTreeMap::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&PreparedExchange<R>> {
        if let Some(stream) = &self.stream {
            stream.get(&index)
        } else {
            self.frozen.get(index)
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &PreparedExchange<R>> + Clone {
        self.frozen
            .iter()
            .chain(self.stream.iter().flat_map(BTreeMap::values))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PreparedExchange<R>> {
        self.frozen
            .iter_mut()
            .chain(self.stream.iter_mut().flat_map(BTreeMap::values_mut))
    }

    pub(super) fn get_mut(&mut self, index: usize) -> Option<&mut PreparedExchange<R>> {
        if let Some(stream) = &mut self.stream {
            stream.get_mut(&index)
        } else {
            self.frozen.get_mut(index)
        }
    }

    pub(super) fn next_index(&self, source: &SourceContext) -> Result<usize> {
        let Some(stream) = &self.stream else {
            return Ok(self.frozen.len());
        };
        let sequence = source
            .capture
            .as_ref()
            .map_or(0, |capture| capture.sequence);
        let index = usize::try_from(sequence)?;
        ensure!(
            index != 0
                && stream
                    .last_key_value()
                    .is_none_or(|(&last, _)| index > last),
            "Session native exchange is out of order at Source sequence {sequence}"
        );
        Ok(index)
    }

    pub(super) fn push(&mut self, exchange: PreparedExchange<R>) {
        if let Some(stream) = &mut self.stream {
            stream.insert(exchange.index, exchange);
        } else {
            self.frozen.push(exchange);
        }
    }
}

impl<R: RuleRuntime> Index<usize> for ExchangeEntries<R> {
    type Output = PreparedExchange<R>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("registered native exchange")
    }
}

impl<R: RuleRuntime> IndexMut<usize> for ExchangeEntries<R> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index).expect("registered native exchange")
    }
}

impl<R: RuleRuntime> ExchangeInventory<R> {
    pub fn enable_streaming(&mut self) -> Result<()> {
        ensure!(
            self.exchanges.is_empty(),
            "Session native inventory is already populated"
        );
        self.exchanges.stream = Some(BTreeMap::new());
        Ok(())
    }

    pub fn discard_completed(&mut self, sequence: &crate::SequenceRuntime) -> Result<()> {
        let Some(stream) = &mut self.exchanges.stream else {
            return Ok(());
        };
        let completed: Vec<_> = stream
            .values()
            .filter(|exchange| {
                exchange.status.is_consumed() && !sequence.contains(exchange.index as u64)
            })
            .map(|exchange| exchange.index)
            .collect();
        for index in completed {
            let exchange = stream.remove(&index).expect("completed Session exchange");
            let scope =
                ScopePartition::new(exchange.source.source, exchange.source.case_id.as_deref());
            if let Some(request) = exchange.request {
                let key = CandidateKey {
                    scope: scope.clone(),
                    protocol: exchange.protocol,
                    endpoint: exchange.native.endpoint.clone(),
                    structure: serde_json::to_vec(R::structure(&request))?,
                };
                self.candidates.discard(&key, index);
            }
            if self.lanes.discard(index)
                && let Some(lane) = exchange.native.lane
            {
                self.lane_ids
                    .remove(&(scope, exchange.protocol, exchange.native.endpoint, lane));
            }
            if let RecordedInput::Emission { after, .. } = exchange.native.input
                && let Some(emissions) = self.emissions.get_mut(&after)
            {
                emissions.retain(|&existing| existing != index);
                if emissions.is_empty() {
                    self.emissions.remove(&after);
                }
            }
            self.transaction_starts.remove(&index);
            self.lifecycle.discard(index);
        }
        Ok(())
    }
}
