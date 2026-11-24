//! Finite Redis reads use the latest successfully delivered write to their slot.
use super::*;
use std::collections::HashMap;
use traffic_policy_value::{PreparedMessage, StoredValue};
use traffic_protocol::message::ProtocolMessage;
use traffic_protocol_redis::{
    message::RequestMessage,
    storage_replay::{
        ReadLink, ReadQuery, ScopeHistory, Stamp, WriteEffect, delivered, delivered_writes,
        request, source_facts,
    },
};
use traffic_replay::WaitRegistration;

#[derive(Default)]
pub(super) struct Storage {
    cases: HashMap<String, CaseStorage>,
    run: ScopeHistory,
    delivered: delivered::State,
}

#[derive(Default)]
struct CaseStorage {
    history: ScopeHistory,
    reads: HashMap<usize, Stamp>,
    has_value_policy: bool,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorage")
            .field("prepared_cases", &self.cases.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
pub struct StorageDelivery {
    writes: Vec<WriteEffect>,
    reads: Vec<ReadLink>,
}

impl StorageDelivery {
    pub(super) fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.reads.is_empty()
    }
}

type Exchange = traffic_replay::exchange::PreparedExchange<crate::value_extensions::ValueRules>;

fn messages(exchange: &Exchange) -> Option<(&RequestMessage, &PreparedMessage)> {
    if exchange.protocol.as_str() != "redis" {
        return None;
    }
    Some((
        request(exchange.native.request()?)?,
        exchange.response.as_ref()?,
    ))
}

impl Storage {
    fn case(&mut self, case: &str) -> &mut CaseStorage {
        self.cases.entry(case.to_owned()).or_default()
    }

    pub(super) fn observe_value_policy(&mut self, exchange: &Exchange) {
        if exchange.protocol.as_str() == "redis"
            && exchange.source.source == ReplaySource::Case
            && let Some(case) = exchange.source.case_id.as_deref()
            && self
                .cases
                .get(case)
                .is_none_or(|storage| !storage.has_value_policy)
            && exchange
                .request
                .iter()
                .chain(exchange.response.iter())
                .any(|message| message.has_bound_values())
        {
            self.case(case).has_value_policy = true;
        }
    }

    pub(super) fn register(&mut self, exchange: &Exchange, event: &Value) {
        let Some((request, response)) = messages(exchange) else {
            return;
        };
        self.observe_value_policy(exchange);
        let response = response.projection();
        let case = exchange
            .source
            .case_id
            .as_deref()
            .filter(|_| exchange.source.source == ReplaySource::Case);
        let facts = source_facts(request, response);
        let has_read_slots = case.is_some() && facts.read_has_values;
        if facts.effects.is_empty() && !has_read_slots {
            return;
        }
        let stamp = Stamp::from_record(exchange.index, &exchange.native.reference, event);
        let scope = match case {
            Some(case) => {
                let storage = self.case(case);
                if has_read_slots {
                    storage.reads.insert(exchange.index, stamp);
                }
                &mut storage.history
            }
            None => &mut self.run,
        };
        for change in facts.effects {
            scope.record(
                &exchange.native.endpoint,
                change.location,
                stamp,
                case.and(change.argument),
            );
        }
    }
}

impl Inventory {
    pub fn prepare_storage_delivery(
        &self,
        index: usize,
        actual: &dyn ProtocolMessage,
    ) -> StorageDelivery {
        if !self.prepare_redis_storage {
            return StorageDelivery::default();
        }
        let exchange = &self.core.exchanges[index];
        let Some((source, response)) = messages(exchange) else {
            return StorageDelivery::default();
        };
        let case = exchange
            .source
            .case_id
            .as_deref()
            .and_then(|case| self.redis_storage.cases.get(case));
        if exchange.source.source == ReplaySource::Case
            && case.is_none_or(|storage| !storage.has_value_policy)
        {
            return StorageDelivery::default();
        }
        let Some(actual) = request(actual) else {
            return StorageDelivery::default();
        };
        let projection = response.projection();
        if let Some(case) = case
            && let Some(stamp) = case.reads.get(&index).copied()
        {
            let reads = case.history.read_links(
                &self.redis_storage.run,
                ReadQuery {
                    endpoint: &exchange.native.endpoint,
                    stamp,
                    source,
                    target: actual,
                    response: projection,
                },
                |index| request(self.core.exchanges.get(index)?.native.request()?),
            );
            StorageDelivery {
                reads,
                writes: Vec::new(),
            }
        } else {
            StorageDelivery {
                writes: delivered_writes(
                    source,
                    actual,
                    projection,
                    exchange.source.source == ReplaySource::Case,
                ),
                reads: Vec::new(),
            }
        }
    }

    pub fn wait_for_storage_delivery(
        &self,
        delivery: &StorageDelivery,
    ) -> Result<Option<WaitRegistration>> {
        for link in &delivery.reads {
            let exchange = &self.core.exchanges[link.writer];
            let lifecycle = &self.core.lifecycle;
            if lifecycle
                .live_status(link.writer, exchange.status)
                .is_consumed()
            {
                continue;
            }
            if let Some(wait) = lifecycle.wait_for(link.writer, admission::Barrier::Delivered) {
                return Ok(Some(wait));
            }
            anyhow::bail!("Redis read requires a successfully delivered preceding write");
        }
        Ok(None)
    }

    pub fn publish_storage_delivery(
        &mut self,
        index: usize,
        delivery: &StorageDelivery,
        completed_at: tokio::time::Instant,
    ) {
        if delivery.writes.is_empty() {
            return;
        }
        let exchange = &self.core.exchanges[index];
        for write in &delivery.writes {
            self.redis_storage.delivered.publish(
                &exchange.native.endpoint,
                exchange.source.source == ReplaySource::Case,
                &write.location,
                delivered::Receipt {
                    completed_at,
                    index,
                    argument: write.argument,
                    value: write.value.clone(),
                },
            );
        }
    }

    pub fn finish_storage_preparation(&mut self, case: &str) {
        let Some(storage) = self.redis_storage.cases.get_mut(case) else {
            return;
        };
        if storage.has_value_policy {
            storage.history.prepare();
            self.redis_storage.run.prepare();
        } else {
            self.redis_storage.cases.remove(case);
        }
    }

    pub fn clear_storage_deliveries(&mut self, case: &str) {
        self.redis_storage.delivered.clear_case();
        self.redis_storage.cases.remove(case);
    }

    pub(super) fn storage_values(
        &self,
        index: usize,
        delivery: &StorageDelivery,
        response: &PreparedMessage,
    ) -> Result<BTreeMap<String, StoredValue>> {
        let endpoint = &self.core.exchanges[index].native.endpoint;
        let mut values = BTreeMap::new();
        for link in &delivery.reads {
            let latest = self
                .redis_storage
                .delivered
                .latest(endpoint, &link.target)
                .filter(|effect| {
                    effect.index == link.writer && effect.argument == Some(link.argument)
                })
                .context(
                    "Redis read no longer refers to the current Target write at this key and field",
                )?;
            let bytes = match &latest.value {
                Some(bytes) => bytes,
                None if response.has_value_rules(&link.path) => {
                    &response.projection().values[&link.path].bytes
                }
                None => continue,
            };
            values.insert(
                link.path.clone(),
                StoredValue::from_write(link.writer, bytes.clone()),
            );
        }
        Ok(values)
    }
}
