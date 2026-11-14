//! Static native dependency adapters expose real inventory and delivery state.
//! Matching, claims, protocol sessions and consumption remain with native drivers.
use super::{ReplayExchangeStatus, ReplayState};
use crate::dependency_provider::{DependencyProvider, ResourceProvider};
use crate::protocol_contract::{ProtocolContract, ProtocolKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod inventory;
#[cfg(test)]
mod tests;
pub(in crate::replay) use inventory::resolve_case;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::replay) enum RecordedReference {
    Capture { exchange_id: Uuid },
    Redis { connection_id: Uuid, sequence: u64 },
    RedisRpcPush { connection_id: Uuid, sequence: u64 },
    Mysql { connection_id: Uuid, sequence: u64 },
    Http { exchange_id: Uuid },
    Connect { event_id: Uuid },
    Memcached { connection_id: Uuid, sequence: u64 },
    Motan { connection_id: Uuid, sequence: u64 },
    KafkaProduce { connection_id: Uuid, sequence: u64 },
    KafkaFetch { connection_id: Uuid, sequence: u64 },
    KafkaDelivery { connection_id: Uuid, sequence: u64 },
}

#[derive(Debug, Clone, Copy)]
pub(in crate::replay) enum DependencyAdapter {
    Redis(usize),
    RedisRpcPush(usize),
    Mysql(usize),
    Http(usize),
    Memcached(usize),
    Motan(usize),
    Kafka(super::kafka::FiniteExchange),
}

pub(in crate::replay) trait NativeDependencyAdapter {
    fn protocol(self) -> ProtocolKind;
    fn delivery_state(self, state: &ReplayState) -> Option<ReplayExchangeStatus>;
    fn permits_cancelled_omission(self, state: &ReplayState) -> bool;
    fn permits_unstarted_omission(
        self,
        state: &ReplayState,
        shared_initialization: bool,
        strict_reference: bool,
    ) -> bool;
}

impl NativeDependencyAdapter for DependencyAdapter {
    fn permits_cancelled_omission(self, state: &ReplayState) -> bool {
        match self {
            Self::Redis(index) => state.redis.permits_cancelled_append_omission(index),
            Self::Http(index) => state.permits_cancelled_http_omission(index),
            _ => false,
        }
    }
    fn protocol(self) -> ProtocolKind {
        match self {
            Self::Redis(_) | Self::RedisRpcPush(_) => ProtocolKind::Redis,
            Self::Mysql(_) => ProtocolKind::Mysql,
            Self::Http(_) => ProtocolKind::Http,
            Self::Memcached(_) => ProtocolKind::Memcached,
            Self::Motan(_) => ProtocolKind::Motan,
            Self::Kafka(_) => ProtocolKind::Kafka,
        }
    }

    fn delivery_state(self, state: &ReplayState) -> Option<ReplayExchangeStatus> {
        match self {
            Self::Redis(index) => state.redis.exchange_status(index),
            Self::RedisRpcPush(index) => state.redis.pubsub.finite_rpc_push_status(index),
            Self::Mysql(index) => state.mysql.exchange_status(index),
            Self::Http(index) => state.http_exchange_status(index),
            Self::Memcached(index) => state.memcached.finite_exchange_status(index),
            Self::Motan(index) => state.motan.finite_exchange_status(index),
            Self::Kafka(exchange) => state.kafka.finite_exchange_status(exchange),
        }
    }

    fn permits_unstarted_omission(
        self,
        state: &ReplayState,
        shared_initialization: bool,
        strict_reference: bool,
    ) -> bool {
        match self {
            // MySQL proves native setup/cleanup and transaction equivalence
            // independently of the finite async inventory. It never permits an
            // unobserved business statement or an already started delivery.
            Self::Mysql(index) => state.mysql.permits_unstarted_omission(index),
            Self::Http(index) => {
                !strict_reference
                    && shared_initialization
                    && state.http_exchange_status(index) == Some(ReplayExchangeStatus::Available)
            }
            _ => false,
        }
    }
}

/// Transport connection failures retain their original independent finite identity.
#[derive(Debug, Clone, Copy)]
pub(in crate::replay) enum ExchangeHandle {
    Registered(usize),
    Native(DependencyAdapter),
    Connect(usize),
}

impl ExchangeHandle {
    pub(in crate::replay) fn permits_cancelled_omission(self, state: &ReplayState) -> bool {
        match self {
            Self::Native(adapter) => adapter.permits_cancelled_omission(state),
            Self::Connect(_) | Self::Registered(_) => false,
        }
    }
    pub(in crate::replay) fn shared_initialization(
        self,
        state: &ReplayState,
        http_completion: &[crate::policy::AsyncHttpEnd],
    ) -> bool {
        match self {
            Self::Native(DependencyAdapter::Http(index)) => {
                state.http_shared_initialization(index, http_completion)
            }
            _ => false,
        }
    }

    pub(in crate::replay) fn delivery_state(
        self,
        state: &ReplayState,
    ) -> Option<ReplayExchangeStatus> {
        match self {
            Self::Native(adapter) => adapter.delivery_state(state),
            Self::Connect(index) => state.connect_failures.status(index),
            Self::Registered(index) => state.native.core.exchanges.get(index).map(|exchange| {
                state
                    .native
                    .core
                    .lifecycle
                    .live_status(index, exchange.status)
            }),
        }
    }

    pub(in crate::replay) fn permits_unstarted_omission(
        self,
        state: &ReplayState,
        shared_initialization: bool,
        strict_reference: bool,
    ) -> bool {
        match self {
            Self::Native(adapter) => {
                adapter.permits_unstarted_omission(state, shared_initialization, strict_reference)
            }
            Self::Connect(_) | Self::Registered(_) => false,
        }
    }
}

pub(in crate::replay) fn contract(protocol: ProtocolKind) -> ProtocolContract {
    ResourceProvider::for_protocol(protocol).contract()
}
