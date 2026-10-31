//! Resource-level native contracts, separate from payload semantics and exchange delivery.
//! Providers describe real protocol operations and preparation; they never consume I/O.
use crate::{
    policy::Surface,
    protocol_contract::{
        CapabilitySupport, NativeProtocolVersion, ProtocolContract, ProtocolKind, ProtocolRole,
    },
    value_contract::plan::SlotKind,
};
use anyhow::Result;

mod operation;
mod preparation;
mod resource;

#[cfg(test)]
mod tests;

pub(crate) use operation::OperationSelector;
pub(crate) use preparation::{
    LookupPreparation, ResourcePreparation, ResourcePreparationRequest, SelectorPreparation,
};
pub(crate) use resource::{BoundResource, NativeResource};

pub(crate) trait DependencyProvider: Copy {
    fn contract(self) -> ProtocolContract;
    fn bind_resource<'a>(self, resource: NativeResource<'a>) -> Result<BoundResource<'a>>;
    fn operation<'a>(self, operation: Option<&'a str>) -> Result<OperationSelector<'a>>;
    fn value_slot(self, surface: Surface, slot: SlotKind) -> CapabilitySupport;
    fn prepare<'a>(
        self,
        request: ResourcePreparationRequest<'a>,
    ) -> Result<ResourcePreparation<'a>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceProvider {
    Http,
    Redis,
    Mysql,
    Memcached,
    Motan,
    Kafka,
}

impl ResourceProvider {
    pub(crate) const fn for_protocol(protocol: ProtocolKind) -> Self {
        match protocol {
            ProtocolKind::Http => Self::Http,
            ProtocolKind::Redis => Self::Redis,
            ProtocolKind::Mysql => Self::Mysql,
            ProtocolKind::Memcached => Self::Memcached,
            ProtocolKind::Motan => Self::Motan,
            ProtocolKind::Kafka => Self::Kafka,
        }
    }
}

impl DependencyProvider for ResourceProvider {
    fn contract(self) -> ProtocolContract {
        use NativeProtocolVersion as V;
        let (protocol, native_versions): (_, &'static [V]) = match self {
            Self::Http => (ProtocolKind::Http, &[V::Http]),
            Self::Redis => (ProtocolKind::Redis, &[V::RedisResp2, V::RedisResp3]),
            Self::Mysql => (ProtocolKind::Mysql, &[V::MysqlClassic]),
            Self::Memcached => (
                ProtocolKind::Memcached,
                &[V::MemcachedText, V::MemcachedBinary],
            ),
            Self::Motan => (ProtocolKind::Motan, &[V::Motan1, V::Motan2]),
            Self::Kafka => (ProtocolKind::Kafka, &[V::Kafka]),
        };
        ProtocolContract {
            protocol,
            role: ProtocolRole::Dependency,
            native_versions,
        }
    }

    fn bind_resource<'a>(self, resource: NativeResource<'a>) -> Result<BoundResource<'a>> {
        resource::bind(self, resource)
    }

    fn operation<'a>(self, operation: Option<&'a str>) -> Result<OperationSelector<'a>> {
        operation::prepare(self, operation)
    }

    fn value_slot(self, surface: Surface, slot: SlotKind) -> CapabilitySupport {
        use CapabilitySupport::{Supported, Unsupported};
        if !matches!(
            surface,
            Surface::DependencyRequest | Surface::DependencyResponse
        ) {
            return Unsupported {
                reason: "a dependency resource provider cannot own a primary API value slot",
            };
        }
        let supported = match self {
            Self::Http => slot == SlotKind::Body,
            Self::Redis => matches!(slot, SlotKind::Value | SlotKind::RedisValue),
            Self::Mysql => match surface {
                Surface::DependencyRequest => {
                    matches!(slot, SlotKind::SqlValue | SlotKind::SqlField)
                }
                Surface::DependencyResponse => {
                    matches!(slot, SlotKind::SqlColumn | SlotKind::SqlField)
                }
                Surface::ApiResponse => false,
            },
            Self::Memcached => slot == SlotKind::Value,
            Self::Motan => {
                return Unsupported {
                    reason: "Motan native framing exists; a typed rule payload-slot adapter is not installed",
                };
            }
            Self::Kafka => {
                return Unsupported {
                    reason: "Kafka native replay exists; a typed rule payload-slot adapter is not installed",
                };
            }
        };
        if supported {
            Supported
        } else {
            Unsupported {
                reason: "the selected dependency protocol, surface and physical value slot have no installed adapter",
            }
        }
    }

    fn prepare<'a>(
        self,
        request: ResourcePreparationRequest<'a>,
    ) -> Result<ResourcePreparation<'a>> {
        preparation::prepare(self, request)
    }
}
