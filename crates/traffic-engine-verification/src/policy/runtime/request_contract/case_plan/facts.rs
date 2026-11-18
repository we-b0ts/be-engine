//! Only native selector facts are retained; no SQL, keys or payloads are copied.
use super::*;
use crate::dependency_provider::NativeResource;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceFact {
    pub(super) protocol: ProtocolKind,
    host: String,
    port: u16,
    database_index: Option<i64>,
    database_name: Option<String>,
    username: Option<String>,
    group: Option<String>,
    pub(super) operation: Option<String>,
}

impl SourceFact {
    pub(super) fn from_event(event: &Value) -> Option<Self> {
        let protocol = match event["event_type"].as_str()? {
            "http_exchange" => ProtocolKind::Http,
            "redis_exchange" => ProtocolKind::Redis,
            "mysql_exchange" => ProtocolKind::Mysql,
            "memcached_exchange" => ProtocolKind::Memcached,
            "motan_exchange" => ProtocolKind::Motan,
            "kafka_produce" | "kafka_fetch" | "kafka_delivery" => ProtocolKind::Kafka,
            _ => return None,
        };
        let (host, port) = if protocol == ProtocolKind::Http {
            let authority = event["authority"]
                .as_str()?
                .parse::<hyper::http::uri::Authority>()
                .ok()?;
            let port = authority.port_u16().unwrap_or(
                if event["scheme"]
                    .as_str()
                    .is_some_and(|scheme| scheme.contains("https"))
                {
                    443
                } else {
                    80
                },
            );
            (crate::replay::normalize_host(authority.host()), port)
        } else {
            if let Some((host, port)) = event["target_host"].as_str().zip(
                event["target_port"]
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok()),
            ) {
                (crate::replay::normalize_host(host), port)
            } else if protocol == ProtocolKind::Mysql {
                let target = crate::replay::target_from_addr(event["target_addr"].as_str()?)?;
                (target.host, target.port)
            } else {
                return None;
            }
        };
        // Kafka effect records and older native envelopes can omit an operation.
        // None is an explicitly coarse selector, never a fabricated command.
        let operation = match protocol {
            ProtocolKind::Http => event["method"].as_str(),
            ProtocolKind::Redis | ProtocolKind::Mysql | ProtocolKind::Memcached => {
                event["command"].as_str()
            }
            ProtocolKind::Motan => event["method_name"]
                .as_str()
                .or_else(|| event["command"].as_str()),
            ProtocolKind::Kafka => event["api"].as_str(),
        }
        .map(str::to_owned);
        Some(Self {
            protocol,
            host,
            port,
            operation,
            database_index: event["database"].as_i64(),
            database_name: event["database"].as_str().map(str::to_owned),
            username: event["username"].as_str().map(str::to_owned),
            group: event["group"].as_str().map(str::to_owned),
        })
    }

    pub(super) fn resource(&self) -> NativeResource<'_> {
        match self.protocol {
            ProtocolKind::Http => NativeResource::Http {
                host: &self.host,
                port: self.port,
            },
            ProtocolKind::Redis => NativeResource::Redis {
                host: &self.host,
                port: self.port,
                database: self.database_index,
                username: self.username.as_deref(),
            },
            ProtocolKind::Mysql => NativeResource::Mysql {
                host: &self.host,
                port: self.port,
                database: self.database_name.as_deref(),
                username: self.username.as_deref(),
            },
            ProtocolKind::Memcached => NativeResource::Memcached {
                host: &self.host,
                port: self.port,
            },
            ProtocolKind::Motan => NativeResource::Motan {
                host: &self.host,
                port: self.port,
                group: self.group.as_deref(),
            },
            ProtocolKind::Kafka => NativeResource::Kafka {
                host: &self.host,
                port: self.port,
            },
        }
    }

    pub(super) fn matches_resource(&self, resource: &crate::policy::Resource) -> bool {
        self.protocol == resource.protocol.into()
            && self.host == crate::replay::normalize_host(&resource.endpoint.host)
            && self.port == resource.endpoint.port
            && resource
                .username
                .as_ref()
                .is_none_or(|name| self.username.as_ref() == Some(name))
            && resource
                .database
                .as_ref()
                .is_none_or(|database| match database {
                    crate::policy::Database::Index(index) => self.database_index == Some(*index),
                    crate::policy::Database::Name(name) => {
                        self.database_name.as_ref() == Some(name)
                    }
                })
    }

    pub(super) fn target(&self) -> TargetKey {
        TargetKey {
            host: self.host.clone(),
            port: self.port,
        }
    }
}

impl RequestContracts {
    pub fn observe_plan_fact(&self, case: &str, event: &Value) {
        if let Some(fact) = SourceFact::from_event(event) {
            self.state
                .lock()
                .expect("request contracts")
                .source_plan_facts
                .entry(case.into())
                .or_default()
                .insert(fact);
        }
    }
}
