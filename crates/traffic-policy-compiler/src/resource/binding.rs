//! Native endpoint and session identity are retained independently of operation/payload.
use super::{DependencyProvider, ResourceProvider};
use crate::protocol_contract::ProtocolKind;
use anyhow::{Result, ensure};

#[derive(Debug, Clone, Copy)]
pub enum NativeResource<'a> {
    Http {
        host: &'a str,
        port: u16,
    },
    Redis {
        host: &'a str,
        port: u16,
        database: Option<i64>,
        username: Option<&'a str>,
    },
    Mysql {
        host: &'a str,
        port: u16,
        database: Option<&'a str>,
        username: Option<&'a str>,
    },
    Memcached {
        host: &'a str,
        port: u16,
    },
    Motan {
        host: &'a str,
        port: u16,
        group: Option<&'a str>,
    },
    Kafka {
        host: &'a str,
        port: u16,
    },
}

impl<'a> NativeResource<'a> {
    pub fn from_policy(resource: &'a crate::Resource) -> Result<Self> {
        let host = resource.endpoint.host.as_str();
        let port = resource.endpoint.port;
        Ok(match resource.protocol {
            crate::Protocol::Http => {
                ensure!(
                    resource.database.is_none() && resource.username.is_none(),
                    "HTTP resource does not define database or native username dimensions"
                );
                Self::Http { host, port }
            }
            crate::Protocol::Redis => {
                let database = resource
                    .database
                    .as_ref()
                    .map(|database| match database {
                        crate::Database::Index(index) => Ok(*index),
                        crate::Database::Name(_) => {
                            anyhow::bail!("Redis resource requires a numeric database identity")
                        }
                    })
                    .transpose()?;
                Self::Redis {
                    host,
                    port,
                    database,
                    username: resource.username.as_deref(),
                }
            }
            crate::Protocol::Mysql => {
                let database = resource
                    .database
                    .as_ref()
                    .map(|database| match database {
                        crate::Database::Name(name) => Ok(name.as_str()),
                        crate::Database::Index(_) => {
                            anyhow::bail!("MySQL resource requires a named database identity")
                        }
                    })
                    .transpose()?;
                Self::Mysql {
                    host,
                    port,
                    database,
                    username: resource.username.as_deref(),
                }
            }
            crate::Protocol::Memcached => {
                ensure!(
                    resource.database.is_none() && resource.username.is_none(),
                    "Memcached resource does not define supported database or SASL username dimensions"
                );
                Self::Memcached { host, port }
            }
        })
    }

    pub fn protocol(self) -> ProtocolKind {
        match self {
            Self::Http { .. } => ProtocolKind::Http,
            Self::Redis { .. } => ProtocolKind::Redis,
            Self::Mysql { .. } => ProtocolKind::Mysql,
            Self::Memcached { .. } => ProtocolKind::Memcached,
            Self::Motan { .. } => ProtocolKind::Motan,
            Self::Kafka { .. } => ProtocolKind::Kafka,
        }
    }

    pub fn endpoint(self) -> (&'a str, u16) {
        match self {
            Self::Http { host, port }
            | Self::Redis { host, port, .. }
            | Self::Mysql { host, port, .. }
            | Self::Memcached { host, port }
            | Self::Motan { host, port, .. }
            | Self::Kafka { host, port } => (host, port),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BoundResource<'a> {
    pub native: NativeResource<'a>,
}

impl<'a> BoundResource<'a> {
    pub fn endpoint(self) -> (&'a str, u16) {
        self.native.endpoint()
    }
}

pub fn bind<'a>(
    provider: ResourceProvider,
    resource: NativeResource<'a>,
) -> Result<BoundResource<'a>> {
    ensure!(
        resource.protocol() == provider.contract().protocol,
        "resource identity crossed native protocol providers"
    );
    let (host, port) = resource.endpoint();
    ensure!(
        !host.is_empty() && !host.chars().any(char::is_control) && port != 0,
        "resource provider requires an actual endpoint identity"
    );
    let valid_name = |name: Option<&str>| {
        name.is_none_or(|name| name.len() <= 4096 && !name.chars().any(char::is_control))
    };
    match resource {
        NativeResource::Redis {
            database, username, ..
        } => {
            ensure!(
                database.is_none_or(|index| index >= 0) && valid_name(username),
                "Redis resource has an invalid database or username identity"
            );
        }
        NativeResource::Mysql {
            database, username, ..
        } => {
            ensure!(
                valid_name(database) && valid_name(username),
                "MySQL resource has an invalid database or username identity"
            );
        }
        NativeResource::Motan { group, .. } => ensure!(
            valid_name(group),
            "Motan resource has an invalid group identity"
        ),
        NativeResource::Http { .. }
        | NativeResource::Memcached { .. }
        | NativeResource::Kafka { .. } => (),
    }
    Ok(BoundResource { native: resource })
}
