//! Native MySQL endpoint, database and username correspondence.
use crate::recorded::{RecordedMysqlConnection, RecordedMysqlExchange};
use traffic_protocol::{
    connection::{Endpoint, endpoint_from_addr as target_from_addr},
    observation::normalize_host,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyIdentity {
    pub target: Endpoint,
    pub database: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub target: Option<Endpoint>,
    pub database: Option<String>,
    pub username: Option<String>,
}

pub fn identity_from_connection(
    connection: &RecordedMysqlConnection,
) -> Option<DependencyIdentity> {
    let target = target_from_connection(connection)?;
    Some(DependencyIdentity {
        target,
        database: normalize_optional(&connection.database),
        username: normalize_optional(&connection.username),
    })
}

pub fn identity_from_exchange<E>(
    exchange: &RecordedMysqlExchange<E>,
) -> Option<DependencyIdentity> {
    let target = target_from_exchange(exchange)?;
    Some(DependencyIdentity {
        target,
        database: normalize_optional(&exchange.database),
        username: normalize_optional(&exchange.username),
    })
}

pub fn target_from_connection(connection: &RecordedMysqlConnection) -> Option<Endpoint> {
    if let (Some(host), Some(port)) = (&connection.target_host, connection.target_port) {
        return Some(Endpoint {
            host: normalize_host(host),
            port,
        });
    }
    if let Some(target_addr) = &connection.target_addr
        && let Some(target) = target_from_addr(target_addr)
    {
        return Some(target);
    }
    None
}

pub fn target_from_exchange<E>(exchange: &RecordedMysqlExchange<E>) -> Option<Endpoint> {
    if let (Some(host), Some(port)) = (&exchange.target_host, exchange.target_port) {
        return Some(Endpoint {
            host: normalize_host(host),
            port,
        });
    }
    if let Some(target_addr) = &exchange.target_addr
        && let Some(target) = target_from_addr(target_addr)
    {
        return Some(target);
    }
    None
}

pub fn identity_matches_exchange(session: &SessionIdentity, exchange: &DependencyIdentity) -> bool {
    session.target.as_ref() == Some(&exchange.target)
        && same_identity_value(session.database.as_deref(), exchange.database.as_deref())
        && same_identity_value(session.username.as_deref(), exchange.username.as_deref())
}

pub fn normalize_identity_value(value: Option<&str>) -> Option<String> {
    identity_value(value).map(str::to_ascii_lowercase)
}

fn identity_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn same_identity_value(left: Option<&str>, right: Option<&str>) -> bool {
    match (identity_value(left), identity_value(right)) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

pub fn normalize_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
