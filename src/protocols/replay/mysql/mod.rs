use crate::policy::runtime as policy;
use crate::policy::runtime::*;
use crate::protocols::replay::ReplayState;
pub(crate) use crate::protocols::replay::report::snapshot::{
    ConnectionReport, MatchedQueryReport, QueryReport, RecordedExchangeSummary,
};
pub(crate) use traffic_protocol_mysql::report::SqlSummary;
mod admission;
mod broker;
mod candidates;
mod case_status;
use traffic_protocol_mysql::cleanup_selection;
pub(crate) mod contracts;
mod evidence;
pub(crate) mod isolation;
mod lifecycle;
mod matcher;
mod model;
pub(crate) mod optional_session;
pub(crate) mod ownership;
mod preparation;
use traffic_protocol_mysql::projection;
mod report_inventory;
mod response;
mod savepoints;
mod session;
mod session_constraints;
mod session_setup;
pub(crate) use session_setup::is_nonsemantic_session_setup;
pub(crate) mod sql_match;
#[cfg(test)]
mod sqlx_tests;
mod startup;
mod termination;
#[cfg(test)]
mod tests;
pub(crate) mod transaction_equivalence;
pub(crate) mod transaction_ownership;
pub(crate) mod transaction_projection;
mod transaction_scope;
mod values;
mod wire_diagnostics;

pub(crate) use broker::handle_connection;
pub(crate) use matcher::MysqlReplayState;
pub(crate) use model::*;
pub(crate) use response::*;
pub(crate) use session::*;
pub(crate) use session_constraints::SessionContext;
pub(crate) use values::*;

use crate::replay::*;
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

#[cfg(test)]
use crate::mysql::wire::{
    CLIENT_CONNECT_WITH_DB, CLIENT_SECURE_CONNECTION, CLIENT_SSL, read_packet,
};
use crate::mysql::wire::{MysqlPacket, parse_client_command};
pub(crate) use traffic_protocol::connection::ConnectionIo as MysqlReplayIo;

pub(crate) use traffic_protocol_mysql::types::*;

pub(crate) fn source_records(
    records: &[crate::protocols::replay::source::DependencyRecord],
) -> impl Iterator<Item = (usize, &RecordedMysqlExchange)> + Clone {
    records.iter().enumerate().filter_map(|(index, record)| {
        let crate::protocols::replay::source::DependencyRecord::MysqlExchange(record) = record
        else {
            return None;
        };
        Some((index, record.as_ref()))
    })
}

mod source_identity;
pub(crate) use source_identity::active_case_matches;
pub(crate) use traffic_protocol_mysql::session_identity::{
    identity_from_exchange, identity_matches_exchange, normalize_identity_value,
};

mod source_loading;
