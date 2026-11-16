//! Historical SQL policy evidence adapters. Live serving belongs to the installed provider.
use crate::policy::runtime as policy;
pub(crate) mod contracts;
pub(crate) mod sql_match;
pub(crate) use traffic_protocol_mysql::model::MysqlValue as RecordedMysqlValue;
pub(crate) type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
pub(crate) type RecordedMysqlResponse =
    traffic_protocol_mysql::recorded::RecordedMysqlResponse<crate::dependency_index::RecordRef>;
use crate::replay::*;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
pub(crate) use traffic_protocol_mysql::session_identity::{
    SessionIdentity as ReplaySessionIdentity, identity_from_exchange,
};
pub(crate) use traffic_protocol_mysql::values::*;

#[cfg(test)]
use crate::mysql::wire::{
    CLIENT_CONNECT_WITH_DB, CLIENT_SECURE_CONNECTION, CLIENT_SSL, read_packet,
};

use traffic_protocol_mysql::projection;
