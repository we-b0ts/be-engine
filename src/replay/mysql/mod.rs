mod admission;
mod broker;
mod candidates;
mod cleanup_selection;
pub(in crate::replay) mod contracts;
mod evidence;
pub(in crate::replay) mod isolation;
mod lifecycle;
mod matcher;
mod model;
pub(crate) mod optional_session;
pub(in crate::replay) mod ownership;
mod preparation;
mod projection;
mod report_inventory;
mod response;
mod savepoints;
mod session;
mod session_constraints;
mod session_setup;
pub(crate) use session_setup::is_nonsemantic_session_setup;
pub(in crate::replay) mod sql_match;
#[cfg(test)]
mod sqlx_tests;
mod startup;
mod termination;
#[cfg(test)]
mod tests;
pub(in crate::replay) mod transaction_equivalence;
pub(in crate::replay) mod transaction_ownership;
pub(in crate::replay) mod transaction_projection;
mod transaction_scope;
mod values;
mod wire_diagnostics;

pub(crate) use broker::handle_connection;
pub(crate) use matcher::MysqlReplayState;
pub(crate) use model::*;
pub(super) use response::*;
pub(super) use session::*;
pub(crate) use session_constraints::SessionContext;
pub(super) use values::*;

use super::*;

#[cfg(test)]
use crate::mysql::wire::{
    CLIENT_CONNECT_WITH_DB, CLIENT_SECURE_CONNECTION, CLIENT_SSL, read_packet,
};
use crate::mysql::wire::{MysqlPacket, parse_client_command, parse_handshake_response};
use tokio::io::{AsyncRead, AsyncWrite};

pub(in crate::replay) trait MysqlReplayIo:
    AsyncRead + AsyncWrite + Unpin + Send
{
}

impl<T> MysqlReplayIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(in crate::replay) type BoxedMysqlReplayIo = Box<dyn MysqlReplayIo>;

pub(in crate::replay) use traffic_protocol_mysql::types::*;

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
pub(super) use source_identity::active_case_matches;
pub(super) use traffic_protocol_mysql::session_identity::{
    identity_from_exchange, identity_matches_exchange, normalize_identity_value,
};

mod source_loading;
