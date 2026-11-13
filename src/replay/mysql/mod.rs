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
pub(in crate::replay) mod optional_session;
pub(in crate::replay) mod ownership;
mod projection;
mod report_inventory;
mod response;
mod savepoints;
mod session;
mod session_setup;
pub(in crate::replay) use session_setup::is_nonsemantic_session_setup;
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

pub(super) use broker::handle_connection;
pub(super) use matcher::MysqlReplayState;
pub(super) use model::*;
pub(super) use response::*;
pub(super) use session::*;
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
