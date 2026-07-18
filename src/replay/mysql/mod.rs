mod broker;
mod matcher;
mod model;
mod response;
mod session;
#[cfg(test)]
mod tests;
mod values;

pub(super) use broker::handle_connection;
pub(super) use matcher::MysqlReplayState;
pub(super) use model::*;
pub(super) use response::*;
pub(super) use session::*;
pub(super) use values::*;

use super::*;
use crate::mysql::wire::{
    CLIENT_CONNECT_WITH_DB, CLIENT_SECURE_CONNECTION, MysqlPacket, parse_client_command,
    parse_handshake_response, read_packet,
};

pub(in crate::replay) const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
pub(in crate::replay) const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
pub(in crate::replay) const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub(in crate::replay) const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
pub(in crate::replay) const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
pub(in crate::replay) const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
pub(in crate::replay) const MYSQL_REPLAY_AUTH_PLUGIN: &[u8] = b"mysql_native_password";
pub(in crate::replay) const MYSQL_REPLAY_AUTH_PLUGIN_DATA_1: &[u8; 8] = b"replay01";
pub(in crate::replay) const MYSQL_REPLAY_AUTH_PLUGIN_DATA_2: &[u8; 12] = b"replay-seed2";

pub(in crate::replay) const MYSQL_TYPE_TINY: u8 = 1;
pub(in crate::replay) const MYSQL_TYPE_SHORT: u8 = 2;
pub(in crate::replay) const MYSQL_TYPE_LONG: u8 = 3;
pub(in crate::replay) const MYSQL_TYPE_FLOAT: u8 = 4;
pub(in crate::replay) const MYSQL_TYPE_DOUBLE: u8 = 5;
pub(in crate::replay) const MYSQL_TYPE_NULL: u8 = 6;
pub(in crate::replay) const MYSQL_TYPE_TIMESTAMP: u8 = 7;
pub(in crate::replay) const MYSQL_TYPE_LONGLONG: u8 = 8;
pub(in crate::replay) const MYSQL_TYPE_INT24: u8 = 9;
pub(in crate::replay) const MYSQL_TYPE_DATE: u8 = 10;
pub(in crate::replay) const MYSQL_TYPE_TIME: u8 = 11;
pub(in crate::replay) const MYSQL_TYPE_DATETIME: u8 = 12;
pub(in crate::replay) const MYSQL_TYPE_YEAR: u8 = 13;
pub(in crate::replay) const MYSQL_TYPE_BIT: u8 = 16;
pub(in crate::replay) const MYSQL_TYPE_JSON: u8 = 245;
pub(in crate::replay) const MYSQL_TYPE_NEWDECIMAL: u8 = 246;
pub(in crate::replay) const MYSQL_TYPE_VAR_STRING: u8 = 253;
pub(in crate::replay) const MYSQL_TYPE_STRING: u8 = 254;
pub(in crate::replay) const MYSQL_TYPE_GEOMETRY: u8 = 255;

const MYSQL_FLAG_NOT_NULL: u16 = 0x0001;
const MYSQL_FLAG_UNSIGNED: u16 = 0x0020;
pub(in crate::replay) const MYSQL_FLAG_BINARY: u16 = 0x0080;
const MYSQL_CHARSET_UTF8_GENERAL_CI: u16 = 33;
const MYSQL_CHARSET_BINARY: u16 = 63;
