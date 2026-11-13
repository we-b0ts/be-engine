//! MySQL Classic capability, field and wire metadata constants.
pub const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
pub const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
pub const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
pub const MYSQL_REPLAY_AUTH_PLUGIN: &[u8] = b"mysql_native_password";
pub const MYSQL_REPLAY_AUTH_PLUGIN_DATA_1: &[u8; 8] = b"replay01";
pub const MYSQL_REPLAY_AUTH_PLUGIN_DATA_2: &[u8; 12] = b"replay-seed2";

pub const MYSQL_TYPE_TINY: u8 = 1;
pub const MYSQL_TYPE_SHORT: u8 = 2;
pub const MYSQL_TYPE_LONG: u8 = 3;
pub const MYSQL_TYPE_FLOAT: u8 = 4;
pub const MYSQL_TYPE_DOUBLE: u8 = 5;
pub const MYSQL_TYPE_NULL: u8 = 6;
pub const MYSQL_TYPE_TIMESTAMP: u8 = 7;
pub const MYSQL_TYPE_LONGLONG: u8 = 8;
pub const MYSQL_TYPE_INT24: u8 = 9;
pub const MYSQL_TYPE_DATE: u8 = 10;
pub const MYSQL_TYPE_TIME: u8 = 11;
pub const MYSQL_TYPE_DATETIME: u8 = 12;
pub const MYSQL_TYPE_YEAR: u8 = 13;
pub const MYSQL_TYPE_BIT: u8 = 16;
pub const MYSQL_TYPE_JSON: u8 = 245;
pub const MYSQL_TYPE_NEWDECIMAL: u8 = 246;
pub const MYSQL_TYPE_VAR_STRING: u8 = 253;
pub const MYSQL_TYPE_STRING: u8 = 254;
pub const MYSQL_TYPE_GEOMETRY: u8 = 255;

pub const MYSQL_FLAG_NOT_NULL: u16 = 0x0001;
pub const MYSQL_FLAG_UNSIGNED: u16 = 0x0020;
pub const MYSQL_FLAG_BINARY: u16 = 0x0080;
pub const MYSQL_CHARSET_UTF8_GENERAL_CI: u16 = 33;
pub const MYSQL_CHARSET_BINARY: u16 = 63;
