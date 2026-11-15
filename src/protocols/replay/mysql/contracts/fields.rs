//! Application codec binding for native result-value carriers.
use super::*;
use crate::policy::Codec;
pub(super) use traffic_protocol_mysql::value_rules::fields::response_origin;
pub(super) fn value_bytes(value: &RecordedMysqlValue, codec: &Codec) -> Result<Option<Vec<u8>>> {
    if *codec == Codec::Scalar {
        traffic_protocol_mysql::value_rules::fields::scalar_bytes(value)
    } else {
        traffic_protocol_mysql::value_rules::fields::encoded_bytes(value)
    }
}
