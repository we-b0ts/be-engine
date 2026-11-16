//! Protocol key slots may consume already accepted complete identity pairs.
use super::*;

impl RequestContracts {
    /// This projection reads the case bijection and never creates a relation.
    /// Only protocol-owned key slots and opaque script ARGV references change;
    /// TTLs, indices and structured values retain
    /// their existing comparator and their original independent observations.
    pub(crate) fn project_known_redis_keys(
        &self,
        case: &str,
        command: &str,
        source: &[Vec<u8>],
        target: &[Vec<u8>],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        self.project_redis_key_pairs(case, command, source, target, &[])
    }

    pub(crate) fn project_redis_key_pairs(
        &self,
        case: &str,
        command: &str,
        source: &[Vec<u8>],
        target: &[Vec<u8>],
        pairs: &[crate::value_contract::identities::IdentityPair],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        traffic_protocol_redis::value_rules::project_key_references(
            command,
            source,
            target,
            pairs,
            |bytes| {
                crate::value_codec::try_recognize(bytes, &traffic_value::Value::Null)
                    .ok()
                    .flatten()
                    .and_then(|codec| codec.decode(bytes).ok())
                    .is_some_and(|value| value.logical.is_object() || value.logical.is_array())
            },
            |source, target| self.knows_native_identity(case, source, target),
        )
    }
}
