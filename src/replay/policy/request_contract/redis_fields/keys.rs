//! Protocol key slots may consume already accepted complete identity pairs.
use super::*;

use crate::redis::key_slots::key_indices;

impl RequestContracts {
    /// This projection reads the case bijection and never creates a relation.
    /// Only protocol-owned key slots and opaque script ARGV references change;
    /// TTLs, indices and structured values retain
    /// their existing comparator and their original independent observations.
    pub(in crate::replay::policy::request_contract) fn project_known_redis_keys(
        &self,
        case: &str,
        command: &str,
        source: &[Vec<u8>],
        target: &[Vec<u8>],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        self.project_redis_key_pairs(case, command, source, target, &[])
    }

    pub(in crate::replay::policy::request_contract) fn project_redis_key_pairs(
        &self,
        case: &str,
        command: &str,
        source: &[Vec<u8>],
        target: &[Vec<u8>],
        pairs: &[crate::value_contract::identities::IdentityPair],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        ensure!(source.len() == target.len(), "Redis argument count changed");
        let mut projected = None;
        let mut positions = key_indices(command, source)?;
        if matches!(command, "EVAL" | "EVALSHA") {
            let start = 2 + std::str::from_utf8(&source[1])?.parse::<usize>()?;
            positions.extend((start..source.len()).filter(|&index| {
                !crate::json_value::parse(&source[index])
                    .is_some_and(|value| value.is_object() || value.is_array())
            }));
        } else if command == "DELEX" && source.len() == 3 && source[1].eq_ignore_ascii_case(b"IFEQ")
        {
            positions.push(2);
        }
        for index in positions {
            if source[index] == target[index] {
                continue;
            }
            let (Ok(a), Ok(b)) = (
                std::str::from_utf8(&source[index]),
                std::str::from_utf8(&target[index]),
            ) else {
                continue;
            };
            let source_key = serde_json::to_string(a)?;
            let target_key = serde_json::to_string(b)?;
            if pairs
                .iter()
                .any(|pair| pair.source == source_key && pair.target == target_key)
                || self.knows_native_identity(case, a, b)?
            {
                projected.get_or_insert_with(|| target.to_vec())[index] = source[index].clone();
            }
        }
        Ok(projected)
    }
}
