//! Resource fields compose with prevalidated contextual Redis JSON leaves.
use super::*;
use crate::value_contract::json::{Comparison, Field, LeafObservations, VerifiedField};

impl RequestContracts {
    /// Key-only contextual effects leave ordinary storage values to their
    /// resource declarations. Resolve the physical carrier before decoding so
    /// unrelated TTLs, options, keys and opaque arguments remain byte exact.
    pub(in crate::replay::policy::request_contract) fn compare_redis_native_argument(
        &self,
        context: &RedisRequestContext<'_>,
        args: &[Vec<u8>],
        argument: usize,
        source: &[u8],
        target: &[u8],
    ) -> Result<Option<Comparison>> {
        let values = super::runtime::request_values(context.command, args)?;
        let Some(value) = values.iter().find(|value| value.argument == Some(argument)) else {
            return Ok(None);
        };
        if self.global_json().is_none() && self.redis_policy().is_none() {
            return Ok(None);
        }
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            None,
            None,
        );
        let comparison = self.compare_redis_storage_value(
            context.case,
            context.target,
            context.database,
            value,
            source,
            target,
            clocks,
        )?;
        ensure!(
            comparison.passed(),
            "Redis resource value failed: {:?}",
            comparison.differences
        );
        Ok(Some(comparison))
    }

    /// The native owner already checked its selected leaves, including signed
    /// values and explicit clock relationships. Reuse only those exact leaf
    /// pairs while the common comparator validates declared resource fields
    /// and the complete, immutable JSON remainder together.
    pub(in crate::replay::policy::request_contract) fn compare_redis_native_fields(
        &self,
        context: &RedisRequestContext<'_>,
        args: &[Vec<u8>],
        argument: usize,
        source: &Value,
        target: &Value,
        native: &BTreeSet<String>,
    ) -> Result<Option<Comparison>> {
        let values = super::runtime::request_values(context.command, args)?;
        let Some(value) = values.iter().find(|value| value.argument == Some(argument)) else {
            return Ok(None);
        };
        let Some(global) = self.global_json() else {
            return Ok(None);
        };
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            None,
            None,
        );
        let selected_fields = global.comparison_fields(source, target, clocks)?;
        let fields = selected_fields
            .iter()
            .map(|(pointer, contract)| Field {
                rule_id: crate::policy::GLOBAL_JSON_ID,
                pointer,
                contract,
            })
            .collect::<Vec<_>>();
        let mut selected = BTreeSet::new();
        for field in &fields {
            selected.extend(crate::replay::policy::response::select_json_pointers(
                field.pointer,
                source,
                target,
            ));
            ensure!(
                selected.len() <= 16384,
                "Redis resource field bound exceeded"
            );
        }
        let verify = |context: crate::value_contract::json::LeafContext<'_>| {
            if context.source_pointer != context.target_pointer
                || source.pointer(context.source_pointer) != Some(context.source)
                || target.pointer(context.target_pointer) != Some(context.target)
            {
                return Err("native Redis leaf pairing changed".into());
            }
            Ok(LeafObservations::default())
        };
        let mut verified = native
            .iter()
            .filter(|pointer| {
                !selected.contains(*pointer)
                    || selected_fields.iter().any(|(path, _)| path == *pointer)
            })
            .map(|pointer| VerifiedField {
                rule_id: "schema:redis-native-prevalidated",
                pointer,
                verifier: &verify,
            })
            .collect::<Vec<_>>();
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            None,
            None,
        );
        let copies = if value.stored
            && self.has_time_copies(context.case)
            && let Some(global) = self.global_json()
        {
            let position = super::time_copies::redis_time_position(
                &context.target.host,
                context.target.port,
                context.database,
                value,
            );
            let mut lookups = Vec::new();
            for leaf in crate::value_contract::time_copies::global_leaves(source, global, clocks)? {
                if let Some(lookup) = crate::value_contract::time_copies::TimeCopyLookup::new_time(
                    &leaf.time,
                    position,
                    position,
                    &leaf.pattern,
                    &leaf.pattern,
                    &leaf.value,
                    crate::policy::GLOBAL_JSON_ID,
                ) {
                    lookups.push(lookup.at(&leaf.pointer, &leaf.pattern));
                }
            }
            self.time_copy_proofs(context.case, lookups, clocks.dependency)
        } else {
            vec![]
        };
        let checks = crate::value_contract::global_protocol::checks(global, source)?;
        verified.extend(checks.fields());
        let mut comparison = crate::value_contract::json::compare_with_verified_time_copies(
            source, target, &fields, &verified, clocks, &copies,
        );
        // This verifier grants no additional authored policy use.
        comparison
            .evaluated
            .remove("schema:redis-native-prevalidated");
        ensure!(
            comparison.passed(),
            "Redis native/resource fields failed: {}",
            serde_json::to_string(&comparison.differences)?
        );
        Ok(Some(comparison))
    }
}
