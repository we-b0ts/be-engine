//! Resource fields compose with prevalidated contextual Redis JSON leaves.
use super::*;
use crate::policy::{Codec, Surface};
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
        let scoped = self.scoped_compiled_redis(context, Surface::DependencyRequest);
        let values = super::runtime::request_values(context.command, args)?;
        let Some(value) = values.iter().find(|value| value.argument == Some(argument)) else {
            return Ok(None);
        };
        let rules = Self::filter_redis_value_rules(&scoped, context, value);
        if rules.is_empty() {
            return Ok(None);
        }
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            None,
            None,
        );
        let comparison = crate::value_contract::encoded::compare(source, target, &rules, clocks)?;
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
        let scoped = self.scoped_compiled_redis(context, Surface::DependencyRequest);
        let values = super::runtime::request_values(context.command, args)?;
        let Some(value) = values.iter().find(|value| value.argument == Some(argument)) else {
            return Ok(None);
        };
        let rules = Self::filter_redis_value_rules(&scoped, context, value);
        if rules.is_empty() {
            return Ok(None);
        }
        ensure!(
            rules
                .iter()
                .all(|rule| matches!(rule.rule.codec, Codec::Json)),
            "native JSON and resource declarations disagree on the Redis codec"
        );
        let fields = rules
            .iter()
            .flat_map(|rule| {
                rule.rule
                    .contract
                    .iter()
                    .map(move |(pointer, contract)| Field {
                        rule_id: &rule.rule.id,
                        pointer,
                        contract,
                    })
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
        let verified = native
            .difference(&selected)
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
        let mut comparison = crate::value_contract::json::compare_with_verified(
            source,
            target,
            &fields,
            &[],
            &verified,
            clocks,
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
