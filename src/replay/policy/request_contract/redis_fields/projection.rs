//! Preserve immutable resource identities across legacy string projections.
use super::*;
use crate::policy::{FieldContract, Surface};

pub(in crate::replay) struct ProtectedRedisArguments {
    pub source: Vec<Vec<u8>>,
    pub actual: Vec<Vec<u8>>,
}

impl RequestContracts {
    /// A legacy generated-value rule may project other request references.
    /// It cannot replace the original pair at a resource-owned identity leaf
    /// with S/S before the domain comparator observes it.
    pub(in crate::replay) fn protect_redis_identity_values(
        &self,
        context: &RedisRequestContext<'_>,
        original_source: &[Vec<u8>],
        original_target: &[Vec<u8>],
        projected_source: &[Vec<u8>],
        projected_target: &[Vec<u8>],
    ) -> Result<Option<ProtectedRedisArguments>> {
        if original_source == projected_source && original_target == projected_target {
            return Ok(None);
        }
        let scoped = self.scoped_compiled_redis(context, Surface::DependencyRequest);
        if scoped.is_empty() {
            return Ok(None);
        }
        ensure!(
            original_source.len() == projected_source.len()
                && original_target.len() == projected_target.len()
                && original_source.len() == original_target.len(),
            "Redis identity projection changed argument counts"
        );
        let values = super::runtime::request_values(context.command, original_source)?;
        let mut result = None;
        for value in &values {
            let Some(index) = value.argument else {
                continue;
            };
            if original_source[index] == projected_source[index]
                && original_target[index] == projected_target[index]
            {
                continue;
            }
            let rules = Self::filter_redis_value_rules(&scoped, context, value);
            if !crate::value_contract::identities::rules_have_identity(&rules) {
                continue;
            }
            let plan = crate::value_contract::encoded::prepared_codec(&rules)?;
            let source = plan.decode(&original_source[index])?;
            let target = plan.decode(&original_target[index])?;
            let projected_a = plan.decode(&projected_source[index])?;
            let projected_b = plan.decode(&projected_target[index])?;
            let mut protected = BTreeSet::new();
            for rule in &rules {
                for (pattern, contract) in &rule.rule.contract {
                    if !matches!(contract.unconditional(), FieldContract::Identity { .. }) {
                        continue;
                    }
                    for pointer in crate::replay::policy::response::select_json_pointers(
                        pattern,
                        &source.logical,
                        &target.logical,
                    ) {
                        if let FieldContract::Conditional { when, .. } = contract {
                            protected.insert(
                                when.peer_pointer(&pointer)
                                    .context("identity condition has no physical peer")?,
                            );
                        }
                        protected.insert(pointer);
                        ensure!(
                            protected.len() <= 8192,
                            "Redis identity projection field bound exceeded"
                        );
                    }
                }
            }
            let protected = protected.into_iter().collect::<Vec<_>>();
            let restore = |projected: &crate::value_codec::DecodedValue,
                           original: &crate::value_codec::DecodedValue|
             -> Result<Vec<u8>> {
                let mut logical = projected.logical.clone();
                for pointer in &protected {
                    let value = original
                        .logical
                        .pointer(pointer)
                        .context("original Redis identity field is absent")?;
                    *logical
                        .pointer_mut(pointer)
                        .context("projected Redis identity field is absent")? = value.clone();
                }
                projected.encode(&logical, &protected)
            };
            let result = result.get_or_insert_with(|| ProtectedRedisArguments {
                source: projected_source.to_vec(),
                actual: projected_target.to_vec(),
            });
            result.source[index] = restore(&projected_a, &source)?;
            result.actual[index] = restore(&projected_b, &target)?;
        }
        Ok(result)
    }
}
