//! Global JSON comparison for Redis value slots; RESP arguments remain strict.
use super::*;

impl RequestContracts {
    pub(in crate::replay::policy::request_contract) fn compare_redis_compiled(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        if self.global_json().is_none() && self.redis_policy().is_none() {
            return None;
        }
        let values = match request_values(context.command, source) {
            Ok(values) => values,
            Err(error) => return Some(Err(error)),
        };
        if values.is_empty() {
            return None;
        }
        Some((|| {
            ensure!(source.len() == actual.len(), "Redis argument count changed");
            let clocks = self.contract_clocks(
                Some(context.case),
                context.recorded_at,
                context.actual_at,
                None,
                None,
            );
            let normalized = crate::replay::normalize_redis_expiration(
                context.command,
                source,
                actual,
                clocks.dependency,
            )?;
            let actual = normalized.as_deref().unwrap_or(actual);
            let indices = values
                .iter()
                .filter_map(|value| value.argument)
                .collect::<BTreeSet<_>>();
            let mut merged = crate::value_contract::json::Comparison::default();
            for value in &values {
                let index = value
                    .argument
                    .context("Redis write has no argument position")?;
                let mut comparison = self.compare_redis_storage_value(
                    context.case,
                    context.target,
                    context.database,
                    value,
                    &source[index],
                    &actual[index],
                    clocks,
                )?;
                ensure!(
                    comparison.passed(),
                    "Redis global value contract failed: {:?}",
                    comparison.differences
                );
                comparison.scope_schema_clocks(index);
                merged.merge_and_validate(comparison);
            }
            ensure!(
                merged.passed(),
                "Redis value relationships changed: {:?}",
                merged.differences
            );
            let identity = self.identity_decision(context.case, &merged)?;
            let keys = self.project_redis_key_pairs(
                context.case,
                context.command,
                source,
                actual,
                &merged.identity_pairs(),
            )?;
            let actual = keys.as_deref().unwrap_or(actual);
            ensure!(
                source
                    .iter()
                    .zip(actual)
                    .enumerate()
                    .all(|(index, (a, b))| indices.contains(&index) || a == b),
                "Redis key, hash field, index or unselected options/arguments changed"
            );
            let mut decision = Decision::from_value_comparison(merged);
            decision.identity = Some(identity);
            Ok(decision)
        })())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn compare_redis_storage_value(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        value: &RedisFieldValue<'_>,
        source: &[u8],
        actual: &[u8],
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<crate::value_contract::json::Comparison> {
        use crate::value_contract::redis_scalar;
        let scalar = if value.stored {
            self.redis_policy()
                .map(|policy| policy.field(database, value.key))
                .transpose()?
                .flatten()
                .map(|field| {
                    redis_scalar::decode_field(source, field)
                        .map(|scalar| scalar.map(|scalar| (field, scalar)))
                })
                .transpose()?
                .flatten()
        } else {
            None
        };
        let position =
            super::time_copies::redis_time_position(&target.host, target.port, database, value);
        let mut copies = Vec::new();
        if self.has_time_copies(case)
            && let Some((field, scalar)) = &scalar
        {
            let lookups = super::time_copies::redis_scalar_time_write_lookups(
                position, scalar, field, clocks,
            )?;
            copies.extend(self.time_copy_proofs(case, lookups, clocks.dependency));
        }
        let mut compared = if let Some((field, _)) = &scalar {
            redis_scalar::compare(source, actual, field, clocks, &copies)?
        } else {
            Default::default()
        };
        let json_constraint = if let Some((_, value)) = &scalar {
            value.json
                && self
                    .global_json()
                    .map(|global| Ok::<_, anyhow::Error>(global.fields.contains_key("")))
                    .transpose()?
                    .unwrap_or(false)
        } else {
            true
        };
        if json_constraint {
            let empty = crate::policy::CompiledJsonPolicy {
                fields: Default::default(),
                fingerprint: String::new(),
            };
            let global = self.global_json().unwrap_or(&empty);
            let comparison = if value.stored
                && self.has_time_copies(case)
                && crate::json_value::parse(source).is_some()
            {
                let plan = crate::value_codec::CodecPlan::compile(&crate::policy::Codec::Json)?;
                let expected = plan.decode(source)?;
                let observed = plan.decode(actual)?;
                let lookups = super::time_copies::redis_global_time_write_lookups(
                    position, &expected, global, clocks,
                )?;
                let proofs = self.time_copy_proofs(case, lookups, clocks.dependency);
                crate::value_contract::global::compare_decoded_with_time_copies(
                    &expected,
                    &observed,
                    global,
                    &[],
                    clocks,
                    &proofs,
                )?
            } else {
                crate::value_contract::global::compare(source, actual, global, &[], clocks)?
            };
            compared.merge_and_validate(comparison);
        }
        Ok(compared)
    }

    pub(in crate::replay::policy::request_contract) fn observe_redis_compiled_source(
        &self,
        context: &RedisRequestContext<'_>,
        event: &Value,
        source: &[Vec<u8>],
    ) -> Result<()> {
        if self.witnesses.is_none() && self.global_json().is_none() && self.redis_policy().is_none()
        {
            return Ok(());
        }
        let observed = event["timestamp"]
            .as_str()
            .and_then(|value| value.parse().ok());
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            None,
            observed,
            None,
        );
        let identities = response_identities(context.command, source).unwrap_or_default();
        let response = if !identities.is_empty()
            && event.get("outcome").is_none_or(|value| value == "response")
        {
            Some(evidence::decode(&event["response"])?)
        } else {
            None
        };
        if let Some(raw) = &response
            && self.witnesses.is_some()
        {
            self.record_unified_response_source(context, raw, observed);
        }
        if self.global_json().is_none() && self.redis_policy().is_none() {
            return Ok(());
        }
        let responses = if let Some(raw) = response.as_deref() {
            redis_field_values(context.command, source, Some(raw))?
        } else {
            Vec::new()
        };
        let requests = request_values(context.command, source)?;
        let same =
            |pair: crate::value_contract::time::ClockPair| crate::value_contract::time::ClockPair {
                source: pair.source,
                target: pair.source,
            };
        let clocks = crate::value_contract::json::AnchorClocks {
            case: same(clocks.case),
            dependency: same(clocks.dependency),
            delivery: same(clocks.delivery),
        };
        let mut ids = BTreeSet::new();
        for value in requests.into_iter().chain(responses) {
            let Some(payload) = value.payload else {
                continue;
            };
            let validation = self.compare_redis_storage_value(
                context.case,
                context.target,
                context.database,
                &value,
                payload,
                payload,
                clocks,
            )?;
            ensure!(
                validation.passed(),
                "Source Redis global value contract failed: {:?}",
                validation.differences
            );
            ids.extend(validation.evaluated);
        }
        self.observe_source_applicability(context.case, event, ids);
        Ok(())
    }
}

pub(super) fn request_values<'a>(
    command: &str,
    args: &'a [Vec<u8>],
) -> Result<Vec<RedisFieldValue<'a>>> {
    let mut values = redis_field_values(command, args, None)?;
    if let Some(index) = super::super::unified::value_index(command, args.len())
        && !values.iter().any(|value| value.argument == Some(index))
        && let (Some(key), Some(payload)) = (args.first(), args.get(index))
    {
        values.push(RedisFieldValue {
            container: RedisContainer::String,
            key,
            hash_field: None,
            payload: Some(payload),
            stored: false,
            argument: Some(index),
            response: None,
        });
    }
    Ok(values)
}
