//! Successful stored writes make their exact temporal counterparts available to later reads.
use super::*;
use crate::replay::contract_value::CopiedTime;
use crate::value_contract::{
    json::AnchorClocks,
    time_copies::{self, TimeCopyLookup, TimeCopyRecord},
};

#[derive(Clone, Debug)]
pub(in crate::replay) struct PreparedRedisTimeWrite {
    owner: RequestContracts,
    case: String,
    source_completed: Option<DateTime<Utc>>,
    records: Vec<TimeCopyRecord>,
}
impl PreparedRedisTimeWrite {
    pub(in crate::replay) fn publish(&self, target_completed: DateTime<Utc>) -> Result<()> {
        self.owner.record_time_copies(
            &self.case,
            self.records.clone(),
            crate::value_contract::time::ClockPair {
                source: self.source_completed,
                target: Some(target_completed),
            },
        )
    }
}

fn wrote(command: &str, response: &[u8]) -> bool {
    match command {
        "SET" | "SETEX" | "PSETEX" | "MSET" | "HMSET" | "LSET" => response == b"+OK\r\n",
        "HSET" | "RPUSH" | "LPUSH" => std::str::from_utf8(response)
            .ok()
            .and_then(|raw| raw.strip_prefix(':'))
            .and_then(|raw| raw.strip_suffix("\r\n"))
            .and_then(|raw| raw.parse::<u64>().ok())
            .is_some(),
        _ => false,
    }
}

impl RequestContracts {
    pub(in crate::replay) fn prepare_redis_time_write(
        &self,
        context: &RedisRequestContext<'_>,
        source_args: &[Vec<u8>],
        target_args: &[Vec<u8>],
        response: &[u8],
        source_completed: Option<DateTime<Utc>>,
    ) -> Result<Option<PreparedRedisTimeWrite>> {
        let Some(global) = self.global_json() else {
            return Ok(None);
        };
        if !wrote(context.command, response) {
            return Ok(None);
        }
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            source_completed,
            None,
        );
        let source = redis_field_values(context.command, source_args, None)?;
        let target = redis_field_values(context.command, target_args, None)?;
        ensure!(
            source.len() == target.len(),
            "Redis temporal write carrier count changed"
        );
        let mut records = Vec::new();
        for (source, target) in source.iter().zip(&target) {
            if !source.stored {
                continue;
            }
            let (Some(source_payload), Some(target_payload)) = (source.payload, target.payload)
            else {
                continue;
            };
            let (before, after) = if let Some(before) = crate::json_value::parse(source_payload) {
                let after = crate::json_value::parse(target_payload)
                    .context("Redis temporal write Target changed JSON encoding")?;
                (before, after)
            } else if self
                .redis_policy()
                .map(|policy| policy.field(source.key))
                .transpose()?
                .flatten()
                .is_none()
                && let Some(scalar) = crate::value_contract::redis_scalar::decode_automatic(
                    source_payload,
                    global,
                    clocks,
                )?
            {
                let after = scalar.target(target_payload)?;
                (scalar.logical, after)
            } else {
                continue;
            };
            let source_position = super::time_copies::redis_time_position(
                &context.target.host,
                context.target.port,
                context.database,
                source,
            );
            let target_position = super::time_copies::redis_time_position(
                &context.target.host,
                context.target.port,
                context.database,
                target,
            );
            for leaf in time_copies::global_leaves(&before, global, clocks)? {
                let observed = after
                    .pointer(&leaf.pointer)
                    .context("Redis temporal write Target field is absent")?;
                records.push(TimeCopyRecord::new_time(
                    &leaf.time,
                    source_position,
                    target_position,
                    &leaf.pattern,
                    &leaf.pattern,
                    &leaf.value,
                    observed,
                )?);
                ensure!(
                    records.len() <= 4096,
                    "Redis pending write time leaves exceed their bound"
                );
            }
        }
        Ok((!records.is_empty()).then(|| PreparedRedisTimeWrite {
            owner: self.clone(),
            case: context.case.into(),
            source_completed,
            records,
        }))
    }

    pub(in crate::replay::policy::request_contract) fn redis_known_times(
        &self,
        context: &RedisRequestContext<'_>,
        source: &RedisFieldValue<'_>,
        target: &RedisFieldValue<'_>,
        global: &crate::policy::CompiledJsonPolicy,
        clocks: AnchorClocks,
    ) -> Result<Vec<CopiedTime>> {
        if !self.has_time_copies(context.case) {
            return Ok(Vec::new());
        }
        let Some(payload) = source.payload else {
            return Ok(Vec::new());
        };
        let logical = if let Some(logical) = crate::json_value::parse(payload) {
            logical
        } else if let Some(scalar) =
            crate::value_contract::redis_scalar::decode_automatic(payload, global, clocks)?
        {
            scalar.logical
        } else {
            return Ok(Vec::new());
        };
        let source_position = super::time_copies::redis_time_position(
            &context.target.host,
            context.target.port,
            context.database,
            source,
        );
        let target_position = super::time_copies::redis_time_position(
            &context.target.host,
            context.target.port,
            context.database,
            target,
        );
        let mut copies = Vec::new();
        for leaf in time_copies::global_leaves(&logical, global, clocks)? {
            let Some(lookup) = TimeCopyLookup::new_time(
                &leaf.time,
                source_position,
                target_position,
                &leaf.pattern,
                &leaf.pattern,
                &leaf.value,
                leaf.rule_id,
            )
            .map(|lookup| lookup.at(&leaf.pointer, &leaf.pointer)) else {
                continue;
            };
            for (value, proof) in
                self.time_copy_deliveries(context.case, vec![lookup], clocks.dependency)?
            {
                copies.push(CopiedTime {
                    pointer: leaf.pointer.clone(),
                    value,
                    proof,
                });
            }
        }
        Ok(copies)
    }
}
