//! The planner and runtime share complete Source byte-stream validation.
use super::*;
use crate::replay::policy::native_projection::NativeSourceCase;

pub(in crate::replay) fn validate_source(
    contracts: &crate::replay::policy::request_contract::RequestContracts,
    cases: &[NativeSourceCase<'_>],
) -> Result<BTreeMap<String, usize>> {
    if !contracts.compiled_rules().is_some_and(|p| {
        p.native
            .iter()
            .any(|r| matches!(r.rule.effect, NativeEffect::RedisAppendStream))
    }) {
        return Ok(BTreeMap::new());
    }
    let mut state = RedisReplayState {
        request_contracts: contracts.clone(),
        ..Default::default()
    };
    let mut targets = BTreeMap::new();
    for case in cases {
        for event in case
            .events
            .iter()
            .filter(|e| e["event_type"] == "redis_exchange")
        {
            let target = TargetKey {
                host: event["target_host"]
                    .as_str()
                    .context("Source Redis host missing")?
                    .into(),
                port: u16::try_from(
                    event["target_port"]
                        .as_u64()
                        .context("Source Redis port missing")?,
                )?,
            };
            let selected = contracts
                .compiled_rules()
                .into_iter()
                .flat_map(|p| &p.native)
                .any(|r| {
                    matches!(r.rule.effect, NativeEffect::RedisAppendStream)
                        && contracts.native_rule_scope_matches(
                            &r.rule.id,
                            Some(case.id),
                            Protocol::Redis,
                            &target,
                            Some(&Database::Index(event["database"].as_i64().unwrap_or(0))),
                            // Retain other users' records on the same database,
                            // so complete Source preparation can reject key overlap.
                            r.rule
                                .selector
                                .resource
                                .as_ref()
                                .and_then(|resource| resource.username.as_deref())
                                .or_else(|| event["username"].as_str()),
                        )
                });
            if selected {
                state.register_exchange(
                    serde_json::from_value(event.clone())?,
                    ReplaySource::Case,
                    Some(case.id),
                    &mut targets,
                    &[],
                )?;
            }
        }
    }
    for case in cases {
        state.prepare_append_case(case.id)?;
    }
    let mut counts = BTreeMap::new();
    for profile in state.append_streams.profiles {
        *counts.entry(profile.rule).or_default() += profile.pieces.len();
    }
    Ok(counts)
}
