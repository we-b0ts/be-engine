//! Complete scoped Source inventory for finite Redis operation semantics.
use super::*;

/// Build the complete scoped inventory before a native Source owner grants permission.
pub(super) fn source_inventory(
    contracts: &crate::policy::runtime::request_contract::RequestContracts,
    cases: &[crate::policy::runtime::native_projection::NativeSourceCase<'_>],
    selected_effect: impl Fn(&crate::policy::NativeEffect) -> bool,
) -> Result<RedisReplayState> {
    use crate::policy::{Database, Protocol};
    if !contracts
        .compiled_rules()
        .is_some_and(|p| p.native.iter().any(|r| selected_effect(&r.rule.effect)))
    {
        return Ok(RedisReplayState::default());
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
                    selected_effect(&r.rule.effect)
                        && contracts.native_rule_scope_matches(
                            &r.rule.id,
                            Some(case.id),
                            Protocol::Redis,
                            &target,
                            Some(&Database::Index(event["database"].as_i64().unwrap_or(0))),
                            // Retain other users' records on the same database,
                            // so each Case's proof can reject conflicting users
                            // without consulting another ordinary Case's history.
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
    Ok(state)
}
