//! Redis resource-field selection, strict request remainder and Source applicability.
use super::*;
use crate::policy::{CompiledRule, Protocol, Slot, Surface};

impl RequestContracts {
    pub(in crate::replay::policy::request_contract) fn scoped_compiled_redis(
        &self,
        context: &RedisRequestContext<'_>,
        surface: Surface,
    ) -> Vec<&CompiledRule> {
        let Some(policy) = &self.compiled else {
            return Vec::new();
        };
        let candidates = policy
            .resource_rules(
                surface,
                Protocol::Redis,
                &context.target.host,
                context.target.port,
            )
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }
        let state = self.state.lock().expect("request contracts");
        let Some(anchor) = state.cases.get(context.case) else {
            return Vec::new();
        };
        candidates
            .into_iter()
            .filter(|compiled| {
                let rule = &compiled.rule;
                let resource = rule.selector.resource.as_ref().expect("indexed resource");
                resource
                    .database
                    .as_ref()
                    .is_none_or(|database| database.index() == Some(context.database))
                    && resource
                        .username
                        .as_deref()
                        .is_none_or(|username| Some(username) == context.username)
                    && rule
                        .selector
                        .operation
                        .as_deref()
                        .is_none_or(|operation| operation == context.command)
                    && rule.selector.matches_api(&anchor.method, &anchor.path)
                    && rule.when.as_ref().is_none_or(|condition| {
                        anchor
                            .source_body
                            .as_ref()
                            .is_some_and(|body| condition.matches_body(body))
                    })
            })
            .collect()
    }

    pub(in crate::replay::policy::request_contract) fn filter_redis_value_rules<'a>(
        scoped: &[&'a CompiledRule],
        context: &RedisRequestContext<'_>,
        value: &RedisFieldValue<'_>,
    ) -> Vec<&'a CompiledRule> {
        scoped
            .iter()
            .copied()
            .filter(|compiled| {
                let rule = &compiled.rule;
                let slot_matches = match rule.slot {
                    Slot::RedisValue(container) => value.stored && container == value.container,
                    Slot::Value if rule.surface == Surface::DependencyRequest => {
                        value.argument
                            == super::super::unified::value_index(
                                context.command,
                                if matches!(context.command, "SETEX" | "PSETEX") {
                                    3
                                } else {
                                    2
                                },
                            )
                    }
                    Slot::Value => matches!(context.command, "GET" | "HGET"),
                    _ => false,
                };
                slot_matches
                    && rule
                        .selector
                        .key
                        .as_ref()
                        .is_some_and(|key| key.matches(value.key))
                    && rule.selector.hash_field.as_ref().is_none_or(|field| {
                        value.hash_field.is_some_and(|value| field.matches(value))
                            || (context.command == "HGETALL" && value.hash_field.is_none())
                    })
            })
            .collect()
    }

    pub(in crate::replay::policy::request_contract) fn compare_redis_compiled(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        let scoped = self.scoped_compiled_redis(context, Surface::DependencyRequest);
        if scoped.is_empty() {
            return None;
        }
        let raw_selected =
            scoped.iter().any(|rule| {
                matches!(rule.rule.slot, Slot::Value)
                    && rule.rule.selector.key.as_ref().is_some_and(|selector| {
                        source.first().is_some_and(|key| selector.matches(key))
                    })
            });
        let values = match request_values(context.command, source) {
            Ok(values) => values,
            Err(error) => return raw_selected.then_some(Err(error)),
        };
        if values.is_empty() && raw_selected {
            return Some(Err(anyhow::anyhow!(
                "command does not expose a supported Redis value slot"
            )));
        }
        let selected = values
            .iter()
            .map(|value| {
                (
                    value,
                    Self::filter_redis_value_rules(&scoped, context, value),
                )
            })
            .filter(|(_, rules)| !rules.is_empty())
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return None;
        }
        Some((|| {
            ensure!(source.len() == actual.len(), "Redis argument count changed");
            let indices = selected
                .iter()
                .filter_map(|(value, _)| value.argument)
                .collect::<BTreeSet<_>>();
            ensure!(
                source
                    .iter()
                    .zip(actual)
                    .enumerate()
                    .all(|(index, (a, b))| { indices.contains(&index) || a == b }),
                "Redis key, hash field, index or unselected options/arguments changed"
            );
            let clocks = self.contract_clocks(
                Some(context.case),
                context.recorded_at,
                context.actual_at,
                None,
                None,
            );
            let mut merged = crate::value_contract::json::Comparison::default();
            let mut plans = BTreeMap::new();
            for (value, rules) in selected {
                let index = value
                    .argument
                    .context("Redis write has no argument position")?;
                let key = rules
                    .iter()
                    .map(|rule| rule.rule.id.as_str())
                    .collect::<Vec<_>>();
                let plan = if let Some(plan) = plans.get(&key) {
                    Arc::clone(plan)
                } else {
                    let plan = prepared_codec(&rules)?;
                    plans.insert(key, Arc::clone(&plan));
                    plan
                };
                let expected = plan.decode(&source[index])?;
                let observed = plan.decode(&actual[index])?;
                let position = super::time_copies::redis_time_position(
                    &context.target.host,
                    context.target.port,
                    context.database,
                    value,
                );
                let copies = if self.has_time_copies(context.case) {
                    let lookups = super::time_copies::redis_time_write_lookups(
                        position, position, &expected, &rules,
                    )?;
                    self.time_copy_proofs(context.case, lookups, clocks.dependency)
                } else {
                    Vec::new()
                };
                let mut comparison =
                    crate::value_contract::encoded::compare_decoded_with_time_copies(
                        &expected, &observed, &rules, clocks, &copies,
                    )?;
                ensure!(
                    comparison.passed(),
                    "Redis value contract failed: {}",
                    serde_json::to_string(&comparison.differences)?
                );
                comparison.scope_schema_clocks(index);
                merged.merge_and_validate(comparison);
            }
            ensure!(
                merged.passed(),
                "Redis value relationships changed: {}",
                serde_json::to_string(&merged.differences)?
            );
            let identity = self.identity_decision(context.case, &merged)?;
            let mut decision = Decision::from_value_comparison(merged);
            decision.identity = Some(identity);
            Ok(decision)
        })())
    }

    pub(in crate::replay::policy::request_contract) fn observe_redis_compiled_source(
        &self,
        context: &RedisRequestContext<'_>,
        event: &Value,
        source: &[Vec<u8>],
    ) -> Result<()> {
        let request_rules = self.scoped_compiled_redis(context, Surface::DependencyRequest);
        let response_rules = self.scoped_compiled_redis(context, Surface::DependencyResponse);
        if request_rules.is_empty() && response_rules.is_empty() && self.witnesses.is_none() {
            return Ok(());
        }
        let mut ids = BTreeSet::new();
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
        let response_selected = identities.iter().any(|value| {
            !Self::filter_redis_value_rules(&response_rules, context, value).is_empty()
        });
        let retain_response = self.witnesses.is_some() && !identities.is_empty();
        let raw = if (response_selected || retain_response)
            && event.get("outcome").is_none_or(|value| value == "response")
        {
            Some(evidence::decode(&event["response"])?)
        } else {
            None
        };
        if let Some(raw) = raw.as_deref()
            && retain_response
        {
            self.record_unified_response_source(context, raw, observed);
        }
        let response_values = if let Some(raw) = raw.as_deref().filter(|_| response_selected) {
            redis_field_values(context.command, source, Some(raw))?
        } else {
            identities
        };
        let request_values = if request_rules.is_empty() {
            Vec::new()
        } else {
            request_values(context.command, source).unwrap_or_default()
        };
        let mut plans = BTreeMap::new();
        for (values, scoped) in [
            (request_values, request_rules),
            (response_values, response_rules),
        ] {
            for value in values {
                let selected = Self::filter_redis_value_rules(&scoped, context, &value);
                if selected.is_empty() {
                    continue;
                }
                let Some(payload) = value.payload else {
                    self.observe_value_slot_unavailable(selected.iter().map(|r| r.rule.id.clone()));
                    continue;
                };
                let key = selected
                    .iter()
                    .map(|rule| rule.rule.id.as_str())
                    .collect::<Vec<_>>();
                let plan = if let Some(plan) = plans.get(&key) {
                    Arc::clone(plan)
                } else {
                    let plan = prepared_codec(&selected)?;
                    plans.insert(key, Arc::clone(&plan));
                    plan
                };
                let decoded = plan.decode(payload)?;
                for rule in &selected {
                    for pointer in rule.delivery_time.keys() {
                        ensure!(
                            crate::value_contract::json::pointer_observed(
                                &decoded.logical,
                                pointer
                            ),
                            "Source delivery timestamp {pointer:?} was not observed"
                        );
                    }
                }
                let same_clock = |pair: crate::value_contract::time::ClockPair| {
                    crate::value_contract::time::ClockPair {
                        source: pair.source,
                        target: pair.source,
                    }
                };
                let validation = crate::value_contract::encoded::compare_decoded(
                    &decoded,
                    &decoded,
                    &selected,
                    crate::value_contract::json::AnchorClocks {
                        case: same_clock(clocks.case),
                        dependency: same_clock(clocks.dependency),
                        delivery: same_clock(clocks.delivery),
                    },
                )?;
                ensure!(
                    validation.passed(),
                    "Source Redis value violates its declared contract: {:?}",
                    validation.differences
                );
                ids.extend(validation.evaluated);
            }
        }
        self.observe_source_applicability(context.case, event, ids);
        Ok(())
    }
}

fn prepared_codec(rules: &[&CompiledRule]) -> Result<Arc<crate::value_codec::CodecPlan>> {
    crate::value_contract::encoded::prepared_codec(rules)
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
