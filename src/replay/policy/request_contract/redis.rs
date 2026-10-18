//! Atomic validation of Redis argument copies, JSON timestamps and signed JWT claims.
use super::*;
use config::{ArgumentRule, JsonField, JwtContract, RedisRequestSelector};

impl RequestContracts {
    #[cfg(test)]
    pub(in crate::replay) fn preview_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        // Unit fixtures supply this pair explicitly as dependency observations;
        // production callers must populate RedisRequestContext from the exchange.
        let times = self.request_times(case);
        let mut context = RedisRequestContext::without_exchange(case, target, database, command);
        context.recorded_at = times.source;
        context.actual_at = times.target;
        if let Some(result) = self.preview_unified_redis(&context, source, actual) {
            return Some(result);
        }
        self.preview_redis_legacy(&context, source, actual)
    }

    pub(super) fn preview_redis_legacy(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        let RedisRequestContext {
            case,
            target,
            database,
            username,
            command,
            ..
        } = *context;
        let rules: Vec<_> = self
            .selected(case, target, DependencyProtocol::Redis)
            .into_iter()
            .filter(|rule| {
                let Some(super::super::redis_value::RedisSelector::Requests(selector)) =
                    &rule.redis
                else {
                    return false;
                };
                self.native_rule_scope_matches(
                    &rule.id,
                    Some(case),
                    crate::policy::Protocol::Redis,
                    target,
                    Some(&crate::policy::Database::Index(database)),
                    username,
                ) && selector.database == database
                    && selector.commands.iter().any(|entry| {
                        entry.command == command
                            && entry.matches_identity(source)
                            && entry
                                .key(source)
                                .is_some_and(|key| selector.key.matches(key))
                    })
            })
            .collect();
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            ensure!(rules.len() == 1, "overlapping Redis request contracts");
            let rule = rules[0];
            let super::super::redis_value::RedisSelector::Requests(selector) =
                rule.redis.as_ref().unwrap()
            else {
                unreachable!()
            };
            self.compare_redis(context, rule, selector, source, actual)
        })())
    }
    pub(super) fn compare_redis(
        &self,
        context: &RedisRequestContext<'_>,
        rule: &ReplayDependencyRule,
        selector: &RedisRequestSelector,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Result<Decision> {
        let (case, command) = (context.case, context.command);
        ensure!(
            source.len() == actual.len(),
            "Redis key or argument count changed"
        );
        let location = selector
            .commands
            .iter()
            .position(|c| c.command == command)
            .context("request command is not selected")?;
        let config = &selector.commands[location];
        config.validate_arguments(source)?;
        config.validate_arguments(actual)?;
        if command == "PUBLISH" {
            ensure!(
                source.len() == 2,
                "PUBLISH requires an exact channel and one JSON payload"
            );
        }
        if command == "ZADD" {
            ensure!(
                source.len() == 3,
                "time score requires one plain ZADD member"
            );
        }
        if command == "ZREMRANGEBYSCORE" {
            ensure!(
                source.len() == 3,
                "time maximum requires one plain ZREMRANGEBYSCORE range"
            );
        }
        let anchor = |_field: &config::TimeField| crate::replay::assertion::RequestTimes {
            source: context.recorded_at,
            target: context.actual_at,
        };
        let mut decision = Decision {
            ids: vec![rule.id.clone()],
            ..Default::default()
        };
        self.compare_key(
            case,
            rule,
            selector,
            source.first().context("source key missing")?,
            actual.first().context("target key missing")?,
            crate::replay::assertion::RequestTimes {
                source: context.recorded_at,
                target: context.actual_at,
            },
            &mut decision,
        )?;
        let mut times = Vec::new();
        for (index, (source, actual)) in source.iter().zip(actual).enumerate() {
            if index == 0 {
                continue;
            }
            match config.argument_values.get(&index) {
                None => ensure!(source == actual, "unselected Redis argument differs"),
                Some(ArgumentRule::Time(field)) => {
                    let source = serde_json::from_slice(source)?;
                    let actual = serde_json::from_slice(actual)?;
                    times.push(super::time::compare(
                        &source,
                        &actual,
                        field,
                        anchor(field),
                    )?);
                    decision.time_validations += 1;
                }
                Some(ArgumentRule::Json(fields)) => {
                    let mut source = crate::replay::json_order::parse(source)
                        .context("source value requires bounded complete unique-member JSON")?;
                    let mut actual = crate::replay::json_order::parse(actual)
                        .context("target value requires bounded complete unique-member JSON")?;
                    let source_original = source.clone();
                    let actual_original = actual.clone();
                    for (pattern, field) in &fields.json {
                        let pointers = crate::replay::policy::response::select_json_pointers(
                            pattern,
                            &source_original,
                            &actual_original,
                        );
                        ensure!(
                            !pointers.is_empty() && pointers.len() <= 16384,
                            "selected Redis JSON fields are missing or exceed bounds"
                        );
                        for pointer in &pointers {
                            let time_start = times.len();
                            let a = source_original
                                .pointer(pointer)
                                .context("source request field is missing")?;
                            let b = actual_original
                                .pointer(pointer)
                                .context("target request field is missing")?;
                            match field {
                                JsonField::Random(field) => field.random.compare(a, b)?,
                                JsonField::Url(field) => {
                                    let compared = field.compare(a, b, anchor)?;
                                    decision.time_validations += compared.len();
                                    times.extend(compared);
                                }
                                JsonField::Identity(reference) => self.compare_identity(
                                    case,
                                    rule,
                                    selector.database,
                                    &reference.identity,
                                    a.as_str()
                                        .context("source identity reference is not a string")?,
                                    b.as_str()
                                        .context("target identity reference is not a string")?,
                                    &mut decision,
                                )?,
                                JsonField::Time(field) => {
                                    times.push(super::time::compare(a, b, field, anchor(field))?);
                                    decision.time_validations += 1;
                                }
                                JsonField::Jwt(field) => {
                                    self.jwt(
                                        case,
                                        &rule.id,
                                        pointer,
                                        a,
                                        b,
                                        &source_original,
                                        &actual_original,
                                        match fields.json.get(&field.jwt.relative_to) {
                                            Some(JsonField::Time(field)) => field,
                                            _ => anyhow::bail!(
                                                "JWT anchor has no typed time contract"
                                            ),
                                        },
                                        &field.jwt,
                                        &mut decision,
                                    )?;
                                }
                            }
                            *source.pointer_mut(pointer).unwrap() = Value::Null;
                            *actual.pointer_mut(pointer).unwrap() = Value::Null;
                            // Explicit named clocks on array patterns belong to each
                            // matched element, rather than every element sharing a read.
                            let indices = pattern
                                .split('/')
                                .zip(pointer.split('/'))
                                .filter_map(|(p, v)| (p == "*").then_some(v))
                                .collect::<Vec<_>>();
                            if !indices.is_empty() {
                                for time in &mut times[time_start..] {
                                    if let Some(group) = &mut time.group {
                                        group.push(':');
                                        group.push_str(&indices.join(":"));
                                    }
                                }
                            }
                        }
                    }
                    ensure!(source == actual, "unselected Redis JSON fields differ");
                }
            }
        }
        ensure!(
            config.argument_values.keys().all(|i| *i < source.len()),
            "selected Redis argument is missing"
        );
        super::time::validate_relationships(&times)?;
        if selector.commands.len() > 1 {
            let key = (
                case.into(),
                rule.id.clone(),
                config.key(source).context("Redis key is missing")?.to_vec(),
            );
            let previous = self
                .state
                .lock()
                .expect("request contracts")
                .sequences
                .get(&key)
                .cloned()
                .unwrap_or_default();
            ensure!(
                previous.next == location,
                "request time sequence differs from configured order"
            );
            if let Some(key) = &previous.actual_key {
                ensure!(
                    Some(key) == actual.first(),
                    "key changed within a command sequence"
                );
            }
            super::time::validate_relationships(
                &previous
                    .times
                    .iter()
                    .chain(&times)
                    .cloned()
                    .collect::<Vec<_>>(),
            )?;
            let next = (location + 1) % selector.commands.len();
            let times = if next == 0 {
                vec![]
            } else {
                previous.times.into_iter().chain(times).collect()
            };
            decision.sequence = Some((
                key,
                Sequence {
                    next,
                    times,
                    actual_key: (next != 0).then(|| actual[0].clone()),
                },
            ));
        }
        Ok(decision)
    }
    #[allow(clippy::too_many_arguments)]
    fn jwt(
        &self,
        case: &str,
        rule: &str,
        pointer: &str,
        source: &Value,
        actual: &Value,
        source_document: &Value,
        actual_document: &Value,
        anchor_contract: &config::TimeField,
        config: &JwtContract,
        decision: &mut Decision,
    ) -> Result<()> {
        let key = self
            .keys
            .get(&(rule.into(), pointer.into()))
            .context("request JWT signing key is unavailable")?
            .bytes();
        let a = super::time::timestamp(
            source_document
                .pointer(&config.relative_to)
                .context("source JWT time anchor missing")?,
            anchor_contract,
        )?;
        let b = super::time::timestamp(
            actual_document
                .pointer(&config.relative_to)
                .context("target JWT time anchor missing")?,
            anchor_contract,
        )?;
        let validated = crate::request_rules::jwt::contract::compare(
            source,
            actual,
            crate::request_rules::jwt::contract::Contract {
                algorithm: config.algorithm,
                key,
                anchors: [a, b],
                tolerance: (config::tolerance(&config.tolerance)? * 1e9).round() as i128,
                dynamic_claims: &config.dynamic_claims,
            },
        )
        .map_err(|error| anyhow::anyhow!("JWT contract failed: {error:?}"))?;
        decision.time_validations += validated.time_validations;
        for nonce in validated.nonces {
            let claim = &nonce.claim;
            let a = nonce.source;
            let b = nonce.target;
            let key = (case.into(), rule.into(), format!("{pointer}{claim}"));
            let state = self.state.lock().expect("request contracts");
            if let Some(bindings) = state.nonces.get(&key) {
                ensure!(
                    (bindings.contains_key(&a) || bindings.len() < 256)
                        && bindings
                            .iter()
                            .all(|(left, right)| (left != &a || right == &b)
                                && (right != &b || left == &a)),
                    "JWT nonce binding is inconsistent"
                );
            }
            drop(state);
            decision.nonces.push((key, a, b));
        }
        Ok(())
    }
}
