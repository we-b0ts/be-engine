//! Atomic validation of Redis argument copies, JSON timestamps and signed JWT claims.
use super::*;
use config::{ArgumentRule, JsonField, JwtContract, RedisRequestSelector, TimeField};

pub(super) fn number(value: &Value) -> Result<f64> {
    let value = value.as_f64().context("timestamp must be numeric")?;
    ensure!(
        value.is_finite() && (-62_135_596_800.0..=253_402_300_799.0).contains(&value),
        "timestamp must be finite Unix seconds within years 1..9999"
    );
    Ok(value)
}
fn relative(source: f64, actual: f64, anchor: &CaseAnchor, tolerance: f64) -> Result<()> {
    let recorded = anchor
        .recorded
        .context("request time rule requires recorded request timestamp")?;
    let replay = anchor
        .actual
        .context("request time rule requires an active case")?;
    let seconds = |time: DateTime<Utc>| {
        time.timestamp() as f64 + f64::from(time.timestamp_subsec_nanos()) / 1e9
    };
    ensure!(
        ((actual - seconds(replay)) - (source - seconds(recorded))).abs() <= tolerance,
        "request timestamp differs from its recorded relative time"
    );
    Ok(())
}
fn time(
    source: &Value,
    actual: &Value,
    rule: &TimeField,
    anchor: &CaseAnchor,
) -> Result<(f64, f64)> {
    ensure!(
        source.is_i64() == actual.is_i64() && source.is_u64() == actual.is_u64(),
        "timestamp numeric category changed"
    );
    let pair = (
        timestamp(source, rule.format)?,
        timestamp(actual, rule.format)?,
    );
    relative(pair.0, pair.1, anchor, config::tolerance(&rule.tolerance)?)?;
    Ok(pair)
}

pub(super) fn timestamp(value: &Value, format: config::UnixTimeFormat) -> Result<f64> {
    let unit = match format {
        config::UnixTimeFormat::UnixSeconds => 1.0,
        config::UnixTimeFormat::UnixMilliseconds => 1000.0,
    };
    number(&Value::from(
        value.as_f64().context("timestamp must be numeric")? / unit,
    ))
}

impl RequestContracts {
    pub(in crate::replay) fn preview_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        let rules: Vec<_> = self
            .selected(case, target, DependencyProtocol::Redis)
            .into_iter()
            .filter(|rule| {
                let Some(super::super::redis_value::RedisSelector::Requests(selector)) =
                    &rule.redis
                else {
                    return false;
                };
                selector.database == database
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
            self.compare_redis(case, rule, selector, command, source, actual)
        })())
    }
    pub(super) fn compare_redis(
        &self,
        case: &str,
        rule: &ReplayDependencyRule,
        selector: &RedisRequestSelector,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Result<Decision> {
        ensure!(
            source.len() == actual.len() && source.first() == actual.first(),
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
        let anchor = self.anchor(case)?;
        let mut decision = Decision {
            ids: vec![rule.id.clone()],
            ..Default::default()
        };
        let mut times = Vec::new();
        for (index, (source, actual)) in source.iter().zip(actual).enumerate() {
            match config.argument_values.get(&index) {
                None => ensure!(source == actual, "unselected Redis argument differs"),
                Some(ArgumentRule::Time(field)) => {
                    let source = serde_json::from_slice(source)?;
                    let actual = serde_json::from_slice(actual)?;
                    times.push(time(&source, &actual, field, &anchor)?);
                    decision.time_validations += 1;
                }
                Some(ArgumentRule::Json(fields)) => {
                    let mut source = crate::replay::json_order::parse(source)
                        .context("source value requires bounded complete unique-member JSON")?;
                    let mut actual = crate::replay::json_order::parse(actual)
                        .context("target value requires bounded complete unique-member JSON")?;
                    let source_original = source.clone();
                    let actual_original = actual.clone();
                    for (pointer, field) in &fields.json {
                        let a = source_original
                            .pointer(pointer)
                            .context("source request field is missing")?;
                        let b = actual_original
                            .pointer(pointer)
                            .context("target request field is missing")?;
                        match field {
                            JsonField::Time(field) => {
                                times.push(time(a, b, field, &anchor)?);
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
                                    &field.jwt,
                                    &mut decision,
                                )?;
                            }
                        }
                        *source.pointer_mut(pointer).unwrap() = Value::Null;
                        *actual.pointer_mut(pointer).unwrap() = Value::Null;
                    }
                    ensure!(source == actual, "unselected Redis JSON fields differ");
                }
            }
        }
        ensure!(
            config.argument_values.keys().all(|i| *i < source.len()),
            "selected Redis argument is missing"
        );
        if let Some(first) = times.first() {
            ensure!(
                times
                    .iter()
                    .all(|pair| ((pair.1 - first.1) - (pair.0 - first.0)).abs() <= 0.000_001),
                "request time parameter relationship changed"
            );
        }
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
            if let Some(first) = previous.times.first() {
                for pair in &times {
                    ensure!(
                        ((pair.1 - first.1) - (pair.0 - first.0)).abs() <= 0.000_001,
                        "request time parameter relationship changed"
                    );
                }
            }
            let next = (location + 1) % selector.commands.len();
            let times = if next == 0 {
                vec![]
            } else {
                previous.times.into_iter().chain(times).collect()
            };
            decision.sequence = Some((key, Sequence { next, times }));
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
        config: &JwtContract,
        decision: &mut Decision,
    ) -> Result<()> {
        let key = self
            .keys
            .get(&(rule.into(), pointer.into()))
            .context("request JWT signing key is unavailable")?
            .bytes();
        let a = number(
            source_document
                .pointer(&config.relative_to)
                .context("source JWT time anchor missing")?,
        )?;
        let b = number(
            actual_document
                .pointer(&config.relative_to)
                .context("target JWT time anchor missing")?,
        )?;
        let validated = crate::request_rules::jwt::contract::compare(
            source,
            actual,
            crate::request_rules::jwt::contract::Contract {
                algorithm: config.algorithm,
                key,
                anchors: [(a * 1e9).round() as i128, (b * 1e9).round() as i128],
                tolerance: (config::tolerance(&config.tolerance)? * 1e9).round() as i128,
                dynamic_claims: &config
                    .dynamic_claims
                    .iter()
                    .cloned()
                    .map(crate::request_rules::JwtDynamicClaim::Legacy)
                    .collect::<Vec<_>>(),
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
