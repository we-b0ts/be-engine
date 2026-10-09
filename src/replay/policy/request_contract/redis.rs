//! Atomic validation of Redis argument copies, JSON timestamps and signed JWT claims.
use super::*;
use base64::Engine as _;
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
    let pair = (number(source)?, number(actual)?);
    relative(pair.0, pair.1, anchor, config::tolerance(&rule.tolerance)?)?;
    Ok(pair)
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
                    && source.first().is_some_and(|key| selector.key.matches(key))
                    && selector
                        .commands
                        .iter()
                        .any(|entry| entry.command == command)
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
                                time(a, b, field, &anchor)?;
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
        if selector.commands.len() > 1 {
            let key = (case.into(), rule.id.clone(), source[0].clone());
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
        let parse = |value: &Value| {
            let raw = value.as_str().context("JWT must be a string")?;
            let token = crate::request_rules::jwt::Token::parse(raw)?
                .context("invalid compact HMAC JWT")?;
            for part in raw.split('.').take(2) {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part)?;
                crate::replay::json_order::parse(&bytes)
                    .context("JWT header and claims require complete unique-member JSON")?;
            }
            Ok::<_, anyhow::Error>(token)
        };
        let mut source = parse(source)?;
        let mut actual = parse(actual)?;
        let key = self
            .keys
            .get(&(rule.into(), pointer.into()))
            .context("request JWT signing key is unavailable")?
            .bytes();
        ensure!(
            source.algorithm == config.algorithm
                && actual.algorithm == config.algorithm
                && source.verify(key)
                && actual.verify(key),
            "JWT algorithm or signature differs from its declared signing contract"
        );
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
        for name in ["exp", "iat", "nbf"] {
            let left = source.integer_claim(name)?;
            let right = actual.integer_claim(name)?;
            ensure!(
                left.is_some() == right.is_some(),
                "JWT time claim presence changed"
            );
            if let (Some(left), Some(right)) = (left, right) {
                decision.time_validations += 1;
                ensure!(
                    ((right as f64 - b) - (left as f64 - a)).abs()
                        <= config::tolerance(&config.tolerance)?,
                    "JWT relative lifetime changed"
                );
                if matches!(name, "iat" | "nbf") {
                    ensure!(
                        left as f64 <= a + config::tolerance(&config.tolerance)?
                            && right as f64 <= b + config::tolerance(&config.tolerance)?,
                        "JWT is not valid at generation"
                    );
                }
                if name == "exp" {
                    ensure!(
                        left as f64 > a && right as f64 > b,
                        "JWT expired at generation"
                    );
                }
                source.claims[name] = Value::Null;
                actual.claims[name] = Value::Null;
            }
        }
        ensure!(source.claims.get("exp").is_some(), "JWT requires exp");
        for claim in &config.dynamic_claims {
            let a = source
                .claims
                .pointer(claim)
                .and_then(Value::as_str)
                .context("source JWT nonce is missing")?
                .to_owned();
            let b = actual
                .claims
                .pointer(claim)
                .and_then(Value::as_str)
                .context("target JWT nonce is missing")?
                .to_owned();
            for value in [&a, &b] {
                ensure!(
                    uuid::Uuid::parse_str(value)?.get_version_num() == 4,
                    "JWT nonce must be UUID v4"
                );
            }
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
            *source.claims.pointer_mut(claim).unwrap() = Value::Null;
            *actual.claims.pointer_mut(claim).unwrap() = Value::Null;
        }
        ensure!(
            source.header_value()? == actual.header_value()? && source.claims == actual.claims,
            "unselected JWT header or claims differ"
        );
        Ok(())
    }
}
