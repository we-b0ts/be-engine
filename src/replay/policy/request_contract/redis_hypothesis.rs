//! Native Redis slots project into the shared bounded value hypothesis kernel.
use super::*;
use crate::value_contract::json::Comparison;

impl RequestContracts {
    pub(super) fn preview_redis_hypothesis(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        if !self.pre_match_enabled || source == actual {
            return None;
        }
        Some((|| {
            ensure!(
                source.len() == actual.len() && source.len() <= 16384,
                "Redis hypothesis preserves argument inventory"
            );
            let keys = crate::redis::key_slots::key_indices(context.command, source)?;
            ensure!(
                keys == crate::redis::key_slots::key_indices(context.command, actual)?,
                "Redis physical key slots differ"
            );
            let values = redis_field_values(context.command, source, None)?;
            let mut scalar_slots = values
                .iter()
                .filter_map(|value| value.argument)
                .collect::<BTreeSet<_>>();
            if matches!(context.command, "EVAL" | "EVALSHA") {
                ensure!(
                    source.first() == actual.first() && source.get(1) == actual.get(1),
                    "Redis script identity and key count remain strict"
                );
                scalar_slots.extend(2 + keys.len()..source.len());
            }
            let empty = crate::policy::CompiledJsonPolicy {
                fields: Default::default(),
                fingerprint: String::new(),
                signatures: Default::default(),
            };
            let clocks = self.contract_clocks(
                Some(context.case),
                context.recorded_at,
                context.actual_at,
                None,
                None,
            );
            let mut normalized = actual.to_vec();
            let mut comparison = Comparison::default();
            for (index, (a, b)) in source.iter().zip(actual).enumerate() {
                if a == b {
                    continue;
                }
                let key = keys.contains(&index);
                ensure!(
                    key || scalar_slots.contains(&index),
                    "Redis unowned options or arguments differ"
                );
                if let Some(value) = values.iter().find(|value| value.argument == Some(index))
                    && let Some(policy) = self.redis_policy()
                {
                    ensure!(
                        policy.field(value.key)?.is_none(),
                        "authored Redis scalar owner cannot be replaced by a hypothesis"
                    );
                }
                let (a, b) = if key {
                    key_values(a, b)?
                } else {
                    (argument(a)?, argument(b)?)
                };
                let plan = if !key && (a.is_object() || a.is_array()) {
                    self.global_json().unwrap_or(&empty)
                } else {
                    &empty
                };
                let mut preview = crate::value_contract::hypothesis::preview_values(
                    context.case,
                    &a,
                    &b,
                    plan,
                    clocks,
                );
                for considered in &mut preview.attempts {
                    location(&mut considered.candidate, index, key);
                }
                if let Some(checked) = &mut preview.comparison {
                    for candidate in &mut checked.pre_matches {
                        location(candidate, index, key);
                    }
                }
                let owner = self.with_hypothesis_context(HypothesisContext {
                    carrier: if key {"redis_key"} else {"redis_args"}.into(),
                    source_reference: serde_json::json!({"connection_id":context.connection_id,"sequence":context.sequence,"argument":index}),
                    target_observation_id: context.observation_id.map(|id|id.to_string()),
                });
                let checked = owner
                    .retain_hypothesis_preview(preview)
                    .context("Redis argument has no supported hypothesis")?;
                comparison.merge_and_validate(checked);
                normalized[index] = source[index].clone();
            }
            // Revalidate every declared native/value owner against the projected
            // request. Selected JSON paths were protected by the shared kernel.
            let mut strict = self.clone();
            strict.configure_pre_match(false);
            if let Some(checked) = strict.preview_unified_redis(context, source, &normalized) {
                checked?;
            }
            ensure!(
                source == normalized && !comparison.pre_matches.is_empty() && comparison.passed(),
                "Redis hypothesis must explain the complete request"
            );
            let identity = self.identity_decision(context.case, &comparison)?;
            let mut decision = Decision::from_value_comparison(comparison);
            decision.identity = Some(identity);
            Ok(decision)
        })())
    }
}

fn argument(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)?;
    Ok(crate::json_value::parse(bytes).unwrap_or(Value::String(text.into())))
}

fn key_values(source: &[u8], target: &[u8]) -> Result<(Value, Value)> {
    ensure!(
        source.len() <= 4096 && target.len() <= 4096,
        "Redis hypothesis key exceeds 4096 bytes"
    );
    let (source, target) = (std::str::from_utf8(source)?, std::str::from_utf8(target)?);
    let (a, b) = (key_parts(source), key_parts(target));
    ensure!(
        a.len() <= 64
            && a.len() == b.len()
            && a.iter().zip(&b).all(|(a, b)| match (a, b) {
                (KeyPart::Fixed(a), KeyPart::Fixed(b)) => a == b,
                (KeyPart::Uuid(_), KeyPart::Uuid(_)) | (KeyPart::Time(_), KeyPart::Time(_)) => true,
                _ => false,
            }),
        "Redis key fixed structure or generated slot kind differs"
    );
    ensure!(
        a.iter().any(|part| !matches!(part, KeyPart::Fixed(_))),
        "Redis key has no supported generated slot"
    );
    let values = |parts: Vec<KeyPart<'_>>| -> Result<Value> {
        let mut values = serde_json::Map::new();
        for (index, part) in parts.into_iter().enumerate() {
            let value = match part {
                KeyPart::Fixed(value) | KeyPart::Uuid(value) => Value::String(value.into()),
                KeyPart::Time(value) => crate::json_value::parse(value.as_bytes())
                    .context("Redis key time must be a complete integer")?,
            };
            values.insert(format!("key_part_{index}"), value);
        }
        Ok(Value::Object(values))
    };
    Ok((values(a)?, values(b)?))
}

enum KeyPart<'a> {
    Fixed(&'a str),
    Uuid(&'a str),
    Time(&'a str),
}

fn key_parts(text: &str) -> Vec<KeyPart<'_>> {
    let mut parts = Vec::new();
    let mut cursor = 0;
    let boundary = |byte: Option<u8>| byte.is_none_or(|byte| !byte.is_ascii_alphanumeric());
    for (position, character) in text.char_indices() {
        if position < cursor
            || !boundary(
                position
                    .checked_sub(1)
                    .and_then(|p| text.as_bytes().get(p).copied()),
            )
        {
            continue;
        }
        if let Some(end) = position.checked_add(36)
            && let Some(candidate) = text.get(position..end)
            && boundary(text.as_bytes().get(end).copied())
            && uuid::Uuid::parse_str(candidate).is_ok()
        {
            parts.push(KeyPart::Fixed(&text[cursor..position]));
            parts.push(KeyPart::Uuid(candidate));
            cursor = end;
            continue;
        }
        if character.is_ascii_digit() {
            let end = position
                + text.as_bytes()[position..]
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count();
            let candidate = &text[position..end];
            if matches!(candidate.len(), 10 | 13 | 16)
                && !candidate.starts_with('0')
                && boundary(text.as_bytes().get(end).copied())
                && candidate
                    .parse::<i64>()
                    .is_ok_and(|value| value >= 946_684_800)
            {
                parts.push(KeyPart::Fixed(&text[cursor..position]));
                parts.push(KeyPart::Time(candidate));
                cursor = end;
            }
        }
    }
    parts.push(KeyPart::Fixed(&text[cursor..]));
    parts
}

fn location(candidate: &mut crate::value_contract::hypothesis::Candidate, index: usize, key: bool) {
    let pointer = candidate.pointer.clone();
    candidate.pointer = format!("/args/{index}{pointer}");
    candidate.command = format!(
        "redis.{}:{index}{pointer}",
        if key { "key" } else { "argument" }
    );
    candidate.draft_policy = serde_json::json!({"capability":if key {"redis_key"} else {"redis_argument"},"argument":index,"value_policy":candidate.draft_policy});
    candidate.candidate_id = format!(
        "pre-match-{}",
        &crate::policy_evidence::digest(
            &serde_json::to_vec(&candidate.draft_policy).expect("Redis hypothesis draft")
        )[..16]
    );
}
