//! Compose existing script ARGV clocks with global JSON payload validation.
//! Script identity, KEYS, arity and every undeclared ARGV stay strict.
use super::*;
use crate::policy::native::SequenceArgument;
use crate::policy::{FieldContract, TimestampFormat};
use crate::value_contract::json::{self, Field};
use sha2::{Digest, Sha256};

pub(super) fn compare(
    event: &Value,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    context: &CompareContext<'_>,
) -> Result<(BTreeSet<usize>, Comparison)> {
    let command = event["command"].as_str().unwrap_or_default();
    let Some(request) = context
        .request
        .filter(|_| matches!(command, "EVAL" | "EVALSHA"))
    else {
        return Ok((BTreeSet::new(), Comparison::default()));
    };
    ensure!(
        source.len() == target.len(),
        "Redis script argument inventory changed"
    );
    let count = source.get(1).context("Redis script key count missing")?;
    let keys = std::str::from_utf8(count)?.parse::<usize>()?;
    let first_argument = keys
        .checked_add(2)
        .context("Redis script key count overflow")?;
    // These envelopes cannot select the atomic sequence owner. Leave them to
    // ordinary global payload/remainder validation, including zero-key scripts.
    if keys == 0 || keys > 32 || first_argument >= source.len() {
        return Ok((BTreeSet::new(), Comparison::default()));
    }
    let key = &source[2];
    let resource = observed_resource(event)?;
    let method = request["method"]
        .as_str()
        .context("script Source method unavailable")?;
    let uri: hyper::Uri = request["uri"]
        .as_str()
        .context("script Source URI unavailable")?
        .parse()?;
    let body = capture(&request["body"])
        .ok()
        .and_then(|bytes| crate::json_value::parse(&bytes));
    let mut owned = Vec::new();
    for rule in crate::primary_protocol::assertion::native::selected(
        context.policy,
        method,
        uri.path(),
        body.as_ref(),
    ) {
        let selected = &rule.rule.selector;
        let NativeEffect::RedisSequence(effect) = &rule.rule.effect else {
            continue;
        };
        if !selected
            .resource
            .as_ref()
            .is_none_or(|r| resource_matches(r, &resource))
            || !selected.operation.as_ref().is_none_or(|op| op == command)
            || !selected
                .key
                .as_ref()
                .is_none_or(|selector| key_matches(selector, key))
        {
            continue;
        }
        for entry in &effect.commands {
            if entry.operation != command {
                continue;
            }
            let Some(script) = entry.script.as_ref().map(|s| &s.contract) else {
                continue;
            };
            let matches = |args: &[Vec<u8>]| match command {
                "EVALSHA" => script
                    .sha1
                    .as_ref()
                    .is_some_and(|hash| args[0].eq_ignore_ascii_case(hash.as_bytes())),
                "EVAL" => script.sha256.as_ref().is_some_and(|hash| {
                    args[0].len() <= 1024 * 1024
                        && hash.eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(&args[0])))
                }),
                _ => false,
            };
            if !matches(source) || !matches(target) {
                continue;
            }
            for (&index, argument) in &entry.arguments {
                let SequenceArgument::Time(time) = &argument.contract else {
                    continue;
                };
                ensure!(
                    index >= first_argument && index < source.len(),
                    "native script time selector is outside ARGV"
                );
                owned.push((
                    index,
                    rule.rule.id.as_str(),
                    format!("/{index}"),
                    FieldContract::Time {
                        format: time.format,
                        relation: time.relation,
                        anchor: time.anchor,
                        utc_offset: time.utc_offset.clone(),
                        clock_group: time.clock_group.clone(),
                        clock_scope: time.clock_scope.clone(),
                    },
                ));
            }
        }
    }
    let mut expected = serde_json::Map::new();
    let mut actual = serde_json::Map::new();
    for (index, _, _, contract) in &owned {
        let FieldContract::Time { format, .. } = contract else {
            unreachable!()
        };
        expected.insert(index.to_string(), value(&source[*index], *format)?);
        actual.insert(index.to_string(), value(&target[*index], *format)?);
    }
    let fields = owned
        .iter()
        .map(|(_, rule_id, pointer, contract)| Field {
            rule_id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    let checked = json::compare(
        &Value::Object(expected),
        &Value::Object(actual),
        &fields,
        context.clocks,
    );
    Ok((owned.iter().map(|(index, ..)| *index).collect(), checked))
}

fn value(bytes: &[u8], format: TimestampFormat) -> Result<Value> {
    if matches!(
        format,
        TimestampFormat::UnixSeconds
            | TimestampFormat::UnixMilliseconds
            | TimestampFormat::UnixMicroseconds
    ) {
        serde_json::from_slice(bytes).context("native script timestamp is not a JSON scalar")
    } else {
        Ok(std::str::from_utf8(bytes)
            .context("native script timestamp is not UTF-8")?
            .into())
    }
}
