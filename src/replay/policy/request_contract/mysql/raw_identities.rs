//! Recover declared raw ID pairs after a native owner validated comparison copies.
//! The accepted normalized pairing also preserves unordered element associations.
use super::*;
use crate::mysql::sql::Token;
use crate::replay::policy::matcher::{mysql_native::fields, mysql_values};
use crate::value_contract::{identities::IdentityPair, json::Comparison};

type Tokens = BTreeMap<(String, String), String>;

pub(super) fn restore(
    rules: &[&CompiledRule],
    normalized: &RecordedMysqlExchange,
    target_sql: Option<&str>,
    target_params: Option<&[RecordedMysqlValue]>,
    raw: RawMysqlIdentityRequest<'_>,
    comparison: &Comparison,
) -> Result<Vec<IdentityPair>> {
    let statements = [
        (raw.source.sql.as_deref(), raw.source.params.as_deref()),
        (normalized.sql.as_deref(), normalized.params.as_deref()),
        (raw.target_sql, raw.target_params),
        (target_sql, target_params),
    ];
    let tokens = statements
        .into_iter()
        .map(|(sql, params)| mysql_values::materialized(sql, params).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        tokens.iter().all(|value| value.len() == tokens[0].len()),
        "native normalization changed the raw identity statement shape"
    );
    let analyses = tokens
        .iter()
        .map(|tokens| {
            crate::mysql::sql::field_bindings::analyze(tokens, raw.source.database.as_deref())
                .context("raw identity physical SQL origins are unavailable")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut groups = BTreeMap::<usize, Vec<&CompiledRule>>::new();
    for rule in rules
        .iter()
        .copied()
        .filter(|rule| crate::value_contract::identities::rules_have_identity(&[*rule]))
    {
        ensure!(
            matches!(rule.rule.slot, Slot::SqlField(_)),
            "raw SQL identity requires a physical field"
        );
        let positions = fields::positions_in(rule, &analyses[0])?;
        for analysis in analyses.iter().skip(1) {
            ensure!(
                fields::positions_in(rule, analysis)? == positions,
                "native normalization changed a declared identity's physical position"
            );
        }
        for position in positions {
            groups.entry(position).or_default().push(rule);
        }
    }
    let (mut source, mut target) = (Tokens::new(), Tokens::new());
    for (position, rules) in groups {
        let plan = crate::value_contract::encoded::prepared_codec(&rules)?;
        collect_side(
            &tokens[0][position],
            &tokens[1][position],
            &rules,
            &plan,
            &mut source,
        )?;
        collect_side(
            &tokens[2][position],
            &tokens[3][position],
            &rules,
            &plan,
            &mut target,
        )?;
    }
    comparison
        .identity_pairs()
        .into_iter()
        .map(|pair| {
            Ok(IdentityPair {
                source: source
                    .get(&(pair.domain.clone(), pair.source))
                    .context("normalized Source identity has no immutable field witness")?
                    .clone(),
                target: target
                    .get(&(pair.domain.clone(), pair.target))
                    .context("normalized Target identity has no immutable field witness")?
                    .clone(),
                domain: pair.domain,
            })
        })
        .collect()
}

fn payload(token: &Token, scalar: bool) -> Result<Vec<u8>> {
    if scalar {
        return Ok(serde_json::to_vec(&fields::scalar(token)?)?);
    }
    let Token::Bytes(bytes) = token else {
        anyhow::bail!("raw identity document is not encoded SQL bytes")
    };
    Ok(bytes.clone())
}

fn collect_side(
    raw: &Token,
    normalized: &Token,
    rules: &[&CompiledRule],
    plan: &crate::value_codec::CodecPlan,
    index: &mut Tokens,
) -> Result<()> {
    let scalar = rules[0].rule.codec == crate::policy::Codec::Scalar;
    let raw = payload(raw, scalar)?;
    let normalized = payload(normalized, scalar)?;
    let normalized_value = plan.decode(&normalized)?;
    let raw_value = (raw != normalized).then(|| plan.decode(&raw)).transpose()?;
    let raw_value = raw_value.as_ref().unwrap_or(&normalized_value);
    for selected in
        crate::value_contract::identities::select_with_inactive(&normalized_value.logical, rules)?
    {
        let original = raw_value
            .logical
            .pointer(&selected.pointer)
            .context("raw identity field disappeared during normalization")?;
        if let Some(condition) = selected.condition {
            let active = condition.matches_pair(
                &normalized_value.logical,
                &raw_value.logical,
                &selected.pointer,
                &selected.pointer,
            )?;
            if !active {
                ensure!(
                    original == selected.delivery.value,
                    "native normalization changed an inactive exact identity field"
                );
                continue;
            }
        }
        ensure!(
            selected.delivery.value.is_string() == original.is_string()
                && selected.delivery.value.is_number() == original.is_number(),
            "native normalization changed raw identity representation"
        );
        let normalized = selected.delivery.token()?;
        let original = crate::value_contract::identities::IdentityDelivery {
            value: original,
            ..selected.delivery
        }
        .token()?;
        let key = (selected.delivery.binding.to_owned(), normalized);
        if let Some(previous) = index.insert(key, original.clone()) {
            ensure!(
                previous == original,
                "native normalization merged different raw identities"
            );
        }
        ensure!(
            index.len() <= 16384,
            "raw identity inventory bound exceeded"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
