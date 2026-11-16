//! URL carriers preserve every byte outside the token and proven nonce echoes.
use super::*;

pub struct Extracted {
    pub tokens: [Value; 2],
    pub echoes: BTreeMap<String, [String; 2]>,
}

pub fn extract(
    rule: &ResponseJwtRule,
    source: &Value,
    target: &Value,
) -> Result<Option<Extracted>, ResponseDifferenceKind> {
    let Some(parameter) = &rule.url_query_param else {
        return Ok(None);
    };
    let select = |value: &Value| {
        let raw = value.as_str().ok_or(ResponseDifferenceKind::JwtInvalid)?;
        let mut ranges = Vec::new();
        let mut echoes = BTreeMap::new();
        let mut token = String::new();
        for (name, claim) in std::iter::once((parameter, None)).chain(
            rule.nonce_query_params
                .iter()
                .map(|(claim, name)| (name, Some(claim))),
        ) {
            let selected = traffic_protocol_http::query_token::select(raw, name)
                .map_err(|_| ResponseDifferenceKind::JwtInvalid)?;
            ranges.push((selected.prefix.len(), raw.len() - selected.suffix.len()));
            if let Some(claim) = claim {
                echoes.insert(claim.clone(), selected.token);
            } else {
                token = selected.token;
            }
        }
        ranges.sort_unstable();
        let mut remaining = Vec::new();
        let mut start = 0;
        for (from, to) in ranges {
            if from < start {
                return Err(ResponseDifferenceKind::JwtInvalid);
            }
            remaining.push(raw[start..from].to_owned());
            start = to;
        }
        remaining.push(raw[start..].to_owned());
        Ok((Value::String(token), echoes, remaining))
    };
    let (source, left, source_remainder) = select(source)?;
    let (target, right, target_remainder) = select(target)?;
    if source_remainder != target_remainder {
        return Err(ResponseDifferenceKind::JwtUrlMismatch);
    }
    let echoes = left
        .into_iter()
        .map(|(claim, value)| {
            let actual = right
                .get(&claim)
                .ok_or(ResponseDifferenceKind::JwtNonceMismatch)?
                .clone();
            Ok((claim, [value, actual]))
        })
        .collect::<Result<_, _>>()?;
    Ok(Some(Extracted {
        tokens: [source, target],
        echoes,
    }))
}
