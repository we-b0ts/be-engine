//! Pure signed-JWT comparison shared by response and dependency assertions.
use super::{Algorithm, Token};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Invalid,
    Algorithm,
    Signature,
    Claims,
    Time,
    Nonce,
}

pub(crate) struct Contract<'a> {
    pub algorithm: Algorithm,
    pub key: &'a [u8],
    pub anchors: [i128; 2],
    pub tolerance: i128,
    pub dynamic_claims: &'a [super::nonce::DynamicClaim],
}

pub(crate) struct Validated {
    pub nonces: Vec<Nonce>,
    pub time_validations: usize,
    pub exp: [i64; 2],
}

pub(crate) struct Nonce {
    pub claim: String,
    pub source: String,
    pub target: String,
}

fn parse(value: &Value) -> Result<Token, Failure> {
    let raw = value.as_str().ok_or(Failure::Invalid)?;
    let token = Token::parse(raw)
        .map_err(|_| Failure::Invalid)?
        .ok_or(Failure::Invalid)?;
    for part in raw.split('.').take(2) {
        let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| Failure::Invalid)?;
        crate::json_value::parse(&bytes).ok_or(Failure::Invalid)?;
    }
    Ok(token)
}

pub(crate) fn compare(
    source: &Value,
    target: &Value,
    contract: Contract<'_>,
) -> Result<Validated, Failure> {
    if !(0..=5_000_000_000).contains(&contract.tolerance) {
        return Err(Failure::Time);
    }
    let mut source = parse(source)?;
    let mut target = parse(target)?;
    if source.algorithm != contract.algorithm || target.algorithm != contract.algorithm {
        return Err(Failure::Algorithm);
    }
    if !source.verify(contract.key) || !target.verify(contract.key) {
        return Err(Failure::Signature);
    }
    if source.header_value().map_err(|_| Failure::Invalid)?
        != target.header_value().map_err(|_| Failure::Invalid)?
    {
        return Err(Failure::Claims);
    }
    let mut time_validations = 0;
    let exp = [source.integer_claim("exp"), target.integer_claim("exp")]
        .map(|value| value.ok().flatten());
    let [Some(source_exp), Some(target_exp)] = exp else {
        return Err(Failure::Time);
    };
    for name in ["exp", "iat", "nbf"] {
        let left = source.integer_claim(name).map_err(|_| Failure::Time)?;
        let right = target.integer_claim(name).map_err(|_| Failure::Time)?;
        if left.is_some() != right.is_some() || name == "exp" && left.is_none() {
            return Err(Failure::Time);
        }
        if let (Some(left), Some(right)) = (left, right) {
            time_validations += 1;
            let [a, b] = contract.anchors;
            let left = i128::from(left) * 1_000_000_000;
            let right = i128::from(right) * 1_000_000_000;
            let source_offset = left.checked_sub(a).ok_or(Failure::Time)?;
            let target_offset = right.checked_sub(b).ok_or(Failure::Time)?;
            let source_latest = a.checked_add(contract.tolerance).ok_or(Failure::Time)?;
            let target_latest = b.checked_add(contract.tolerance).ok_or(Failure::Time)?;
            if target_offset.abs_diff(source_offset) > contract.tolerance as u128
                || name == "exp" && (left <= a || right <= b)
                || name != "exp" && (left > source_latest || right > target_latest)
            {
                return Err(Failure::Time);
            }
            source.claims.as_object_mut().unwrap().remove(name);
            target.claims.as_object_mut().unwrap().remove(name);
        }
    }
    let mut nonces = Vec::new();
    for claim in contract.dynamic_claims {
        claim.validate().map_err(|_| Failure::Nonce)?;
        let pointer = claim.pointer();
        let left = source
            .claims
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(Failure::Nonce)?;
        let right = target
            .claims
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(Failure::Nonce)?;
        for value in [left, right] {
            if !claim.accepts(value) {
                return Err(Failure::Nonce);
            }
        }
        nonces.push(Nonce {
            claim: pointer.into(),
            source: left.into(),
            target: right.into(),
        });
        source.claims.as_object_mut().unwrap().remove(&pointer[1..]);
        target.claims.as_object_mut().unwrap().remove(&pointer[1..]);
    }
    if source.claims != target.claims {
        return Err(Failure::Claims);
    }
    Ok(Validated {
        nonces,
        time_validations,
        exp: [source_exp, target_exp],
    })
}
