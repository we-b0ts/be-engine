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
    pub iat: [Option<i64>; 2],
}

pub(crate) struct Nonce {
    pub claim: String,
    pub source: String,
    pub target: String,
}

/// API response profiles prove fresh issuance. A carrier-independent format
/// may also describe historical or not-yet-valid tokens stored as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NumericDateMode {
    Issued,
    Format,
}

pub(crate) struct NumericDates {
    pub(crate) time_validations: usize,
    exp: [Option<i64>; 2],
    iat: [Option<i64>; 2],
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
    if !(0..=crate::value_contract::time::DEFAULT_TOLERANCE.as_nanos() as i128)
        .contains(&contract.tolerance)
    {
        return Err(Failure::Time);
    }
    let source = parse(source)?;
    let target = parse(target)?;
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
    compare_authenticated_claims(
        source.claims,
        target.claims,
        contract.anchors,
        contract.tolerance,
        contract.dynamic_claims,
    )
}

/// Call only after authenticating both signatures and comparing their headers.
pub(crate) fn compare_authenticated_claims(
    mut source: Value,
    mut target: Value,
    anchors: [i128; 2],
    tolerance: i128,
    dynamic_claims: &[super::nonce::DynamicClaim],
) -> Result<Validated, Failure> {
    let dates = compare_numeric_dates(
        &mut source,
        &mut target,
        Some(anchors),
        tolerance,
        NumericDateMode::Issued,
    )?;
    let [Some(source_exp), Some(target_exp)] = dates.exp else {
        return Err(Failure::Time);
    };
    let mut nonces = Vec::new();
    for claim in dynamic_claims {
        claim.validate().map_err(|_| Failure::Nonce)?;
        let pointer = claim.pointer();
        let left = source
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(Failure::Nonce)?;
        let right = target
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
        source
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .remove(&pointer[1..]);
        target
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .remove(&pointer[1..]);
    }
    if source != target {
        return Err(Failure::Claims);
    }
    Ok(Validated {
        nonces,
        time_validations: dates.time_validations,
        exp: [source_exp, target_exp],
        iat: dates.iat,
    })
}

/// Only authenticated, header-checked claims may enter this projection. Removes
/// the built-in time leaves after validation so the caller can compare all other
/// claims with its own strictly bounded content strategy.
pub(crate) fn compare_numeric_dates(
    source: &mut Value,
    target: &mut Value,
    anchors: Option<[i128; 2]>,
    tolerance: i128,
    mode: NumericDateMode,
) -> Result<NumericDates, Failure> {
    if !(0..=crate::value_contract::time::DEFAULT_TOLERANCE.as_nanos() as i128).contains(&tolerance)
    {
        return Err(Failure::Time);
    }
    let integer = |value: &Value, name: &str| -> Result<Option<i64>, Failure> {
        value
            .get(name)
            .map(|v| v.as_i64().ok_or(Failure::Time))
            .transpose()
    };
    let iat = [integer(source, "iat")?, integer(target, "iat")?];
    let mut time_validations = 0;
    let exp = [integer(source, "exp")?, integer(target, "exp")?];
    for name in ["exp", "iat", "nbf"] {
        let left = integer(source, name)?;
        let right = integer(target, name)?;
        if left.is_some() != right.is_some()
            || mode == NumericDateMode::Issued && name == "exp" && left.is_none()
        {
            return Err(Failure::Time);
        }
        if let (Some(left), Some(right)) = (left, right) {
            time_validations += 1;
            if mode == NumericDateMode::Format && left == right {
                source.as_object_mut().ok_or(Failure::Invalid)?.remove(name);
                target.as_object_mut().ok_or(Failure::Invalid)?.remove(name);
                continue;
            }
            let [a, b] = anchors.ok_or(Failure::Time)?;
            let left = i128::from(left) * 1_000_000_000;
            let right = i128::from(right) * 1_000_000_000;
            let source_offset = left.checked_sub(a).ok_or(Failure::Time)?;
            let target_offset = right.checked_sub(b).ok_or(Failure::Time)?;
            let source_latest = a.checked_add(tolerance).ok_or(Failure::Time)?;
            let target_latest = b.checked_add(tolerance).ok_or(Failure::Time)?;
            if target_offset.abs_diff(source_offset) > tolerance as u128
                || mode == NumericDateMode::Issued
                    && (name == "exp" && (left <= a || right <= b)
                        || name != "exp" && (left > source_latest || right > target_latest))
            {
                return Err(Failure::Time);
            }
            source.as_object_mut().ok_or(Failure::Invalid)?.remove(name);
            target.as_object_mut().ok_or(Failure::Invalid)?.remove(name);
        }
    }
    Ok(NumericDates {
        time_validations,
        exp,
        iat,
    })
}
