//! Generated scalar slots share SQL identity; live bindings remain atomic.
use super::*;
use crate::policy::native::GeneratedValue;

fn scalar(token: &Token) -> Result<Value> {
    match token {
        Token::Bytes(bytes) => Ok(Value::String(
            std::str::from_utf8(bytes)
                .context("generated SQL scalar must be UTF-8")?
                .into(),
        )),
        Token::Number(number) => crate::json_value::parse(number.as_bytes())
            .filter(Value::is_number)
            .context("generated SQL number is not exact JSON"),
        _ => anyhow::bail!("generated SQL parameter requires a non-null scalar"),
    }
}

pub(super) fn validate_shape(
    source: &Token,
    target: &Token,
    contract: &GeneratedValue,
) -> Result<()> {
    let source = scalar(source)?;
    let target = scalar(target)?;
    ensure!(
        std::mem::discriminant(&source) == std::mem::discriminant(&target),
        "generated SQL scalar type changed"
    );
    if source.is_number() {
        crate::value_contract::time::validate_numeric_category(&source, &target)
            .map_err(|_| anyhow::anyhow!("generated SQL numeric category changed"))?;
    }
    let projected = super::super::super::native_projection::generated(contract)?;
    if let Some(validator) = projected.validate {
        for value in [&source, &target] {
            super::super::super::value::validate_value(value, validator)
                .map_err(|_| anyhow::anyhow!("generated SQL scalar shape differs"))?;
        }
    }
    Ok(())
}
