//! A refresh declaration selects timestamp leaves, never general JSON mutations.
use super::*;

pub(super) fn validate(rule: &NativeRule, effect: &RedisActivityRefreshEffect) -> Result<()> {
    if rule.selector.resource.is_some() {
        let selected = resource(&rule.selector, Protocol::Redis)?;
        ensure!(
            selected
                .database
                .as_ref()
                .and_then(super::super::Database::index)
                .is_some(),
            "activity refresh requires a numeric Redis database"
        );
    } else {
        validate_discovered_redis_key(&rule.selector)?;
    }
    ensure!(
        rule.selector.key.is_some() && rule.selector.operation.is_none(),
        "activity refresh owns its bounded key GET/SET lifecycle, without an operation selector"
    );
    ensure!(
        !effect.fields.is_empty() && effect.fields.len() <= 16,
        "activity refresh requires 1..16 explicit JSON timestamp fields"
    );
    let mut seen = BTreeSet::new();
    for pointer in &effect.fields {
        compiler::validate_pointer(pointer, false)?;
        ensure!(
            !pointer.is_empty() && seen.insert(pointer),
            "activity refresh fields must be unique non-root JSON pointers"
        );
        ensure!(
            !effect.fields.iter().any(|other| other != pointer
                && pointer
                    .strip_prefix(other)
                    .is_some_and(|suffix| suffix.starts_with('/'))),
            "activity refresh fields cannot overlap"
        );
    }
    Ok(())
}
