//! Select a materialized SQL cell only after the parent authenticates its witness.
use super::*;

pub(super) fn is_selector(pointer: &str, surface: Surface) -> bool {
    prefix(surface).is_some_and(|prefix| pointer.starts_with(prefix))
}

fn prefix(surface: Surface) -> Option<&'static str> {
    match surface {
        Surface::DependencyRequest => Some("/sql_values/"),
        Surface::DependencyResponse => Some("/request/sql_values/"),
        _ => None,
    }
}

pub(super) fn observation(
    raw: Option<&[u8]>,
    pointer: &str,
    surface: Surface,
    database: Option<&str>,
) -> Value {
    let Some(raw) = raw else {
        return json!({"presence":"unavailable","reason":"selected document is unavailable"});
    };
    let Some((index, tail)) = prefix(surface)
        .and_then(|prefix| pointer.strip_prefix(prefix))
        .and_then(|selection| selection.split_once('/'))
    else {
        return json!({"presence":"unavailable","reason":"SQL selection requires /sql_values/<token-index>/<cell-pointer>; response requests use /request/sql_values/..."});
    };
    let Ok(index) = index.parse::<usize>() else {
        return json!({"presence":"unavailable","reason":"SQL token index must be a nonnegative integer"});
    };
    match crate::replay::mysql_witness_sql_value(raw, surface, database, index) {
        Ok(Some(value)) => super::selected_observation(value.pointer(&format!("/{tail}"))),
        Ok(None) => json!({"presence":"missing",
            "reason":"no scalar value at this lexical SQL token index; this is not a bound-parameter ordinal. Use physical_fields.fields[].observed_positions; /sql_values is a virtual single-cell selector, not an enumerable JSON collection"}),
        // Native bytes remain readable through their ordinary pointers. A
        // failed projection must never be reported as an absent Source value.
        Err(error) => json!({"presence":"unavailable","reason":error.to_string()}),
    }
}
