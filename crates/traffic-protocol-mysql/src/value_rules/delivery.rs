//! Materialize selected native and JSON values without changing immutable Source.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub fn write_value(
    original: &RecordedMysqlValue,
    logical: Value,
    scalar: bool,
) -> Result<RecordedMysqlValue> {
    let mut output = original.clone();
    if scalar {
        if output.raw.is_some() {
            output.raw = Some(crate::model::ValueCapture {
                truncated: false,
                encoding: "utf8".into(),
                data: logical
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| logical.to_string()),
            });
        }
        output.value = Some(logical);
    } else {
        let original_bytes = fields::encoded_bytes(original)?
            .context("MySQL JSON delivery lost its original bytes")?;
        let bytes = traffic_contract::json::render::derived(&original_bytes, &logical)?;
        if output.raw.is_some() {
            output.raw = Some(crate::model::ValueCapture {
                truncated: false,
                encoding: "base64".into(),
                data: STANDARD.encode(bytes),
            });
            output.value = None;
        } else {
            output.value = Some(Value::String(String::from_utf8(bytes)?));
        }
    }
    Ok(output)
}

pub fn translate_selection(
    owner: &dyn DeliveryHost,
    case: &str,
    selected: &Selection,
    clocks: AnchorClocks,
) -> Result<(Value, Option<traffic_contract::identity::IdentityDecision>)> {
    let mut logical = selected.source.clone();
    let mut pending: Option<traffic_contract::identity::IdentityDecision> = None;
    if selected.date
        && clocks
            .dependency
            .source
            .zip(clocks.dependency.target)
            .is_some_and(|(source, _)| {
                selected.source.as_str().is_some_and(|value| {
                    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                        .is_ok_and(|date| date == source.date_naive())
                })
            })
    {
        let source = chrono::NaiveDate::parse_from_str(
            logical.as_str().context("SQL DATE requires text")?,
            "%Y-%m-%d",
        )?;
        let (a, b) = clocks.dependency.require()?;
        let days = (traffic_contract::time::date_nanos(b) - traffic_contract::time::date_nanos(a))
            .div_euclid(86_400_000_000_000);
        logical = source
            .checked_add_signed(
                chrono::TimeDelta::try_days(i64::try_from(days)?)
                    .context("SQL DATE delta overflow")?,
            )
            .context("SQL DATE overflow")?
            .format("%Y-%m-%d")
            .to_string()
            .into();
    }
    let authored;
    let fields = if selected.id == GLOBAL_JSON_ID {
        authored = owner
            .format_host()
            .map(|plan| {
                plan.field_plan()
                    .delivery_fields_with_clocks(&selected.source, clocks)
            })
            .transpose()?
            .unwrap_or_default();
        &authored
    } else {
        &selected.fields
    };
    for (pointer, contract) in fields {
        if let Some(time) = contract.time() {
            let original = selected
                .source
                .pointer(pointer)
                .context("selected SQL time disappeared")?;
            if selected.inferred && !fresh_native_time(original, &time, clocks) {
                continue;
            }
            let (a, b) = clocks.dependency.require()?;
            let mut delta =
                traffic_contract::time::date_nanos(b) - traffic_contract::time::date_nanos(a);
            if selected.id == MYSQL_ID
                && time.format == traffic_contract::rule::TimestampFormat::SqlDatetime
            {
                let digits = original
                    .as_str()
                    .and_then(|text| text.split_once('.'))
                    .map_or(0, |(_, fraction)| fraction.len().min(9));
                let quantum = 10_i128.pow(9 - u32::try_from(digits)?);
                delta = delta / quantum * quantum;
            }
            let changed = if time.format == traffic_contract::rule::TimestampFormat::CalendarDate {
                traffic_contract::time::calendar::rebase(
                    original,
                    time.offset()?.context("calendar date requires offset")?,
                    clocks.dependency,
                )?
            } else {
                traffic_contract::delivery::shift(original, &time, delta)?
            };
            *logical
                .pointer_mut(pointer)
                .context("SQL delivery time disappeared")? = changed;
        }
    }
    if selected.id == GLOBAL_JSON_ID {
        let decision = owner.translate_document_identity(case, &selected.source, &mut logical)?;
        pending = Some(decision);
        return Ok((logical, pending));
    }
    for (pointer, contract) in &selected.fields {
        if let FieldContract::Identity { prefix, format } = contract {
            let entry = traffic_contract::identity::IdentityDelivery {
                prefix,
                format: *format,
                value: selected
                    .source
                    .pointer(pointer)
                    .context("SQL identity disappeared")?,
            };
            let (mut translated, decision) = owner.identity_deliveries(case, &[entry])?;
            *logical
                .pointer_mut(pointer)
                .context("SQL delivery identity disappeared")? = translated.remove(0);
            if let Some(previous) = &mut pending {
                previous.merge(decision)?;
            } else {
                pending = Some(decision);
            }
        } else if matches!(contract, FieldContract::IdentityAnchor) {
            let encoded = serde_json::to_string(
                selected
                    .source
                    .pointer(pointer)
                    .context("SQL identity anchor disappeared")?,
            )?;
            let decision = owner.preview_identity_pairs(
                case,
                &[traffic_contract::identity::IdentityPair {
                    source: encoded.clone(),
                    target: encoded,
                }],
                true,
            )?;
            if let Some(previous) = &mut pending {
                previous.merge(decision)?;
            } else {
                pending = Some(decision);
            }
        }
    }
    Ok((logical, pending))
}

fn fresh_native_time(
    value: &Value,
    time: &traffic_contract::rule::TimeContract,
    clocks: AnchorClocks,
) -> bool {
    let Some((source, _)) = clocks.dependency.source.zip(clocks.dependency.target) else {
        return false;
    };
    if time.format == traffic_contract::rule::TimestampFormat::CalendarDate {
        return time.offset().ok().flatten().is_some_and(|offset| {
            traffic_contract::time::calendar::compare(
                value,
                value,
                offset,
                traffic_contract::time::TimeMode::RequestWindow,
                traffic_contract::time::ClockPair {
                    source: Some(source),
                    target: Some(source),
                },
            )
            .is_ok()
        });
    }
    traffic_contract::compare::parse_time_pair(value, value, time).is_ok_and(|(value, _)| {
        traffic_contract::time::validate_request_window(value, source).is_ok()
    })
}
