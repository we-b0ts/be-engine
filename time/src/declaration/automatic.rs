//! Recognize standard textual timestamp grammar from the Source value alone.
use super::*;

pub fn recognize_timestamp(source: &Value, default_utc_offset: &str) -> Option<TimeContract> {
    let format = timestamp_format(source.as_str()?)?;
    let utc_offset = matches!(
        format,
        TimestampFormat::Iso8601Naive
            | TimestampFormat::SqlDatetime
            | TimestampFormat::CalendarDate
    )
    .then(|| default_utc_offset.to_owned());
    let contract = TimeContract {
        format,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::Observation,
        utc_offset,
        clock_group: None,
        clock_scope: ClockScope::default(),
    };
    parse_time_value(source, &contract).ok()?;
    Some(contract)
}

pub fn timestamp_format(text: &str) -> Option<TimestampFormat> {
    let bytes = text.as_bytes();
    if !(10..=35).contains(&bytes.len())
        || !bytes[..10]
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                4 | 7 => *byte == b'-',
                _ => byte.is_ascii_digit(),
            })
    {
        return None;
    }
    if bytes.len() == 10 {
        return Some(TimestampFormat::CalendarDate);
    }
    if bytes.len() < 19
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || !bytes[11..19]
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                2 | 5 => *byte == b':',
                _ => byte.is_ascii_digit(),
            })
    {
        return None;
    }
    let zoned = bytes.last().is_some_and(|byte| matches!(byte, b'Z' | b'z'))
        || bytes.len() >= 25
            && matches!(bytes[bytes.len() - 6], b'+' | b'-')
            && bytes[bytes.len() - 3] == b':';
    if zoned {
        if !matches!(bytes[10], b'T' | b't') {
            return None;
        }
        let end = bytes.len()
            - if matches!(bytes[bytes.len() - 1], b'Z' | b'z') {
                1
            } else {
                6
            };
        fraction(&bytes[19..end]).then_some(TimestampFormat::Rfc3339)
    } else if fraction(&bytes[19..]) {
        match bytes[10] {
            b'T' => Some(TimestampFormat::Iso8601Naive),
            b' ' => Some(TimestampFormat::SqlDatetime),
            _ => None,
        }
    } else {
        None
    }
}

fn fraction(bytes: &[u8]) -> bool {
    bytes.is_empty()
        || (2..=10).contains(&bytes.len())
            && bytes[0] == b'.'
            && bytes[1..].iter().all(u8::is_ascii_digit)
}
