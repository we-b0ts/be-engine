//! Native SQL scalar conversion and MySQL binary value encoding.
use crate::model::{
    MysqlColumn as RecordedMysqlColumn, MysqlValue as RecordedMysqlValue,
    ValueCapture as ReplayBodyCapture,
};
use crate::types::*;
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

pub fn string_column(name: &str) -> RecordedMysqlColumn {
    RecordedMysqlColumn {
        database: None,
        name: name.to_string(),
        table: None,
        table_alias: None,
        column: None,
        family: "string".to_string(),
        sql_type: "VARCHAR".to_string(),
        unsigned: None,
        bits: None,
        nullable: Some(true),
        scale: None,
    }
}

pub fn integer_column(name: &str) -> RecordedMysqlColumn {
    RecordedMysqlColumn {
        database: None,
        name: name.to_string(),
        table: None,
        table_alias: None,
        column: None,
        family: "integer".to_string(),
        sql_type: "INT".to_string(),
        unsigned: Some(false),
        bits: Some(32),
        nullable: Some(true),
        scale: None,
    }
}

pub fn params_match(
    recorded: Option<&[RecordedMysqlValue]>,
    actual: Option<&[RecordedMysqlValue]>,
) -> bool {
    match (recorded, actual) {
        (None, None) => true,
        (Some(recorded), Some(actual)) if recorded.len() == actual.len() => recorded
            .iter()
            .zip(actual)
            .all(|(left, right)| left == right),
        _ => false,
    }
}

pub fn normalize_sql(sql: &str) -> String {
    crate::sql::normalize(sql)
}
pub fn count_sql_placeholders(sql: &str) -> usize {
    crate::sql::tokens(sql).map_or(0, |tokens| {
        tokens
            .iter()
            .filter(|t| **t == crate::sql::Token::Placeholder)
            .count()
    })
}

pub fn looks_like_select(sql: &str) -> bool {
    normalize_sql(sql).starts_with("select")
}

pub fn column_type_code(column: &RecordedMysqlColumn) -> u8 {
    let sql_type = column.sql_type.to_ascii_uppercase();
    match sql_type.as_str() {
        "TINYINT" => MYSQL_TYPE_TINY,
        "SMALLINT" => MYSQL_TYPE_SHORT,
        "MEDIUMINT" => MYSQL_TYPE_INT24,
        "INT" | "INTEGER" => MYSQL_TYPE_LONG,
        "BIGINT" => MYSQL_TYPE_LONGLONG,
        "YEAR" => MYSQL_TYPE_YEAR,
        "FLOAT" => MYSQL_TYPE_FLOAT,
        "DOUBLE" => MYSQL_TYPE_DOUBLE,
        "DECIMAL" | "NUMERIC" => MYSQL_TYPE_NEWDECIMAL,
        "DATE" => MYSQL_TYPE_DATE,
        "TIME" => MYSQL_TYPE_TIME,
        "DATETIME" => MYSQL_TYPE_DATETIME,
        "TIMESTAMP" => MYSQL_TYPE_TIMESTAMP,
        "JSON" => MYSQL_TYPE_JSON,
        "BIT" => MYSQL_TYPE_BIT,
        "NULL" => MYSQL_TYPE_NULL,
        "GEOMETRY" => MYSQL_TYPE_GEOMETRY,
        "BINARY" => MYSQL_TYPE_STRING,
        "VARBINARY" => MYSQL_TYPE_VAR_STRING,
        _ => match column.family.as_str() {
            "integer" => {
                if column.bits == Some(64) {
                    MYSQL_TYPE_LONGLONG
                } else {
                    MYSQL_TYPE_LONG
                }
            }
            "decimal" => MYSQL_TYPE_NEWDECIMAL,
            "float" => MYSQL_TYPE_DOUBLE,
            "date" => MYSQL_TYPE_DATE,
            "time" => MYSQL_TYPE_TIME,
            "datetime" => MYSQL_TYPE_DATETIME,
            "binary" | "string" | "json" => MYSQL_TYPE_VAR_STRING,
            "null" => MYSQL_TYPE_NULL,
            _ => MYSQL_TYPE_VAR_STRING,
        },
    }
}

pub fn column_length(column: &RecordedMysqlColumn) -> u32 {
    match column_type_code(column) {
        MYSQL_TYPE_TINY => 4,
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => 6,
        MYSQL_TYPE_INT24 | MYSQL_TYPE_LONG => 11,
        MYSQL_TYPE_LONGLONG => 20,
        MYSQL_TYPE_FLOAT => 12,
        MYSQL_TYPE_DOUBLE => 22,
        MYSQL_TYPE_DATE => 10,
        MYSQL_TYPE_TIME => 16,
        MYSQL_TYPE_DATETIME | MYSQL_TYPE_TIMESTAMP => 26,
        _ => 1024,
    }
}

pub fn mysql_value_bytes(value: &RecordedMysqlValue) -> Result<Vec<u8>> {
    if let Some(raw) = &value.raw {
        return match raw.encoding.as_str() {
            "base64" => STANDARD
                .decode(&raw.data)
                .context("failed to decode recorded MySQL raw base64 value"),
            "utf8" => Ok(raw.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported recorded raw value encoding {other}")),
        };
    }
    let Some(value) = &value.value else {
        return Ok(Vec::new());
    };
    Ok(match value {
        Value::String(value) => value.as_bytes().to_vec(),
        Value::Number(value) => value.to_string().into_bytes(),
        Value::Bool(value) => {
            if *value {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        other => {
            serde_json::to_vec(other).context("failed to serialize recorded MySQL JSON value")?
        }
    })
}

pub fn value_as_i64(value: &RecordedMysqlValue) -> Result<i64> {
    if let Some(Value::Number(number)) = &value.value {
        if let Some(value) = number.as_i64() {
            return Ok(value);
        }
        if let Some(value) = number.as_u64() {
            return i64::try_from(value).context("recorded unsigned integer does not fit i64");
        }
    }
    let text = value_as_str(value)?;
    text.parse::<i64>()
        .with_context(|| format!("recorded value `{text}` is not an integer"))
}

pub fn value_as_f64(value: &RecordedMysqlValue) -> Result<f64> {
    if let Some(Value::Number(number)) = &value.value
        && let Some(value) = number.as_f64()
    {
        return Ok(value);
    }
    let text = value_as_str(value)?;
    text.parse::<f64>()
        .with_context(|| format!("recorded value `{text}` is not a float"))
}

pub fn value_as_str(value: &RecordedMysqlValue) -> Result<&str> {
    if let Some(Value::String(value)) = &value.value {
        return Ok(value);
    }
    Err(anyhow!("recorded value is not a string"))
}

fn fractional_micros(fraction: &str) -> Result<u32> {
    if fraction.is_empty() || fraction.len() > 6 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("invalid recorded MySQL fractional seconds"));
    }
    Ok(fraction.parse::<u32>()? * 10_u32.pow(6 - fraction.len() as u32))
}

pub fn binary_datetime_bytes(value: &str) -> Result<Vec<u8>> {
    let (date, time) = value.split_once(' ').unwrap_or((value, "00:00:00"));
    let mut date_parts = date.split('-');
    let year = date_parts
        .next()
        .unwrap_or("0")
        .parse::<u16>()
        .context("invalid recorded datetime year")?;
    let month = date_parts
        .next()
        .unwrap_or("0")
        .parse::<u8>()
        .context("invalid recorded datetime month")?;
    let day = date_parts
        .next()
        .unwrap_or("0")
        .parse::<u8>()
        .context("invalid recorded datetime day")?;
    let (hms, micros) = time.split_once('.').unwrap_or((time, "0"));
    let mut time_parts = hms.split(':');
    let hour = time_parts.next().unwrap_or("0").parse::<u8>()?;
    let minute = time_parts.next().unwrap_or("0").parse::<u8>()?;
    let second = time_parts.next().unwrap_or("0").parse::<u8>()?;
    let micros = fractional_micros(micros)?;
    let mut out = Vec::new();
    if micros > 0 {
        out.push(11);
    } else if hour > 0 || minute > 0 || second > 0 {
        out.push(7);
    } else {
        out.push(4);
    }
    out.extend_from_slice(&year.to_le_bytes());
    out.push(month);
    out.push(day);
    if out[0] >= 7 {
        out.push(hour);
        out.push(minute);
        out.push(second);
    }
    if out[0] == 11 {
        out.extend_from_slice(&micros.to_le_bytes());
    }
    Ok(out)
}

pub fn binary_time_bytes(value: &str) -> Result<Vec<u8>> {
    let negative = value.starts_with('-');
    let value = value.trim_start_matches('-');
    let (hms, micros) = value.split_once('.').unwrap_or((value, "0"));
    let mut parts = hms.split(':');
    let total_hours = parts.next().unwrap_or("0").parse::<u32>()?;
    let minute = parts.next().unwrap_or("0").parse::<u8>()?;
    let second = parts.next().unwrap_or("0").parse::<u8>()?;
    let days = total_hours / 24;
    let hour = (total_hours % 24) as u8;
    let micros = fractional_micros(micros)?;
    let mut out = Vec::new();
    if micros > 0 {
        out.push(12);
    } else {
        out.push(8);
    }
    out.push(u8::from(negative));
    out.extend_from_slice(&days.to_le_bytes());
    out.push(hour);
    out.push(minute);
    out.push(second);
    if micros > 0 {
        out.extend_from_slice(&micros.to_le_bytes());
    }
    Ok(out)
}

pub fn parse_binary_datetime(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *payload.get(offset)? as usize;
    let start = offset + 1;
    match len {
        0 => Some(("0000-00-00 00:00:00".to_string(), start)),
        4 => {
            let year = read_u16_le(payload, start)?;
            let month = *payload.get(start + 2)?;
            let day = *payload.get(start + 3)?;
            Some((format!("{year:04}-{month:02}-{day:02}"), start + 4))
        }
        7 | 11 => {
            let year = read_u16_le(payload, start)?;
            let month = *payload.get(start + 2)?;
            let day = *payload.get(start + 3)?;
            let hour = *payload.get(start + 4)?;
            let minute = *payload.get(start + 5)?;
            let second = *payload.get(start + 6)?;
            if len == 11 {
                let micros = read_u32_le(payload, start + 7)?;
                Some((
                    format!(
                        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
                    ),
                    start + 11,
                ))
            } else {
                Some((
                    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"),
                    start + 7,
                ))
            }
        }
        _ => None,
    }
}

pub fn parse_binary_time(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *payload.get(offset)? as usize;
    let start = offset + 1;
    match len {
        0 => Some(("00:00:00".to_string(), start)),
        8 | 12 => {
            let negative = *payload.get(start)? != 0;
            let days = read_u32_le(payload, start + 1)?;
            let hour = *payload.get(start + 5)? as u32 + days * 24;
            let minute = *payload.get(start + 6)?;
            let second = *payload.get(start + 7)?;
            let sign = if negative { "-" } else { "" };
            if len == 12 {
                let micros = read_u32_le(payload, start + 8)?;
                Some((
                    format!("{sign}{hour:02}:{minute:02}:{second:02}.{micros:06}"),
                    start + 12,
                ))
            } else {
                Some((
                    format!("{sign}{hour:02}:{minute:02}:{second:02}"),
                    start + 8,
                ))
            }
        }
        _ => None,
    }
}

pub fn read_lenenc_bytes(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let (len, offset) = read_lenenc_int(bytes, offset)?;
    let len = len as usize;
    Some((bytes.get(offset..offset + len)?, offset + len))
}

pub fn read_lenenc_int(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    match first {
        0xfc => Some((read_u16_le(bytes, offset + 1)? as u64, offset + 3)),
        0xfd => {
            let b1 = *bytes.get(offset + 1)? as u64;
            let b2 = *bytes.get(offset + 2)? as u64;
            let b3 = *bytes.get(offset + 3)? as u64;
            Some((b1 | (b2 << 8) | (b3 << 16), offset + 4))
        }
        0xfe => Some((read_u64_le(bytes, offset + 1)?, offset + 9)),
        0xfb => None,
        value => Some((value as u64, offset + 1)),
    }
}

pub fn lenenc_int(value: u64) -> Vec<u8> {
    match value {
        0..=250 => vec![value as u8],
        251..=0xffff => {
            let mut out = vec![0xfc];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xff_ffff => {
            vec![
                0xfd,
                (value & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                ((value >> 16) & 0xff) as u8,
            ]
        }
        _ => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&value.to_le_bytes());
            out
        }
    }
}

pub fn lenenc_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = lenenc_int(value.len() as u64);
    out.extend_from_slice(value);
    out
}

pub fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

pub fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

pub fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

pub fn null_bitmap_bit(bitmap: &[u8], index: usize) -> bool {
    let byte_index = index / 8;
    let bit = index % 8;
    bitmap
        .get(byte_index)
        .is_some_and(|byte| byte & (1 << bit) != 0)
}

pub fn set_null_bitmap_bit(bitmap: &mut [u8], bit_index: usize) {
    let byte_index = bit_index / 8;
    let bit = bit_index % 8;
    if let Some(byte) = bitmap.get_mut(byte_index) {
        *byte |= 1 << bit;
    }
}

pub fn mysql_null() -> RecordedMysqlValue {
    RecordedMysqlValue {
        kind: "null".to_string(),
        value: None,
        raw: None,
    }
}

pub fn mysql_json(kind: &str, value: Value) -> RecordedMysqlValue {
    RecordedMysqlValue {
        kind: kind.to_string(),
        value: Some(value),
        raw: None,
    }
}

pub fn mysql_bytes_or_utf8(bytes: &[u8], force_bytes: bool) -> RecordedMysqlValue {
    if !force_bytes && let Ok(value) = std::str::from_utf8(bytes) {
        return mysql_json("string", Value::String(value.to_string()));
    }
    RecordedMysqlValue {
        kind: "bytes".to_string(),
        value: None,
        raw: Some(ReplayBodyCapture {
            truncated: false,
            encoding: "base64".to_string(),
            data: STANDARD.encode(bytes),
        }),
    }
}
