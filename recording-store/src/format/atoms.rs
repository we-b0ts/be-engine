//! Escaped scalar cells and uncommon, named metadata.
use std::io::Write;

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};
use traffic_model::recording::identity::IdentityKind;
use traffic_protocol::capture::RecordingScalar;

use crate::dependency_columns::{ReadTerms, WriteTerms};

pub(super) fn text(out: &mut Vec<u8>, value: &str) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    if value.is_empty() {
        out.push(b'%');
        return;
    }
    for &byte in value.as_bytes() {
        if byte.is_ascii_whitespace()
            || byte.is_ascii_control()
            || matches!(byte, b'%' | b'[' | b']' | b'=')
            || (value.len() == 1 && matches!(byte, b'-' | b'~' | b'!'))
        {
            out.extend_from_slice(&[b'%', HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
        } else {
            out.push(byte);
        }
    }
}

pub(super) fn untext(value: &str) -> Result<String> {
    if value == "%" {
        return Ok(String::new());
    }
    if !value.contains('%') {
        return Ok(value.to_owned());
    }
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.as_bytes().iter().copied();
    let hex = |byte: Option<u8>| {
        byte.and_then(|byte| (byte as char).to_digit(16))
            .map(|digit| digit as u8)
            .context("invalid dependency escape")
    };
    while let Some(byte) = input.next() {
        bytes.push(if byte == b'%' {
            (hex(input.next())? << 4) | hex(input.next())?
        } else {
            byte
        });
    }
    Ok(String::from_utf8(bytes)?)
}

pub(super) fn scalar(
    out: &mut Vec<u8>,
    value: Option<&Value>,
    kind: RecordingScalar,
) -> Result<()> {
    match value {
        None => out.push(b'-'),
        Some(Value::Null) => out.push(b'~'),
        Some(Value::String(value)) if kind == RecordingScalar::Text => text(out, value),
        Some(Value::Number(value))
            if kind == RecordingScalar::Integer && (value.is_u64() || value.is_i64()) =>
        {
            write!(out, "{value}")?;
        }
        Some(Value::Bool(value)) if kind == RecordingScalar::Boolean => {
            out.push(if *value { b'1' } else { b'0' });
        }
        Some(_) => anyhow::bail!("dependency value does not match its declared scalar type"),
    }
    Ok(())
}

pub(super) fn read_scalar(value: &str, kind: RecordingScalar) -> Result<Option<Value>> {
    Ok(match (value, kind) {
        ("-", _) => None,
        ("~", _) => Some(Value::Null),
        (_, RecordingScalar::Text) => Some(Value::String(untext(value)?)),
        (_, RecordingScalar::Integer) => {
            let number: serde_json::Number = value.parse()?;
            ensure!(
                number.is_u64() || number.is_i64(),
                "invalid dependency integer"
            );
            Some(Value::Number(number))
        }
        ("1", RecordingScalar::Boolean) => Some(Value::Bool(true)),
        ("0", RecordingScalar::Boolean) => Some(Value::Bool(false)),
        _ => anyhow::bail!("invalid dependency boolean"),
    })
}

pub(super) fn named(
    out: &mut Vec<u8>,
    prefix: &str,
    map: &Map<String, Value>,
    terms: &mut WriteTerms,
) -> Result<()> {
    for (key, value) in map {
        out.push(b' ');
        out.extend_from_slice(prefix.as_bytes());
        text(out, key);
        out.push(b'=');
        if let Some(delta) = terms.relative(key, value) {
            write!(out, "t{delta}")?;
            continue;
        }
        match value {
            Value::Null => out.push(b'~'),
            Value::Bool(value) => out.push(if *value { b'+' } else { b'-' }),
            Value::String(value) if matches!(key.as_str(), "observed_case" | "admitted_case") => {
                out.push(b's');
                let value = value.parse().map_or_else(
                    |_| value.clone(),
                    |id| IdentityKind::Case.display(terms.recording_id(), id),
                );
                text(out, &value);
            }
            Value::String(value) => {
                out.push(b's');
                text(out, value);
            }
            Value::Number(value) => write!(out, "n{value}")?,
            _ => {
                let bytes = serde_json::to_vec(value)?;
                if let Some(id) = terms.intern(&bytes) {
                    write!(out, "@{id}")?;
                } else {
                    out.push(b'j');
                    text(out, std::str::from_utf8(&bytes)?);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn read_named(value: &str, terms: &ReadTerms) -> Result<Value> {
    Ok(match value {
        "~" => Value::Null,
        "+" => Value::Bool(true),
        "-" => Value::Bool(false),
        _ => {
            let (tag, data) = value.split_at_checked(1).context("missing metadata type")?;
            match tag {
                "s" => Value::String(untext(data)?),
                "n" => Value::Number(data.parse()?),
                "t" => terms.clock(data.parse()?)?,
                "@" => terms.term(data.parse()?)?,
                "j" => serde_json::from_str(&untext(data)?)?,
                _ => anyhow::bail!("invalid dependency metadata type"),
            }
        }
    })
}
