//! Explicit scalar types prevent wire-type guesses and lossy integer coercion.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

use super::{length_delimited, wire};
use crate::policy::ProtobufType as Type;

pub(super) fn packable(kind: Type) -> bool {
    !matches!(kind, Type::String | Type::Bytes | Type::Message)
}

fn wire_type(kind: Type) -> Result<u8> {
    Ok(match kind {
        Type::String | Type::Bytes => 2,
        Type::Fixed32 | Type::Sfixed32 | Type::Float => 5,
        Type::Fixed64 | Type::Sfixed64 | Type::Double => 1,
        Type::Message => bail!("message fields require a typed message projection"),
        _ => 0,
    })
}

pub(super) fn decode(kind: Type, wire: u8, payload: &[u8]) -> Result<Value> {
    ensure!(
        wire == wire_type(kind)?,
        "Protobuf field type does not match its wire encoding"
    );
    let integer = || -> Result<u64> {
        let mut offset = 0;
        let value = wire::varint(payload, &mut offset)?;
        ensure!(offset == payload.len(), "trailing Protobuf scalar bytes");
        Ok(value)
    };
    Ok(match kind {
        Type::String => Value::String(
            std::str::from_utf8(payload)
                .context("Protobuf string is not UTF-8")?
                .into(),
        ),
        Type::Bytes => Value::String(STANDARD.encode(payload)),
        Type::Int32 | Type::Enum => {
            Value::from(i32::try_from(integer()? as i64).context("Protobuf int32/enum overflow")?)
        }
        Type::Int64 => Value::from(integer()? as i64),
        Type::Uint32 => Value::from(u32::try_from(integer()?).context("Protobuf uint32 overflow")?),
        Type::Uint64 => Value::from(integer()?),
        Type::Sint32 => {
            let value = u32::try_from(integer()?).context("Protobuf sint32 overflow")?;
            Value::from(((value >> 1) as i32) ^ -((value & 1) as i32))
        }
        Type::Sint64 => {
            let value = integer()?;
            Value::from(((value >> 1) as i64) ^ -((value & 1) as i64))
        }
        Type::Bool => match integer()? {
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            _ => bail!("Protobuf bool must be encoded as zero or one"),
        },
        Type::Fixed32 => Value::from(u32::from_le_bytes(payload.try_into()?)),
        Type::Fixed64 => Value::from(u64::from_le_bytes(payload.try_into()?)),
        Type::Sfixed32 => Value::from(i32::from_le_bytes(payload.try_into()?)),
        Type::Sfixed64 => Value::from(i64::from_le_bytes(payload.try_into()?)),
        Type::Float => finite(f64::from(f32::from_le_bytes(payload.try_into()?)))?,
        Type::Double => finite(f64::from_le_bytes(payload.try_into()?))?,
        Type::Message => unreachable!("wire_type rejects Message"),
    })
}

fn finite(value: f64) -> Result<Value> {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .context("nonfinite Protobuf number cannot participate in a typed value contract")
}

pub(super) fn decode_packed(kind: Type, bytes: &[u8], offset: &mut usize) -> Result<Value> {
    let start = *offset;
    let wire = wire_type(kind)?;
    match wire {
        0 => {
            wire::varint(bytes, offset)?;
        }
        1 | 5 => {
            let width = if wire == 1 { 8 } else { 4 };
            *offset = offset
                .checked_add(width)
                .context("packed Protobuf length overflow")?;
            ensure!(*offset <= bytes.len(), "truncated packed Protobuf number");
        }
        _ => bail!("this Protobuf type cannot be packed"),
    }
    decode(kind, wire, &bytes[start..*offset])
}

pub(super) fn encode(kind: Type, value: &Value) -> Result<Vec<u8>> {
    let signed = || {
        value
            .as_i64()
            .context("Protobuf signed value requires an exact integer")
    };
    let unsigned = || {
        value
            .as_u64()
            .context("Protobuf unsigned value requires an exact nonnegative integer")
    };
    Ok(match kind {
        Type::String => length_delimited(
            value
                .as_str()
                .context("Protobuf string requires a string")?
                .as_bytes(),
        ),
        Type::Bytes => length_delimited(
            &STANDARD.decode(value.as_str().context("Protobuf bytes require base64")?)?,
        ),
        Type::Int32 | Type::Enum => {
            wire::encode_varint(i64::from(i32::try_from(signed()?)?) as u64)
        }
        Type::Int64 => wire::encode_varint(signed()? as u64),
        Type::Uint32 => wire::encode_varint(u64::from(u32::try_from(unsigned()?)?)),
        Type::Uint64 => wire::encode_varint(unsigned()?),
        Type::Sint32 => {
            let value = i32::try_from(signed()?)?;
            wire::encode_varint(u64::from(((value as u32) << 1) ^ ((value >> 31) as u32)))
        }
        Type::Sint64 => {
            let value = signed()?;
            wire::encode_varint(((value as u64) << 1) ^ ((value >> 63) as u64))
        }
        Type::Bool => wire::encode_varint(u64::from(
            value
                .as_bool()
                .context("Protobuf bool requires a boolean")?,
        )),
        Type::Fixed32 => u32::try_from(unsigned()?)?.to_le_bytes().to_vec(),
        Type::Fixed64 => unsigned()?.to_le_bytes().to_vec(),
        Type::Sfixed32 => i32::try_from(signed()?)?.to_le_bytes().to_vec(),
        Type::Sfixed64 => signed()?.to_le_bytes().to_vec(),
        Type::Float => {
            let original = value
                .as_f64()
                .context("Protobuf float requires a finite number")?;
            let narrowed = original as f32;
            ensure!(
                narrowed.is_finite() && f64::from(narrowed) == original,
                "Protobuf float delivery would lose precision"
            );
            narrowed.to_le_bytes().to_vec()
        }
        Type::Double => {
            let number = value
                .as_f64()
                .context("Protobuf double requires a finite number")?;
            ensure!(
                number.is_finite(),
                "Protobuf double requires a finite number"
            );
            number.to_le_bytes().to_vec()
        }
        Type::Message => bail!("message delivery requires the original typed message shape"),
    })
}
