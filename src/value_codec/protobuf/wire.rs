//! Whole-message wire parsing and raw slices; unknown fields are never decoded heuristically.
use anyhow::{Result, bail, ensure};

use super::Budget;

pub(super) struct Field<'a> {
    pub number: u32,
    pub wire: u8,
    pub tag: &'a [u8],
    pub payload: &'a [u8],
    pub raw: &'a [u8],
    pub length_padding: usize,
}

pub(super) fn fields<'a>(bytes: &'a [u8], budget: &mut Budget) -> Result<Vec<Field<'a>>> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        budget.field()?;
        let start = offset;
        let tag = varint(bytes, &mut offset)?;
        let number = u32::try_from(tag >> 3)?;
        ensure!(
            (1..(1 << 29)).contains(&number),
            "invalid Protobuf field number"
        );
        let tag_end = offset;
        let wire = (tag & 7) as u8;
        let payload_start = match wire {
            0 => {
                let start = offset;
                varint(bytes, &mut offset)?;
                start
            }
            1 => {
                let start = offset;
                advance(bytes, &mut offset, 8)?;
                start
            }
            2 => {
                let length = usize::try_from(varint(bytes, &mut offset)?)?;
                let start = offset;
                advance(bytes, &mut offset, length)?;
                start
            }
            5 => {
                let start = offset;
                advance(bytes, &mut offset, 4)?;
                start
            }
            3 | 4 => bail!("Protobuf groups require an explicit supported codec"),
            _ => bail!("invalid Protobuf wire type"),
        };
        fields.push(Field {
            number,
            wire,
            tag: &bytes[start..tag_end],
            payload: &bytes[payload_start..offset],
            raw: &bytes[start..offset],
            length_padding: if wire == 2 {
                payload_start - tag_end - encode_varint((offset - payload_start) as u64).len()
            } else {
                0
            },
        });
    }
    Ok(fields)
}

fn advance(bytes: &[u8], offset: &mut usize, length: usize) -> Result<()> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("Protobuf length overflow"))?;
    ensure!(end <= bytes.len(), "truncated Protobuf field");
    *offset = end;
    Ok(())
}

pub(super) fn varint(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| anyhow::anyhow!("truncated Protobuf varint"))?;
        *offset += 1;
        ensure!(shift < 63 || byte <= 1, "Protobuf varint overflow");
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    bail!("Protobuf varint overflow")
}

pub(super) fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(if value == 0 { byte } else { byte | 128 });
        if value == 0 {
            return bytes;
        }
    }
}
