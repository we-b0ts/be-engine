//! Bounded Protobuf wire field decoding for structural comparison.
use super::*;
pub fn parse_fields(payload: &[u8]) -> Result<Vec<Field<'_>>> {
    let mut fields = Vec::new();
    let mut index = 0;
    while index < payload.len() {
        ensure!(
            fields.len() < MAX_FIELDS,
            "protobuf message has too many fields"
        );
        let start = index;
        let tag = read_varint(payload, &mut index)?;
        let number = u32::try_from(tag >> 3)
            .map_err(|_| anyhow::anyhow!("protobuf field number overflow"))?;
        let wire_type = (tag & 7) as u8;
        ensure!(
            number != 0 && number < (1 << 29),
            "invalid protobuf field number"
        );
        let mut nested = None;
        let value_offset = index - start;
        let mut payload_offset = 0;
        match wire_type {
            0 => {
                read_varint(payload, &mut index)?;
            }
            1 => advance(payload, &mut index, 8)?,
            2 => {
                let length = usize::try_from(read_varint(payload, &mut index)?)
                    .map_err(|_| anyhow::anyhow!("protobuf length is not representable"))?;
                payload_offset = index - start;
                let end = index
                    .checked_add(length)
                    .ok_or_else(|| anyhow::anyhow!("protobuf length overflow"))?;
                ensure!(
                    end <= payload.len(),
                    "truncated protobuf length-delimited field"
                );
                nested = Some(&payload[index..end]);
                index = end;
            }
            5 => advance(payload, &mut index, 4)?,
            3 | 4 => bail!("protobuf groups are not supported"),
            _ => bail!("invalid protobuf wire type {wire_type}"),
        }
        fields.push(Field {
            number,
            wire_type,
            raw: &payload[start..index],
            payload: nested,
            value_offset,
            payload_offset,
        });
    }
    Ok(fields)
}

pub fn read_varint(payload: &[u8], index: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *payload
            .get(*index)
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))?;
        *index += 1;
        ensure!(shift < 63 || byte <= 1, "protobuf varint overflow");
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint overflow")
}

pub fn advance(payload: &[u8], index: &mut usize, length: usize) -> Result<()> {
    let end = index
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("protobuf field length overflow"))?;
    ensure!(end <= payload.len(), "truncated protobuf fixed-width field");
    *index = end;
    Ok(())
}
