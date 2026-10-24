//! Complete GET response value locations and length-safe replacement.
//! Correlation fields, flags, CAS, keys, and non-value response bytes stay intact.
use std::ops::Range;

use anyhow::{Context, Result, ensure};

#[derive(Debug, Clone)]
pub(crate) struct ValueSlot {
    pub(crate) frame: usize,
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) payload: Range<usize>,
    length: Length,
}

#[derive(Debug, Clone)]
enum Length {
    Binary { prefix: usize },
    Text { digits: Range<usize> },
}

pub(crate) fn extract(frames: &[Vec<u8>], wire_protocol: &str) -> Result<Vec<ValueSlot>> {
    let mut slots = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        ensure!(
            frame.len() <= 64 * 1024 * 1024,
            "Memcached response frame is oversized"
        );
        match wire_protocol {
            "binary" => {
                if let Some(slot) = binary(frame, index)? {
                    slots.push(slot);
                }
            }
            "text" => slots.extend(text(frame, index)?),
            _ => anyhow::bail!("unknown Memcached wire protocol"),
        }
    }
    Ok(slots)
}

/// Decode a protected complete semantic envelope produced by the replay adapter.
/// The caller selects request/response from its authenticated witness role.
pub(crate) fn witness_values(bytes: &[u8], response: bool) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "Memcached witness envelope is oversized"
    );
    // This envelope is authenticated engine output. Its base64 framing can be
    // larger than the application's separate 1 MiB JSON payload limit.
    let envelope: serde_json::Value =
        serde_json::from_slice(bytes).context("invalid Memcached witness envelope")?;
    ensure!(
        envelope["protocol"] == "memcached",
        "witness is not a Memcached envelope"
    );
    let decode = |value: &serde_json::Value| -> Result<Vec<u8>> {
        Ok(STANDARD.decode(value.as_str().context("witness capture is not base64")?)?)
    };
    let key = if envelope["key"].is_null() {
        Vec::new()
    } else {
        decode(&envelope["key"])?
    };
    if !response {
        if envelope["value"].is_null() {
            return Ok(Vec::new());
        }
        return Ok(vec![(key, decode(&envelope["value"])?)]);
    }
    if !envelope["command"].as_str().is_some_and(|command| {
        matches!(
            command.to_ascii_lowercase().as_str(),
            "get" | "gets" | "gat" | "gats"
        )
    }) {
        return Ok(Vec::new());
    }
    let frames = envelope["response_frames"]
        .as_array()
        .context("response witness has no frame inventory")?
        .iter()
        .map(decode)
        .collect::<Result<Vec<_>>>()?;
    let slots = extract(
        &frames,
        envelope["wire_protocol"]
            .as_str()
            .context("witness wire protocol is missing")?,
    )?;
    Ok(slots
        .into_iter()
        .map(|slot| {
            (
                slot.key.unwrap_or_else(|| key.clone()),
                frames[slot.frame][slot.payload].to_vec(),
            )
        })
        .collect())
}

pub(crate) fn replace(frame: &[u8], slot: &ValueSlot, value: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        slot.payload.start <= slot.payload.end && slot.payload.end <= frame.len(),
        "invalid Memcached value location"
    );
    let mut output = frame.to_vec();
    output.splice(slot.payload.clone(), value.iter().copied());
    match &slot.length {
        Length::Binary { prefix } => {
            let length = u32::try_from(
                prefix
                    .checked_add(value.len())
                    .context("Memcached response length overflow")?,
            )?;
            output[8..12].copy_from_slice(&length.to_be_bytes());
        }
        Length::Text { digits } => {
            output.splice(digits.clone(), value.len().to_string().bytes());
        }
    }
    Ok(output)
}

fn binary(frame: &[u8], index: usize) -> Result<Option<ValueSlot>> {
    ensure!(
        frame.len() >= 24 && frame[0] == 0x81,
        "invalid Memcached binary response header"
    );
    ensure!(
        matches!(frame[1], 0x00 | 0x09 | 0x0c | 0x0d),
        "value contract requires a Memcached GET response"
    );
    let body = usize::try_from(u32::from_be_bytes(frame[8..12].try_into()?))?;
    ensure!(
        body.checked_add(24) == Some(frame.len()),
        "incomplete or trailing Memcached response bytes"
    );
    let extras = usize::from(frame[4]);
    let key = usize::from(u16::from_be_bytes(frame[2..4].try_into()?));
    ensure!(
        extras + key <= body,
        "invalid Memcached binary response sections"
    );
    let status = u16::from_be_bytes(frame[6..8].try_into()?);
    if status != 0 {
        return Ok(None);
    }
    ensure!(
        extras == 4,
        "Memcached GET response requires complete flags"
    );
    let start = 24 + extras + key;
    Ok(Some(ValueSlot {
        frame: index,
        key: (key != 0).then(|| frame[24 + extras..start].to_vec()),
        payload: start..frame.len(),
        length: Length::Binary {
            prefix: extras + key,
        },
    }))
}

fn text(frame: &[u8], index: usize) -> Result<Vec<ValueSlot>> {
    let mut slots = Vec::new();
    let mut cursor = 0;
    while cursor < frame.len() {
        let end = frame[cursor..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .map(|offset| cursor + offset)
            .context("incomplete Memcached text response line")?;
        let line = &frame[cursor..end];
        if line == b"END"
            || line == b"ERROR"
            || line.starts_with(b"CLIENT_ERROR ")
            || line.starts_with(b"SERVER_ERROR ")
        {
            ensure!(
                end + 2 == frame.len(),
                "trailing Memcached text response bytes"
            );
            return Ok(slots);
        }
        let tokens = token_ranges(line);
        ensure!(
            (4..=5).contains(&tokens.len()) && &line[tokens[0].clone()] == b"VALUE",
            "invalid Memcached VALUE header"
        );
        let parse = |range: &Range<usize>| -> Result<u64> {
            Ok(std::str::from_utf8(&line[range.clone()])?.parse()?)
        };
        u32::try_from(parse(&tokens[2])?)?;
        if let Some(cas) = tokens.get(4) {
            parse(cas)?;
        }
        let size = usize::try_from(parse(&tokens[3])?)?;
        let start = end + 2;
        let tail = start
            .checked_add(size)
            .context("Memcached VALUE length overflow")?;
        ensure!(
            tail.checked_add(2).is_some_and(|end| end <= frame.len())
                && frame.get(tail..tail + 2) == Some(b"\r\n"),
            "incomplete Memcached VALUE body"
        );
        slots.push(ValueSlot {
            frame: index,
            key: Some(line[tokens[1].clone()].to_vec()),
            payload: start..tail,
            length: Length::Text {
                digits: cursor + tokens[3].start..cursor + tokens[3].end,
            },
        });
        ensure!(
            slots.len() <= 4096,
            "Memcached response contains too many value slots"
        );
        cursor = tail + 2;
    }
    anyhow::bail!("Memcached VALUE response is missing END")
}

fn token_ranges(line: &[u8]) -> Vec<Range<usize>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < line.len() {
        if line[offset].is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < line.len() && !line[offset].is_ascii_whitespace() {
            offset += 1;
        }
        result.push(start..offset);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_replies_have_no_value_slot_and_malformed_gets_remain_errors() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let mut envelope = serde_json::json!({"protocol":"memcached","wire_protocol":"text","command":"set",
            "key":STANDARD.encode(b"key"),"response_frames":[STANDARD.encode(b"STORED\r\n")]});
        assert!(
            witness_values(&serde_json::to_vec(&envelope).unwrap(), true)
                .unwrap()
                .is_empty()
        );
        envelope["command"] = "get".into();
        assert!(witness_values(&serde_json::to_vec(&envelope).unwrap(), true).is_err());
        envelope["response_frames"] =
            serde_json::json!([STANDARD.encode(b"VALUE key 0 3\r\n123\r\nEND\r\n")]);
        assert_eq!(
            witness_values(&serde_json::to_vec(&envelope).unwrap(), true).unwrap(),
            vec![(b"key".to_vec(), b"123".to_vec())]
        );
    }

    #[test]
    fn binary_patch_preserves_flags_key_opaque_and_cas() {
        let mut frame = vec![0; 24];
        frame[0] = 0x81;
        frame[1] = 0x0c;
        frame[2..4].copy_from_slice(&3_u16.to_be_bytes());
        frame[4] = 4;
        frame[8..12].copy_from_slice(&10_u32.to_be_bytes());
        frame[12..16].copy_from_slice(&123_u32.to_be_bytes());
        frame[16..24].copy_from_slice(&456_u64.to_be_bytes());
        frame.extend([0, 0, 0, 7]);
        frame.extend(b"keyold");
        let slot = extract(std::slice::from_ref(&frame), "binary")
            .unwrap()
            .pop()
            .unwrap();
        let patched = replace(&frame, &slot, b"longer").unwrap();
        assert_eq!(&patched[12..31], &frame[12..31]);
        assert_eq!(&patched[31..], b"longer");
        assert_eq!(u32::from_be_bytes(patched[8..12].try_into().unwrap()), 13);
        assert!(extract(&[patched], "binary").is_ok());
        frame.push(0);
        assert!(extract(&[frame], "binary").is_err());
    }

    #[test]
    fn text_patch_preserves_cas_and_other_entries() {
        let frame = b"VALUE key 7 3 456\r\nold\r\nVALUE other 0 4\r\nsame\r\nEND\r\n".to_vec();
        let slots = extract(std::slice::from_ref(&frame), "text").unwrap();
        assert_eq!(slots.len(), 2);
        let patched = replace(&frame, &slots[0], b"longer").unwrap();
        assert_eq!(
            patched,
            b"VALUE key 7 6 456\r\nlonger\r\nVALUE other 0 4\r\nsame\r\nEND\r\n"
        );
        assert!(extract(&[patched], "text").is_ok());
        for bad in [
            b"VALUE key 0 4\r\nold\r\nEND\r\n".as_slice(),
            b"VALUE key 0 3\r\nold\r\n",
            b"END\r\ntrailing",
        ] {
            assert!(extract(&[bad.to_vec()], "text").is_err());
        }
    }
}
