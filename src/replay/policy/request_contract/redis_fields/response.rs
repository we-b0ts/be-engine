//! Bounded RESP2 storage-value positions; rendering preserves every other byte.
use super::*;

#[derive(Debug)]
struct Frame {
    range: Range<usize>,
    value: FrameValue,
}

#[derive(Debug)]
enum FrameValue {
    Bulk(Range<usize>),
    Array(Vec<Frame>),
    Unavailable,
    Other,
}

/// Decode one selected bulk value without accepting changes to its surrounding frame.
pub(in crate::replay::policy::request_contract) fn bulk_prefix(
    raw: &[u8],
) -> Result<(&[u8], usize)> {
    ensure!(
        raw.len() <= 1024 * 1024,
        "Redis response value exceeds 1 MiB"
    );
    let mut position = 0;
    let mut remaining = 16384;
    let frame = parse(raw, &mut position, 0, &mut remaining)?;
    let FrameValue::Bulk(payload) = frame.value else {
        anyhow::bail!("contextual Redis value must remain a bulk string");
    };
    Ok((&raw[payload], position))
}

pub(super) fn values<'a>(
    command: &str,
    args: &'a [Vec<u8>],
    raw: &'a [u8],
) -> Result<Vec<RedisFieldValue<'a>>> {
    let identities = response_identities(command, args)?;
    if identities.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        raw.len() <= 1024 * 1024,
        "Redis response value exceeds 1 MiB"
    );
    let mut position = 0;
    let mut remaining = 16384;
    let frame = parse(raw, &mut position, 0, &mut remaining)?;
    ensure!(position == raw.len(), "Redis response has trailing frames");
    if matches!(frame.value, FrameValue::Unavailable) {
        return Ok(identities);
    }
    match command {
        "GET" | "HGET" | "LINDEX" => {
            let mut identity = identities.into_iter().next().unwrap();
            fill(&mut identity, frame, raw)?;
            Ok(vec![identity])
        }
        "MGET" | "HMGET" => {
            let FrameValue::Array(frames) = frame.value else {
                anyhow::bail!("{command} response must be an array");
            };
            ensure!(
                frames.len() == identities.len(),
                "{command} response count differs from requested values"
            );
            identities
                .into_iter()
                .zip(frames)
                .map(|(mut identity, frame)| {
                    fill(&mut identity, frame, raw)?;
                    Ok(identity)
                })
                .collect()
        }
        "HGETALL" => {
            let FrameValue::Array(frames) = frame.value else {
                anyhow::bail!("HGETALL response must be an array");
            };
            ensure!(
                frames.len().is_multiple_of(2),
                "incomplete HGETALL field/value pair"
            );
            let mut frames = frames.into_iter();
            let mut values = Vec::new();
            while let Some(field) = frames.next() {
                let FrameValue::Bulk(field) = field.value else {
                    anyhow::bail!("HGETALL field must be a bulk string");
                };
                let mut identity = identities[0].clone();
                identity.hash_field = Some(&raw[field]);
                fill(&mut identity, frames.next().unwrap(), raw)?;
                values.push(identity);
            }
            Ok(values)
        }
        "LRANGE" => {
            let FrameValue::Array(frames) = frame.value else {
                anyhow::bail!("LRANGE response must be an array");
            };
            frames
                .into_iter()
                .map(|frame| {
                    let mut identity = identities[0].clone();
                    fill(&mut identity, frame, raw)?;
                    Ok(identity)
                })
                .collect()
        }
        _ => unreachable!("validated Redis response identity"),
    }
}

fn fill<'a>(value: &mut RedisFieldValue<'a>, frame: Frame, raw: &'a [u8]) -> Result<()> {
    match frame.value {
        FrameValue::Bulk(payload) => {
            value.payload = Some(&raw[payload]);
            value.response = Some(frame.range);
        }
        FrameValue::Unavailable => {}
        _ => anyhow::bail!("selected Redis storage value is not a bulk string"),
    }
    Ok(())
}

fn parse(raw: &[u8], position: &mut usize, depth: usize, remaining: &mut usize) -> Result<Frame> {
    ensure!(
        depth < 64 && *remaining > 0,
        "Redis response frame bound exceeded"
    );
    *remaining -= 1;
    let start = *position;
    let prefix = *raw.get(start).context("incomplete Redis response")?;
    let header_end = raw[start..]
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .map(|offset| start + offset)
        .context("incomplete Redis response header")?;
    let header = &raw[start + 1..header_end];
    *position = header_end + 2;
    let length = || -> Result<i64> { Ok(std::str::from_utf8(header)?.parse::<i64>()?) };
    let value = match prefix {
        b'$' => match length()? {
            -1 => FrameValue::Unavailable,
            length if length >= 0 => {
                let end = position
                    .checked_add(usize::try_from(length)?)
                    .context("Redis bulk length overflow")?;
                ensure!(
                    raw.get(end..end + 2) == Some(b"\r\n"),
                    "incomplete Redis bulk value"
                );
                let payload = *position..end;
                *position = end + 2;
                FrameValue::Bulk(payload)
            }
            _ => anyhow::bail!("invalid Redis bulk length"),
        },
        b'*' => match length()? {
            -1 => FrameValue::Unavailable,
            length if length >= 0 => {
                let count = usize::try_from(length)?;
                ensure!(count <= *remaining, "Redis array count exceeds bounds");
                let frames = (0..count)
                    .map(|_| parse(raw, position, depth + 1, remaining))
                    .collect::<Result<Vec<_>>>()?;
                FrameValue::Array(frames)
            }
            _ => anyhow::bail!("invalid Redis array length"),
        },
        b'-' => FrameValue::Unavailable,
        b'_' if header.is_empty() => FrameValue::Unavailable,
        b':' => {
            length()?;
            FrameValue::Other
        }
        b'+' => FrameValue::Other,
        _ => anyhow::bail!("unsupported Redis response frame"),
    };
    Ok(Frame {
        range: start..*position,
        value,
    })
}
