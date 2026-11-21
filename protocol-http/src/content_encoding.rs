use std::io::Read;

use anyhow::{Context, Result};
use flate2::read::{MultiGzDecoder, ZlibDecoder};

pub struct DecodedBody {
    pub body: Vec<u8>,
    pub truncated: bool,
}

pub fn decode(bytes: &[u8], encoding: &str, limit: usize) -> Result<DecodedBody> {
    let mut out = bytes.to_vec();
    let mut truncated = false;
    for coding in encoding
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty())
        .rev()
    {
        out = match coding {
            "gzip" | "x-gzip" => {
                let mut decoder = MultiGzDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .by_ref()
                    .take(limit.saturating_add(1) as u64)
                    .read_to_end(&mut decoded)
                    .context("failed to decode gzip body")?;
                truncated = decoded.len() > limit;
                decoded.truncate(limit);
                decoded
            }
            "deflate" => {
                let mut decoder = ZlibDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .by_ref()
                    .take(limit.saturating_add(1) as u64)
                    .read_to_end(&mut decoded)
                    .context("failed to decode deflate body")?;
                truncated = decoded.len() > limit;
                decoded.truncate(limit);
                decoded
            }
            "identity" => out,
            other => anyhow::bail!("unsupported content-encoding {other}"),
        };
        if truncated {
            break;
        }
    }
    Ok(DecodedBody {
        body: out,
        truncated,
    })
}
