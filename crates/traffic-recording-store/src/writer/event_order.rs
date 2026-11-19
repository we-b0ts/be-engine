//! Reorder compact event spans at seal if producers queued them out of order.
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use traffic_model::recording::LedgerFileIdentity;

pub(super) fn seal(root: &Path, name: &str) -> Result<LedgerFileIdentity> {
    let path = root.join(name);
    let mut input = BufReader::new(File::open(&path)?);
    let mut spans = Vec::new();
    let mut row = Vec::new();
    let mut offset = 0;
    loop {
        row.clear();
        let length = input.read_until(b'\n', &mut row)?;
        if length == 0 {
            break;
        }
        let column = row
            .iter()
            .position(|byte| *byte == b'\t')
            .context("invalid event row")?;
        let sequence: u64 = std::str::from_utf8(&row[..column])?.parse()?;
        spans.push((sequence, offset, length));
        offset += length as u64;
    }
    spans.sort_unstable_by_key(|span| span.0);
    ensure!(
        spans.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "duplicate recording event sequence"
    );

    let temporary = root.join(format!(".ordered-{name}"));
    let mut output = BufWriter::new(File::create(&temporary)?);
    let mut digest = Sha256::new();
    let mut position = offset;
    for (_, offset, length) in spans {
        if position != offset {
            input.seek(SeekFrom::Start(offset))?;
        }
        row.resize(length, 0);
        input.read_exact(&mut row)?;
        output.write_all(&row)?;
        digest.update(&row);
        position = offset + length as u64;
    }
    output.flush()?;
    output.get_ref().sync_all()?;
    fs::rename(temporary, path)?;
    Ok(LedgerFileIdentity {
        path: name.into(),
        length: offset,
        sha256: format!("{:x}", digest.finalize()),
    })
}
