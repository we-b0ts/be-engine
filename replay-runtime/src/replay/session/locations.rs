//! Preserve out-of-order completions encountered by the monotonic Source reader.
use std::{collections::HashMap, fs::File, os::unix::fs::FileExt};

use anyhow::{Result, ensure};
use traffic_recording_store::source::RecordLocation;

const MEMORY_LOCATIONS: usize = 4096;
const WIDTH: usize = 88;

#[derive(Default)]
pub(super) struct Locations {
    memory: HashMap<u64, RecordLocation>,
    overflow: Option<(File, u64)>,
}

impl Locations {
    pub(super) fn insert(&mut self, sequence: u64, location: RecordLocation) -> Result<()> {
        if self.memory.len() < MEMORY_LOCATIONS {
            ensure!(
                self.memory.insert(sequence, location).is_none(),
                "duplicate Source dependency {sequence}"
            );
            return Ok(());
        }
        let (file, end) = match &mut self.overflow {
            Some(spool) => spool,
            None => self.overflow.insert((tempfile::tempfile()?, 0)),
        };
        let offset = spool_offset(sequence)?;
        let mut bytes = [0; WIDTH];
        bytes[..8].copy_from_slice(&u64::try_from(location.line)?.to_le_bytes());
        bytes[8..16].copy_from_slice(&location.offset.to_le_bytes());
        bytes[16..24].copy_from_slice(&location.length.to_le_bytes());
        ensure!(
            location.sha256.len() == 64,
            "Source dependency has no row checksum"
        );
        bytes[24..].copy_from_slice(location.sha256.as_bytes());
        file.write_all_at(&bytes, offset)?;
        *end = (*end).max(offset + WIDTH as u64);
        Ok(())
    }

    pub(super) fn take(&mut self, sequence: u64) -> Result<Option<RecordLocation>> {
        if let Some(location) = self.memory.remove(&sequence) {
            return Ok(Some(location));
        }
        let Some((file, end)) = &self.overflow else {
            return Ok(None);
        };
        let offset = spool_offset(sequence)?;
        if offset >= *end {
            return Ok(None);
        }
        let mut bytes = [0; WIDTH];
        file.read_exact_at(&mut bytes, offset)?;
        let number = |offset| {
            u64::from_le_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .expect("location field"),
            )
        };
        let line = usize::try_from(number(0))?;
        if line == 0 {
            return Ok(None);
        }
        file.write_all_at(&[0; 8], offset)?;
        Ok(Some(RecordLocation {
            line,
            offset: number(8),
            length: number(16),
            sha256: std::str::from_utf8(&bytes[24..])?.to_owned(),
        }))
    }
}

fn spool_offset(sequence: u64) -> Result<u64> {
    sequence
        .checked_mul(WIDTH as u64)
        .filter(|&offset| offset <= u64::MAX - WIDTH as u64)
        .ok_or_else(|| anyhow::anyhow!("Source dependency sequence is beyond the spill range"))
}
