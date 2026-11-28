//! Transport Source sequence lists without embedding them in agent receipts.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::Receipt;

pub(crate) fn read_sequence_file(path: &Path) -> Result<BTreeSet<u64>> {
    let file =
        File::open(path).with_context(|| format!("open sequence file {}", path.display()))?;
    let mut sequences = BTreeSet::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        for entry in line
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let sequence: u64 = entry.parse().with_context(|| {
                format!(
                    "invalid Source sequence in {} at line {}",
                    path.display(),
                    index + 1
                )
            })?;
            ensure!(sequence > 0, "Source sequences must be positive");
            sequences.insert(sequence);
        }
    }
    ensure!(
        !sequences.is_empty(),
        "sequence file {} is empty",
        path.display()
    );
    Ok(sequences)
}

pub(crate) fn read_receipt(path: &Path) -> Result<Receipt> {
    let mut value: Value =
        serde_json::from_slice(&fs::read(path)?).context("parse delivery receipt")?;
    match value.get("kind").and_then(Value::as_str) {
        Some("fixes") => {
            if let Some(fixes) = value.get_mut("fixes").and_then(Value::as_array_mut) {
                for fix in fixes {
                    load_sequence_field(path, fix)?;
                }
            }
        }
        Some("claim" | "confirmed" | "review" | "engine_gap") => {
            load_sequence_field(path, &mut value)?
        }
        _ => {}
    }
    serde_json::from_value(value).context("parse delivery receipt")
}

fn load_sequence_field(receipt: &Path, row: &mut Value) -> Result<()> {
    let Some(row) = row.as_object_mut() else {
        return Ok(());
    };
    let Some(path) = row.remove("sequences_file") else {
        return Ok(());
    };
    ensure!(
        !row.contains_key("sequences"),
        "provide sequences_file or sequences"
    );
    let path = path.as_str().context("sequences_file must be a path")?;
    let file = receipt.parent().unwrap_or_else(|| Path::new("")).join(path);
    row.insert(
        "sequences".to_owned(),
        serde_json::to_value(read_sequence_file(&file)?)?,
    );
    Ok(())
}
