//! Read only this Case's physical records, retaining original source coordinates.
use super::*;

type SelectedRead = (Arc<Vec<u8>>, Option<Vec<usize>>);

pub(super) fn read(
    path: &Path,
    index: &FileIndex,
    reader: &Arc<std::sync::Mutex<RecordReader>>,
) -> Result<SelectedRead> {
    let source = crate::dependency_index::scoped::resolve(path)?;
    ensure!(
        crate::dependency_index::FileStamp::read_native(&source.path)? == index.stamp,
        "selected Source ledger changed after admission"
    );
    let Some(locations) = &source.locations else {
        let location = RecordLocation {
            line: 1,
            offset: 0,
            length: index.stamp.size,
            sha256: index.sha256.clone(),
        };
        let raw = reader
            .lock()
            .map_err(|_| anyhow!("dependency cache lock poisoned"))?
            .read_source(&source, &index.stamp, &location)?;
        return Ok((raw, None));
    };
    let capacity = locations
        .iter()
        .try_fold(0usize, |total, location| {
            total.checked_add(usize::try_from(location.length).ok()?)
        })
        .context("selected Case dependencies exceed address space")?;
    let mut raw = Vec::with_capacity(capacity);
    let mut lines = Vec::with_capacity(locations.len());
    for location in locations.iter() {
        let bytes = reader
            .lock()
            .map_err(|_| anyhow!("dependency cache lock poisoned"))?
            .read_source(&source, &index.stamp, location)?;
        raw.extend_from_slice(&bytes);
        lines.push(location.line);
    }
    source.validate()?;
    ensure!(
        crate::dependency_index::FileStamp::read_native(&source.path)? == index.stamp,
        "selected Source ledger changed during traversal"
    );
    ensure!(
        crate::policy_evidence::digest(&raw).trim_start_matches("sha256:") == index.sha256,
        "selected Case dependency checksum changed after indexing"
    );
    Ok((Arc::new(raw), Some(lines)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::observation::{
        SCOPE_SCHEMA, ScopeIndex, ScopeKind, ScopeRecordLocation,
    };
    use serde_json::json;

    #[test]
    fn sparse_case_reads_only_its_records_and_prefetch_reuses_physical_cache() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("recording-run.json"), "{}").unwrap();
        let case_id = Uuid::new_v4();
        let directory = temp.path().join(case_id.to_string());
        std::fs::create_dir(&directory).unwrap();
        let rows = [
            "first".to_owned(),
            "never-selected".repeat(8_192),
            "last".to_owned(),
        ]
        .map(|text| format!("{}\n", json!({"text":text})).into_bytes());
        std::fs::write(temp.path().join("dependencies.jsonl"), rows.concat()).unwrap();
        let scope = ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: "..".into(),
            scope: ScopeKind::Case { case_id },
            locations: vec![0, 2]
                .into_iter()
                .map(|i| ScopeRecordLocation {
                    line: i + 1,
                    offset: rows[..i].iter().map(|row| row.len() as u64).sum(),
                    length: rows[i].len() as u64,
                    sha256: crate::policy_evidence::digest(&rows[i])
                        .trim_start_matches("sha256:")
                        .into(),
                    exchange_id: Uuid::new_v4(),
                    effect_index: 0,
                })
                .collect(),
        };
        let path = directory.join("dependency-scope.json");
        std::fs::write(&path, serde_json::to_vec(&scope).unwrap()).unwrap();
        let index = crate::dependency_index::load_file(&path).unwrap();
        let selected = (rows[0].len() + rows[2].len()) as u64;
        assert!(index.stamp.size > selected * 100);
        let reader = Arc::new(std::sync::Mutex::new(RecordReader::new(selected as usize)));
        let (raw, lines) = read(&path, &index, &reader).unwrap();
        assert_eq!(raw.as_slice(), [rows[0].clone(), rows[2].clone()].concat());
        assert_eq!(lines.unwrap(), [1, 3]);
        assert_eq!(reader.lock().unwrap().source_bytes, selected);
        read(&path, &index, &reader).unwrap();
        assert_eq!(reader.lock().unwrap().source_bytes, selected);
        assert_eq!(reader.lock().unwrap().hits, 2);
    }
}
