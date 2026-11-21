//! Preserve the acknowledged journal prefix through atomic report publication.
use super::*;
use std::{
    fs,
    io::{BufRead, Read, Write},
    path::Path,
};

pub(in crate::policy_evidence) fn stage(
    source: &Path,
    destination: &Path,
    report: &serde_json::Value,
) -> Result<()> {
    let Some(value) = report
        .get("dependency_hypothesis_journal")
        .filter(|value| !value.is_null())
    else {
        return Ok(());
    };
    let manifest: JournalManifest = serde_json::from_value(value.clone())?;
    let artifact = manifest
        .path
        .to_str()
        .context("hypothesis journal artifact is not UTF-8")?;
    let src = crate::policy_evidence::storage::named_path(source, artifact)?;
    let dst = crate::policy_evidence::storage::named_path(destination, artifact)?;
    let key = if manifest.durable > 0 {
        let witnesses: crate::policy_evidence::WitnessManifest =
            serde_json::from_value(report["policy_witnesses"].clone())?;
        witnesses.load_graph(source)?;
        let context = report["cases"]
            .as_array()
            .and_then(|cases| cases.iter().find_map(|case| case["case_dir"].as_str()))
            .map(PathBuf::from)
            .unwrap_or_else(|| source.to_path_buf());
        Some(
            witnesses
                .graph()
                .context("hypothesis journal lost its authenticated witness graph")?
                .key(&context)?,
        )
    } else {
        None
    };
    verify(&src, &manifest, key.as_deref())?;
    if src == dst {
        return Ok(());
    }
    if dst.exists() {
        return verify(&dst, &manifest, key.as_deref());
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&dst)?;
    let mut input = fs::File::open(&src)?.take(manifest.bytes);
    std::io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    verify(&dst, &manifest, key.as_deref())
}

pub(super) fn verify(path: &Path, manifest: &JournalManifest, key: Option<&[u8]>) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() >= manifest.bytes
            && manifest.bytes <= super::JOURNAL_BYTE_LIMIT,
        "hypothesis journal must retain its bounded durable prefix"
    );
    let mut reader = std::io::BufReader::new(fs::File::open(path)?.take(manifest.bytes));
    let mut hash = Sha256::new();
    let mut sequence = 0_u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        ensure!(
            line.ends_with(b"\n") && line.len() <= 2 * 1024 * 1024,
            "hypothesis journal durable record is incomplete or oversized"
        );
        hash.update(&line);
        let row: serde_json::Value = serde_json::from_slice(&line)?;
        sequence = sequence
            .checked_add(1)
            .context("hypothesis sequence overflow")?;
        ensure!(
            row["sequence"].as_u64() == Some(sequence),
            "hypothesis journal sequence is discontinuous"
        );
        let payload = &row["payload"];
        let signed = serde_json::to_vec(&(sequence, payload))?;
        ensure!(
            row["sha256"].as_str() == Some(crate::policy_evidence::digest(&signed).as_str()),
            "hypothesis journal payload digest differs"
        );
        crate::policy_evidence::v2::authenticate(
            key.context("hypothesis journal signing key is missing")?,
            "hypothesis",
            &(sequence, payload),
            row["authentication"]
                .as_str()
                .context("hypothesis authentication missing")?,
        )?;
    }
    ensure!(
        sequence == manifest.durable && format!("sha256:{:x}", hash.finalize()) == manifest.sha256,
        "hypothesis journal acknowledged prefix changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn hypothesis_journal_persists_an_append_burst_before_delivery() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary
            .path()
            .join("policy-witnesses-burst.hypotheses.jsonl");
        let key = vec![9; 32];
        let journal = Journal::create(path.clone(), key.clone()).unwrap();
        // Model synchronous admission while the writer has no chance to run.
        for index in 0..1200 {
            journal
                .append(&serde_json::json!({"status":"rejected","index":index}))
                .unwrap();
        }
        assert_eq!(journal.manifest().durable, 0);
        journal.wait_durable().await.unwrap();
        let manifest = journal.manifest();
        assert_eq!(manifest.enqueued, 1200);
        assert_eq!(manifest.durable, 1200);
        assert!(manifest.complete);
        verify(&path, &manifest, Some(&key)).unwrap();
    }

    #[tokio::test]
    async fn hypothesis_journal_rejects_changed_records_and_missing_durable_tail() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary
            .path()
            .join("policy-witnesses-test.hypotheses.jsonl");
        let journal = Journal::create(path.clone(), vec![9; 32]).unwrap();
        journal
            .append(&serde_json::json!({"status":"rejected"}))
            .unwrap();
        journal.wait_durable().await.unwrap();
        let manifest = journal.manifest();
        verify(&path, &manifest, Some(&[9; 32])).unwrap();
        let original = fs::read(&path).unwrap();
        let changed = String::from_utf8(original.clone())
            .unwrap()
            .replace("rejected", "selected");
        fs::write(&path, changed).unwrap();
        assert!(verify(&path, &manifest, Some(&[9; 32])).is_err());
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(verify(&path, &manifest, Some(&[9; 32])).is_err());
    }
}
