//! Authenticate the complete compact graph before offline pair evaluation.
use super::*;
use std::io::{Read, Seek, SeekFrom};

pub(in crate::policy_evidence) fn verify(
    report: &Path,
    manifest: &WitnessManifest,
) -> Result<PathBuf> {
    manifest.load_graph(report)?;
    let graph = manifest
        .graph()
        .context("policy observation graph is missing")?;
    let report_value = std::fs::read(report)
        .ok()
        .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes))
        .transpose()?;
    if let Some(binding) = &graph.replay {
        let report = report_value
            .as_ref()
            .context("bound policy observations require their original Replay report")?;
        ensure!(
            report["session_id"].as_str() == Some(binding.session_id.as_str())
                && report["replay_policy"]["fingerprint"].as_str()
                    == Some(binding.policy_fingerprint.as_str()),
            "policy observation inventory belongs to another Replay session or policy"
        );
        for target in &graph.targets {
            let case = report["cases"]
                .as_array()
                .and_then(|cases| {
                    cases
                        .iter()
                        .find(|case| case["case_id"] == target.metadata.case_id)
                })
                .context("Target observation Case is absent from the Replay report")?;
            let clock = case["target_request_started_at"]
                .as_str()
                .map(str::parse::<DateTime<Utc>>)
                .transpose()?;
            ensure!(
                clock == target.metadata.clocks.case.target,
                "Target observation Case clock differs from the Replay report"
            );
        }
    } else {
        ensure!(
            report_value
                .as_ref()
                .is_none_or(|report| report.get("session_id").is_none()),
            "unbound observations cannot authorize a production Replay report"
        );
    }
    ensure!(
        manifest.sealed
            && manifest.complete
            && manifest.omitted == 0
            && manifest.observed == manifest.recorded
            && manifest.recorded == graph.sources.len() + graph.targets.len()
            && manifest.witnesses.is_empty(),
        "policy payload coverage is incomplete; run fresh genuine Replay before planning"
    );
    let path = artifact_path(report, manifest)?;
    if !graph.segments.is_empty() {
        super::super::storage::verify(report, manifest, graph)?;
    } else {
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 64 * 1024 * 1024,
            "policy observation artifact must be a bounded regular file"
        );
        let bytes = std::fs::read(&path)?;
        ensure!(
            digest(&bytes) == manifest.sha256,
            "policy observation artifact changed after publication"
        );
        let mut offset = 0_u64;
        let mut ids = BTreeSet::new();
        for blob in &graph.blobs {
            if let Some(source) = &blob.source {
                ensure!(
                    blob.length == 0 && blob.offset == 0 && ids.insert((blob.id.clone(), true)),
                    "invalid or duplicate Source payload reference"
                );
                ensure!(
                    crate::dependency_index::FileStamp::read(&source.record.path)?
                        == source.record.stamp,
                    "referenced Source evidence changed after Replay"
                );
                continue;
            }
            ensure!(
                blob.offset == offset
                    && blob.length <= 2 * 1024 * 1024
                    && blob.plaintext_bytes <= 1024 * 1024
                    && ids.insert((blob.id.clone(), false)),
                "policy payload index is incomplete or duplicated"
            );
            offset = offset
                .checked_add(blob.length)
                .context("policy payload index overflow")?;
        }
        ensure!(
            offset == u64::try_from(bytes.len())?
                && graph.payload_bytes
                    == graph
                        .blobs
                        .iter()
                        .map(|blob| blob.plaintext_bytes)
                        .sum::<usize>(),
            "policy payload index does not cover the complete artifact"
        );
    }
    ensure!(
        graph.payload_bytes == graph.blobs.iter().map(|b| b.plaintext_bytes).sum::<usize>(),
        "policy payload accounting differs"
    );
    if graph.sources.is_empty() && graph.targets.is_empty() && graph.key_envelope.is_empty() {
        ensure!(
            graph.blobs.is_empty() && graph.associations.is_empty() && graph.groups.is_empty(),
            "empty policy inventory has references"
        );
        return Ok(path);
    }
    // Published reports may live outside .traffic-e2e/local. Their immutable
    // case directories retain the existing managed-key resolution context.
    let context = report_value
        .and_then(|value| {
            value["cases"]
                .as_array()?
                .iter()
                .find_map(|case| case["case_dir"].as_str().map(PathBuf::from))
        })
        .unwrap_or_else(|| report.to_path_buf());
    let key = graph.key(&context)?;
    let mut unsigned = manifest.clone();
    let authentication = if manifest.version == 4 {
        unsigned.authentication.clear();
        &manifest.authentication
    } else {
        unsigned
            .observations
            .as_mut()
            .unwrap()
            .authentication
            .clear();
        &graph.authentication
    };
    authenticate(&key, "manifest", &unsigned, authentication)?;
    graph.validate(&key)?;
    let used = graph
        .sources
        .iter()
        .map(|source| source.blob)
        .chain(graph.targets.iter().map(|target| target.blob))
        .collect::<BTreeSet<_>>();
    ensure!(
        used.len() == graph.blobs.len(),
        "policy inventory contains unowned payloads"
    );
    Ok(path)
}

pub(in crate::policy_evidence) fn read(
    path: &Path,
    witness: &WitnessRef,
    proof: &PairProof,
    key_context: &Path,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let key = crate::request_headers::decrypt_evidence(
        key_context,
        &key_label(&proof.session_id),
        &proof.key_envelope,
    )?;
    ensure!(key.len() == 32, "invalid observation signing key");
    authenticate(
        &key,
        "source",
        &(
            &proof.session_id,
            &proof.source.id,
            &proof.source.metadata,
            &proof.source_blob,
        ),
        &proof.source.authentication,
    )?;
    let mut expected = proof.source.metadata.clone();
    let target = if let Some((target, blob)) = &proof.target {
        target.metadata.validate()?;
        ensure!(
            compatible(&expected, &target.metadata),
            "candidate association crosses Case, surface, resource or operation"
        );
        authenticate(
            &key,
            "target",
            &(&proof.session_id, &target.id, &target.metadata, blob),
            &target.authentication,
        )?;
        match proof
            .association
            .as_ref()
            .context("candidate association authentication is missing")?
        {
            AssociationProof::Pair(authentication) => authenticate(
                &key,
                "association",
                &(&proof.session_id, &proof.source.id, &target.id),
                authentication,
            )?,
            AssociationProof::Group {
                target: id,
                sources,
                authentication,
            } => {
                ensure!(
                    id == &target.id && sources.contains(&proof.source.id),
                    "observation is outside candidate coverage"
                );
                authenticate(
                    &key,
                    "candidate-group",
                    &(&proof.session_id, id, sources),
                    authentication,
                )?;
            }
        }
        expected.target_role = target.metadata.role;
        expected.clocks.case.target = target.metadata.clocks.case.target;
        expected.clocks.dependency.target = target.metadata.clocks.dependency.target;
        expected.clocks.delivery.target = target.metadata.clocks.delivery.target;
        Some(read_blob(path, &proof.session_id, blob, key_context)?)
    } else {
        ensure!(
            proof.association.is_none(),
            "Source-only inventory has a candidate association"
        );
        None
    };
    let id = proof.target.as_ref().map_or_else(
        || proof.source.id.clone(),
        |(target, _)| format!("{}:{}", proof.source.id, target.id),
    );
    ensure!(
        witness.id == id
            && witness.metadata == expected
            && witness.source_sha256 == proof.source_blob.id
            && witness.target_sha256 == proof.target.as_ref().map(|(_, blob)| blob.id.clone())
            && witness.target_observation_id
                == proof.target.as_ref().map(|(target, _)| target.id.clone())
            && witness.offset == proof.source_blob.offset
            && witness.length == proof.source_blob.length
            && witness.sha256 == proof.source_blob.sha256,
        "policy witness metadata or payload reference differs from its authenticated observations"
    );
    expected.validate_roles(target.is_some())?;
    Ok((
        read_blob(path, &proof.session_id, &proof.source_blob, key_context)?,
        target,
    ))
}
fn read_blob(path: &Path, session_id: &str, blob: &BlobRef, context: &Path) -> Result<Vec<u8>> {
    if let Some(source) = &blob.source {
        let payload = source.read(context)?;
        ensure!(
            payload.len() == blob.plaintext_bytes && digest(&payload) == blob.id,
            "referenced Source envelope differs from authenticated Replay evidence"
        );
        return Ok(payload);
    }
    if !blob.chunks.is_empty() {
        return super::super::storage::read(path, session_id, blob, context);
    }
    ensure!(
        blob.length <= 2 * 1024 * 1024 && blob.plaintext_bytes <= 1024 * 1024,
        "policy payload exceeds supported bound"
    );
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(blob.offset))?;
    let mut bytes = vec![0; usize::try_from(blob.length)?];
    file.read_exact(&mut bytes)?;
    ensure!(
        digest(&bytes) == blob.sha256,
        "protected policy payload changed"
    );
    let envelope: BlobEnvelope = serde_json::from_slice(&bytes)?;
    ensure!(
        envelope.id == blob.id,
        "protected policy payload identity changed"
    );
    let payload = crate::request_headers::decrypt_evidence(
        context,
        &blob_label(session_id, &blob.id),
        &envelope.encrypted,
    )?;
    ensure!(
        payload.len() == blob.plaintext_bytes && digest(&payload) == blob.id,
        "policy payload plaintext fingerprint differs"
    );
    Ok(payload)
}
