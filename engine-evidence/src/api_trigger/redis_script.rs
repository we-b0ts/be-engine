//! SCRIPT EXISTS belongs to an origin only through an adjacent proven invocation.
use super::{
    OriginIndex,
    evidence::{EvidenceFile, case_id, key, timestamp},
    redis_args,
};
use crate::{config::BackgroundDependencyRuleConfig, dependency_index::RecordReader};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn associate(
    files: &[EvidenceFile],
    rules: &[BackgroundDependencyRuleConfig],
    index: &mut OriginIndex,
) -> Result<()> {
    if !rules.iter().any(|r| {
        matches!(
            r,
            BackgroundDependencyRuleConfig::Redis {
                script: Some(_),
                ..
            }
        )
    }) {
        return Ok(());
    }
    let mut reader = RecordReader::new(8 * 1024 * 1024);
    for file in files.iter().filter(|file| file.request.is_some()) {
        let case = case_id(&file.path)?;
        let mut previous = BTreeMap::<String, (Value, String)>::new();
        for record in file.index.records("redis") {
            let bytes = reader.read(&file.path, &file.index.stamp, &record.location)?;
            let event: Value = serde_json::from_slice(&bytes)?;
            let Some(connection) = event["connection_id"].as_str() else {
                continue;
            };
            if let Some((setup, sha)) = previous.get(connection)
                && setup["sequence"].as_u64().and_then(|s| s.checked_add(1))
                    == event["sequence"].as_u64()
                && setup["command"] == "SCRIPT"
                && let (Some(args), Some(invocation)) =
                    (redis_args(setup), index.witness(&case, &event))
            {
                for rule in rules {
                    let BackgroundDependencyRuleConfig::Redis {
                        script: Some(script),
                        name,
                        ..
                    } = rule
                    else {
                        continue;
                    };
                    if timestamp(setup).is_none_or(|t| t < invocation.captured_at)
                        || invocation.rule != *name
                        || !script.exists(&args)
                        || setup["response_kind"] == "error"
                    {
                        continue;
                    }
                    let Some(setup_key) = key(&case, setup) else {
                        continue;
                    };
                    let mut witness = invocation.clone();
                    witness.command = "SCRIPT".into();
                    witness.dependency_sha256 = sha.clone();
                    witness.exchanges = 1;
                    ensure!(
                        index.witnesses.insert(setup_key, witness).is_none(),
                        "ambiguous SCRIPT EXISTS origin"
                    );
                    break;
                }
            }
            previous.insert(connection.into(), (event, record.location.sha256.clone()));
        }
    }
    index.source_bytes += reader.source_bytes;
    Ok(())
}
