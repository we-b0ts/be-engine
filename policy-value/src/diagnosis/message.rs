//! Registered value analysis over protocol-projected message locations.
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use traffic_policy::{Finding, PolicyRegistry};
use traffic_protocol::message::ProtocolMessage;
use traffic_value::codec::CodecRegistry;

const MAX_VALUES: usize = 64;
const MAX_FINDINGS: usize = 16;
const MAX_NODES: usize = 2048;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct MessageFinding {
    pub native_location: String,
    #[serde(flatten)]
    pub finding: Finding,
}

#[derive(Debug, Default)]
pub struct MessageAnalysis {
    pub findings: Vec<MessageFinding>,
    pub limited: bool,
}

pub fn analyze(
    source: &dyn ProtocolMessage,
    target: &dyn ProtocolMessage,
    codecs: &CodecRegistry,
    policies: &PolicyRegistry,
    differences: &[traffic_contract::comparison::Difference],
    facts: &Value,
) -> Result<MessageAnalysis> {
    let mut analysis = MessageAnalysis::default();
    if policies.descriptors().next().is_none() {
        return Ok(analysis);
    }
    let source = source.project()?;
    let target = target.project()?;
    let mut visited = 0;
    for (index, (location, source)) in source.values.iter().enumerate() {
        if index >= MAX_VALUES || analysis.findings.len() >= MAX_FINDINGS {
            analysis.limited = true;
            break;
        }
        let Some(target) = target.values.get(location) else {
            continue;
        };
        if source.bytes == target.bytes {
            continue;
        }
        let paths = differences
            .iter()
            .filter_map(|difference| {
                difference
                    .pointer
                    .strip_prefix(location)
                    .filter(|path| path.is_empty() || path.starts_with('/'))
            })
            .collect::<Vec<_>>();
        if paths.is_empty() {
            continue;
        }
        let metadata = serde_json::from_value(facts.clone())?;
        let Some(codec) = codecs.try_recognize(&source.bytes, &metadata)? else {
            continue;
        };
        let source = codec.decode(&source.bytes)?;
        let Ok(target) = codec.decode(&target.bytes) else {
            continue;
        };
        walk(
            source.value(),
            target.value(),
            "",
            location,
            policies,
            &paths,
            facts,
            &mut visited,
            &mut analysis,
        )?;
    }
    Ok(analysis)
}

#[allow(clippy::too_many_arguments)] // One bounded traversal retains its native and logical locations.
fn walk(
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    pointer: &str,
    location: &str,
    policies: &PolicyRegistry,
    paths: &[&str],
    facts: &Value,
    visited: &mut usize,
    analysis: &mut MessageAnalysis,
) -> Result<()> {
    if source == target {
        return Ok(());
    }
    if !paths
        .iter()
        .any(|path| traffic_value::path::overlaps(path, pointer))
    {
        return Ok(());
    }
    if *visited >= MAX_NODES
        || pointer.len() > 1024
        || pointer.matches('/').count() > MAX_DEPTH
        || analysis.findings.len() >= MAX_FINDINGS
    {
        analysis.limited = true;
        return Ok(());
    }
    *visited += 1;
    let findings = super::analysis::analyze_values(policies, source, target, pointer, facts)?;
    let proposed = findings.iter().any(|finding| finding.proposal.is_some());
    for finding in findings {
        if analysis.findings.len() >= MAX_FINDINGS {
            analysis.limited = true;
            break;
        }
        analysis.findings.push(MessageFinding {
            native_location: location.into(),
            finding,
        });
    }
    if proposed {
        return Ok(());
    }
    match (source, target) {
        (traffic_value::Value::Object(source), traffic_value::Value::Object(target)) => {
            for (name, source) in source {
                if let Some(target) = target.get(name) {
                    walk(
                        source,
                        target,
                        &format!("{pointer}/{}", traffic_value::path::escape(name)),
                        location,
                        policies,
                        paths,
                        facts,
                        visited,
                        analysis,
                    )?;
                }
                if analysis.limited {
                    break;
                }
            }
        }
        (traffic_value::Value::Array(source), traffic_value::Value::Array(target))
            if source.len() == target.len() =>
        {
            for (index, (source, target)) in source.iter().zip(target).enumerate() {
                walk(
                    source,
                    target,
                    &format!("{pointer}/{index}"),
                    location,
                    policies,
                    paths,
                    facts,
                    visited,
                    analysis,
                )?;
                if analysis.limited {
                    break;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
