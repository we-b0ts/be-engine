//! Registered analysis over logical values and explicitly supplied evidence.
use anyhow::Result;

pub fn analyze_values(
    registry: &traffic_policy::PolicyRegistry,
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    source_path: &str,
    facts: &serde_json::Value,
) -> Result<Vec<traffic_policy::Finding>> {
    let facts = serde_json::from_value(facts.clone())?;
    let evidence = ValueEvidence {
        source: Some(source),
        target: Some(target),
        source_bytes: None,
        facts: &facts,
    };
    registry.analyze(
        &traffic_policy::AnalysisInput {
            values: Some(traffic_policy::ValuePair {
                source,
                target,
                source_path,
                target_path: source_path,
            }),
            facts: &facts,
        },
        &evidence,
    )
}

pub fn analyze_source(
    registry: &traffic_policy::PolicyRegistry,
    source: &traffic_value::Value,
    bytes: &[u8],
    facts: &serde_json::Value,
) -> Result<Vec<traffic_policy::Finding>> {
    let facts = serde_json::from_value(facts.clone())?;
    registry.analyze(
        &traffic_policy::AnalysisInput {
            values: None,
            facts: &facts,
        },
        &ValueEvidence {
            source: Some(source),
            target: None,
            source_bytes: Some(bytes),
            facts: &facts,
        },
    )
}

pub fn analyze_context(
    registry: &traffic_policy::PolicyRegistry,
    facts: &serde_json::Value,
) -> Result<Vec<traffic_policy::Finding>> {
    let facts = serde_json::from_value(facts.clone())?;
    registry.analyze(
        &traffic_policy::AnalysisInput {
            values: None,
            facts: &facts,
        },
        &ValueEvidence {
            source: None,
            target: None,
            source_bytes: None,
            facts: &facts,
        },
    )
}

struct ValueEvidence<'a> {
    source: Option<&'a traffic_value::Value>,
    target: Option<&'a traffic_value::Value>,
    source_bytes: Option<&'a [u8]>,
    facts: &'a traffic_value::Value,
}

impl traffic_policy::EvidenceAccess for ValueEvidence<'_> {
    fn query(
        &self,
        kind: &str,
        selection: &traffic_value::Value,
    ) -> Result<Vec<traffic_value::Value>> {
        if kind == "source.bytes" {
            anyhow::ensure!(
                matches!(selection, traffic_value::Value::Null) || selection.as_str() == Some(""),
                "raw evidence selection requires the complete value"
            );
            let bytes = self
                .source_bytes
                .ok_or_else(|| anyhow::anyhow!("original Source bytes are unavailable"))?;
            return Ok(vec![traffic_value::Value::Bytes(bytes.to_vec())]);
        }
        let value = match kind {
            "source" => self.source,
            "target" => self.target,
            "context" => Some(self.facts),
            _ => anyhow::bail!("value analysis evidence {kind:?} is unavailable"),
        }
        .ok_or_else(|| anyhow::anyhow!("value analysis evidence {kind:?} is unavailable"))?;
        let pointer = match selection {
            traffic_value::Value::Null => "",
            traffic_value::Value::String(pointer) => pointer,
            _ => anyhow::bail!("evidence selection requires a logical pointer"),
        };
        traffic_value::path::validate(pointer, false)?;
        Ok(value.pointer(pointer).cloned().into_iter().collect())
    }
}
