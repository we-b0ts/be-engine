//! Separator-joined collections preserve duplicate and empty elements.
use super::*;
use serde::Deserialize;
use traffic_policy::{
    ResourceRequest, TransformInput, TransformPlan, TransformPolicy, TransformedValue,
};

pub struct JoinedStringPolicy;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    separator: String,
}

impl Configuration {
    fn parse(value: &Value) -> Result<Self> {
        let configuration: Self = serde_json::from_value(serde_json::to_value(value)?)?;
        ensure!(
            !configuration.separator.is_empty()
                && configuration.separator.len() <= 16
                && !configuration.separator.contains(['\r', '\n']),
            "joined collection requires a nonempty separator of at most 16 bytes"
        );
        Ok(configuration)
    }
}

fn canonicalize(value: &str, separator: &str) -> String {
    let mut parts = value.split(separator).collect::<Vec<_>>();
    parts.sort_unstable();
    parts.join(separator)
}

impl PolicyProvider for JoinedStringPolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "unordered-joined-string",
            version: 1,
            description: "Compare separator-joined collections with exact multiplicity",
            actions: &[
                PolicyAction::Compare,
                PolicyAction::Transform,
                PolicyAction::Analyze,
            ],
        }
    }
    fn prepare(&self, options: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        Ok(Arc::new(Configuration::parse(options)?))
    }
    fn prepare_transform(&self, options: &Value) -> Result<Arc<dyn TransformPolicy>> {
        Ok(Arc::new(Configuration::parse(options)?))
    }
    fn analyze(&self, input: &AnalysisInput<'_>, _: &dyn EvidenceAccess) -> Result<Vec<Finding>> {
        let Some(pair) = &input.values else {
            return Ok(Vec::new());
        };
        let Some((source, target)) = pair.source.as_str().zip(pair.target.as_str()) else {
            return Ok(Vec::new());
        };
        if source == target {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();
        for separator in [",", ";", "|"] {
            if source.split(separator).count() < 2 && target.split(separator).count() < 2
                || canonicalize(source, separator) != canonicalize(target, separator)
            {
                continue;
            }
            findings.push(Finding {
                policy: "unordered-joined-string".into(), source_path:pair.source_path.into(),
                summary:"Joined collection values differ only in element order".into(),
                hint:"Trace Source splitting and joining, including its separator, duplicate values and empty elements. Declare the shared field policy with Source proof, then verify through genuine Replay.".into(),
                proposal:Some(Proposal::Field(serde_json::from_value(serde_json::json!({"kind":"policy",
                    "id":"unordered-joined-string","version":1,"options":{"separator":separator}}))?)),
                requirements:vec!["source_semantics".into(),"fresh_verification".into()],
            });
        }
        Ok(findings)
    }
}

impl ComparisonPolicy for Configuration {
    fn validate_schema(&self, schema: &traffic_value::codec::FieldSchema) -> Result<()> {
        use traffic_value::codec::{FieldSchema, ValueType};
        ensure!(
            matches!(
                schema,
                FieldSchema::Dynamic | FieldSchema::Scalar | FieldSchema::Typed(ValueType::String)
            ),
            "joined-string policy requires a string field"
        );
        Ok(())
    }

    fn applies(&self, source: &Value, _: &Value) -> Result<bool> {
        Ok(source.as_str().is_some())
    }
    fn evaluate(&self, pair: &ValuePair<'_>, _: &mut dyn EvaluationHost) -> Result<Evaluation> {
        Ok(match pair.source.as_str().zip(pair.target.as_str()) {
            Some((source, target))
                if canonicalize(source, &self.separator)
                    == canonicalize(target, &self.separator) =>
            {
                Evaluation::matched()
            }
            _ => Evaluation::mismatch(
                pair,
                "joined_collection_contents",
                "joined collection changed",
            ),
        })
    }
}

impl TransformPolicy for Configuration {
    fn inspect(&self, input: &TransformInput<'_>) -> Result<Option<Box<dyn TransformPlan>>> {
        ensure!(
            input.bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "joined collection exceeds 64 MiB"
        );
        let source = std::str::from_utf8(input.bytes)?;
        let canonical = canonicalize(source, &self.separator).into_bytes();
        Ok(Some(Box::new(Plan(canonical))))
    }
}
struct Plan(Vec<u8>);
impl TransformPlan for Plan {
    fn requests(&self) -> &[ResourceRequest] {
        &[]
    }
    fn materialize(self: Box<Self>, _: &BTreeMap<String, Value>) -> Result<TransformedValue> {
        Ok(TransformedValue { bytes: self.0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparison_and_transformation_preserve_duplicate_and_empty_elements() {
        let options = serde_json::from_value(serde_json::json!({"separator":","})).unwrap();
        let policy = JoinedStringPolicy.prepare(&options).unwrap();
        for (source, target, passed) in [("a,,b,a", "a,b,a,", true), ("a,,b", "a,b", false)] {
            let source = Value::String(source.into());
            let target = Value::String(target.into());
            let result = policy
                .evaluate(
                    &ValuePair {
                        source: &source,
                        target: &target,
                        source_path: "",
                        target_path: "",
                    },
                    &mut (),
                )
                .unwrap();
            assert_eq!(result.passed(), passed);
        }
        let transformation = JoinedStringPolicy.prepare_transform(&options).unwrap();
        let plan = transformation
            .inspect(&TransformInput {
                bytes: b"b,a,,a",
                context: &Value::Null,
            })
            .unwrap()
            .unwrap();
        assert!(plan.requests().is_empty());
        assert_eq!(plan.materialize(&BTreeMap::new()).unwrap().bytes, b",a,a,b");
        let invalid = serde_json::from_value(serde_json::json!({"separator":""})).unwrap();
        assert!(JoinedStringPolicy.prepare(&invalid).is_err());
    }
}
