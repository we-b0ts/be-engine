//! Bind registered transformations to Source-selected codec documents.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use traffic_policy::{PreparedTransform, ResourceRequest, TransformInput, TransformPlan};
use traffic_value::{
    Value,
    codec::{CodecRegistry, ValueDocument},
};

pub struct Transformation {
    source: Arc<dyn ValueDocument>,
    plan: Box<dyn TransformPlan>,
}

impl Transformation {
    pub fn inspect(
        policy: &PreparedTransform,
        bytes: &[u8],
        context: &Value,
        metadata: &Value,
        codecs: &CodecRegistry,
    ) -> Result<Option<Self>> {
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "transformation input exceeds the 64 MiB value limit"
        );
        let codec = codecs
            .try_recognize(bytes, metadata)?
            .context("transformation input has no installed content codec")?;
        let source = codec.decode(bytes)?;
        let plan = policy.inspect(&TransformInput {
            value: source.value(),
            context,
        })?;
        Ok(plan.map(|plan| Self { source, plan }))
    }

    pub fn requests(&self) -> &[ResourceRequest] {
        self.plan.requests()
    }

    pub fn materialize(self, resources: &BTreeMap<String, Value>) -> Result<Vec<u8>> {
        let transformed = self.plan.materialize(resources)?;
        self.source
            .transform(&transformed.value, &transformed.paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_policy::{
        PolicyAction, PolicyDescriptor, PolicyProvider, PolicyRegistry, TransformPolicy,
        TransformedValue,
    };

    struct Replace;

    impl PolicyProvider for Replace {
        fn descriptor(&self) -> PolicyDescriptor {
            PolicyDescriptor {
                id: "test.replace-value",
                version: 1,
                description: "Logical transformation regression",
                actions: &[PolicyAction::Transform],
            }
        }

        fn prepare_transform(&self, _: &Value) -> Result<Arc<dyn TransformPolicy>> {
            Ok(Arc::new(Self))
        }
    }

    impl TransformPolicy for Replace {
        fn inspect(&self, input: &TransformInput<'_>) -> Result<Option<Box<dyn TransformPlan>>> {
            ensure!(
                input.value.as_str() == Some("before"),
                "unexpected logical value"
            );
            Ok(Some(Box::new(Replacement {
                value: Value::String("after".into()),
                paths: vec![String::new()],
            })))
        }
    }

    struct Replacement {
        value: Value,
        paths: Vec<String>,
    }

    impl TransformPlan for Replacement {
        fn requests(&self) -> &[ResourceRequest] {
            &[]
        }

        fn materialize(self: Box<Self>, _: &BTreeMap<String, Value>) -> Result<TransformedValue> {
            Ok(TransformedValue {
                value: self.value,
                paths: self.paths,
            })
        }
    }

    #[test]
    fn one_logical_policy_uses_each_sources_codec_for_rendering() {
        let mut policies = PolicyRegistry::default();
        policies.register(Arc::new(Replace)).unwrap();
        let policy = policies
            .prepare_transform("test.replace-value", &Value::Null)
            .unwrap();
        let codecs = traffic_extensions::codecs();
        for (source, expected) in [
            (b"before".as_slice(), b"after".as_slice()),
            (br#""before""#.as_slice(), br#""after""#.as_slice()),
        ] {
            let plan = Transformation::inspect(&policy, source, &Value::Null, &Value::Null, codecs)
                .unwrap()
                .unwrap();
            assert!(plan.requests().is_empty());
            assert_eq!(plan.materialize(&BTreeMap::new()).unwrap(), expected);
        }
    }

    #[test]
    fn rendering_rejects_changes_outside_the_policys_selected_paths() {
        let codec = traffic_extensions::codecs()
            .prepare("json", &Value::Null)
            .unwrap();
        let source = codec.decode(br#"{"declared":"before","other":1}"#).unwrap();
        let plan = Transformation {
            source,
            plan: Box::new(Replacement {
                value: serde_json::from_value(serde_json::json!({"declared":"after","other":2}))
                    .unwrap(),
                paths: vec!["/declared".into()],
            }),
        };
        assert!(plan.materialize(&BTreeMap::new()).is_err());
    }

    #[test]
    fn selected_structural_transformation_preserves_outer_tokens() {
        let codec = traffic_extensions::codecs()
            .prepare("json", &Value::Null)
            .unwrap();
        let source = codec
            .decode(br#"{ "outside":1e0, "data": {"keep":7,"gone":0}}"#)
            .unwrap();
        let logical = serde_json::from_value(serde_json::json!({
            "outside":1.0, "data":{"keep":7}
        }))
        .unwrap();
        let paths = vec!["/data".into()];
        assert!(source.encode(&logical, &paths).is_err());
        let plan = Transformation {
            source,
            plan: Box::new(Replacement {
                value: logical,
                paths,
            }),
        };
        assert_eq!(
            plan.materialize(&BTreeMap::new()).unwrap(),
            br#"{ "outside":1e0, "data": {"keep":7}}"#,
        );
    }
}
