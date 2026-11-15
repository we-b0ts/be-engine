//! Registered document transformation with host-owned network route allocation.
use crate::{CompiledRewrite, DocumentRule, RewriteBudget, RewritePlan};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc};
use traffic_policy::{
    AnalysisInput, EvidenceAccess, Finding, PolicyAction, PolicyDescriptor, PolicyProvider,
    ResourceRequest, TransformInput, TransformPlan, TransformPolicy, TransformedValue,
};
use traffic_value::Value;

pub struct ResponseRewritePolicy;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    rules: Vec<DocumentRule>,
}

impl PolicyProvider for ResponseRewritePolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "documents",
            version: 1,
            description: "Discover addresses in selected documents and materialize them with registered routes",
            actions: &[PolicyAction::Transform, PolicyAction::Analyze],
        }
    }
    fn prepare_transform(&self, configuration: &Value) -> Result<Arc<dyn TransformPolicy>> {
        let configuration: Configuration =
            serde_json::from_value(serde_json::to_value(configuration)?)?;
        Ok(Arc::new(CompiledRewrite::compile(&configuration.rules)?))
    }

    fn analyze(&self, input: &AnalysisInput<'_>, _: &dyn EvidenceAccess) -> Result<Vec<Finding>> {
        let query = input.facts.pointer("/query").and_then(Value::as_str);
        let rejected = input.facts.pointer("/egress_rejections/rejected_packets_in_samples")
            .is_some_and(|count| matches!(count, Value::Number(traffic_value::Number::Unsigned(value)) if *value > 0)
                || matches!(count, Value::Number(traffic_value::Number::Signed(value)) if *value > 0));
        let literal_ip = input
            .facts
            .pointer("/clusters")
            .and_then(Value::as_array)
            .is_some_and(|clusters| {
                clusters.iter().any(|cluster| {
                    cluster.pointer("/reason").and_then(Value::as_str) == Some("unmatched_target")
                        && cluster
                            .pointer("/endpoint/host")
                            .and_then(Value::as_str)
                            .is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok())
                })
            });
        let hint = match query {
            Some("ip_capture") => {
                "Trace the reported IP to the exact Source response and address location. Review a learned address through http.response_rewrite with Source consumption proof and the original capture scope. Apply the capture rule, record fresh traffic and verify the new recording through genuine Replay."
            }
            Some("dirty_clusters") if literal_ip => {
                "An unmatched dependency targets a literal IP. Trace that endpoint to Source configuration or an earlier Source response. For a learned address, inspect its exact document location and consumption, then plan the response acquisition policy with Source proof. Complete its recording obligation and verify the fresh recording through genuine Replay."
            }
            Some("dirty_clusters") if rejected => {
                "Packet rejection counts require endpoint and Source-origin investigation. Use route --cause unrecorded-ip with current evidence when the endpoint is known. Trace learned addresses to their Source response before proposing http.response_rewrite. Applying a capture rule requires fresh recording and genuine Replay."
            }
            _ => return Ok(Vec::new()),
        };
        Ok(vec![Finding {
            policy: "documents".into(),
            source_path: String::new(),
            summary: "Inspect address acquisition and interception coverage".into(),
            hint: hint.into(),
            proposal: None,
            requirements: vec![
                "source_semantics".into(),
                "recording".into(),
                "fresh_verification".into(),
            ],
        }])
    }
}

impl TransformPolicy for CompiledRewrite {
    fn inspect(&self, input: &TransformInput<'_>) -> Result<Option<Box<dyn TransformPlan>>> {
        let query = input.context.pointer("/query").and_then(Value::as_str);
        let Some(plan) = self.inspect_with_query(input.bytes, RewriteBudget::default(), query)?
        else {
            return Ok(None);
        };
        let requests = plan
            .endpoints()
            .map(|endpoint| {
                Ok(ResourceRequest {
                    id: endpoint.alias.clone(),
                    capability: "network.route".into(),
                    parameters: serde_json::from_value(serde_json::json!({
                        "alias":endpoint.alias, "upstream_ip":endpoint.upstream_ip.to_string(),
                        "port":endpoint.port, "protocol":endpoint.protocol.as_str(),
                        "upstream_authority":endpoint.upstream_authority,
                    }))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Box::new(Plan { plan, requests })))
    }
}

struct Plan {
    plan: RewritePlan,
    requests: Vec<ResourceRequest>,
}
impl TransformPlan for Plan {
    fn requests(&self) -> &[ResourceRequest] {
        &self.requests
    }
    fn materialize(
        self: Box<Self>,
        resources: &BTreeMap<String, Value>,
    ) -> Result<TransformedValue> {
        let routes = self
            .requests
            .iter()
            .map(|request| {
                let ip = resources
                    .get(&request.id)
                    .and_then(|resource| resource.pointer("/advertised_ip"))
                    .and_then(Value::as_str)
                    .context("response endpoint has no allocated route")?
                    .parse()?;
                Ok((request.id.clone(), ip))
            })
            .collect::<Result<_>>()?;
        Ok(TransformedValue {
            bytes: self.plan.materialize(&routes)?,
        })
    }
}
