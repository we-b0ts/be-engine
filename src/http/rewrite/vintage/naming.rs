use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tracing::debug;

use crate::dependency::DiscoveredTcpTarget;
use crate::dns_mock::FakeDnsEntry;

use super::super::{DiscoveredTarget, Plugin, PluginResult, RewriteInput, RewrittenBody};
use super::{alias_for_ip, application_error_code, parse_outer, query, required_query};

const PLUGIN_NAME: &str = "vintage-naming";
const MAX_DISCOVERED_NODES: usize = 4096;
const WORKING_NODES: &str = "working";
const UNREACHABLE_NODES: &str = "unreachable";

pub(in crate::http::rewrite) struct Naming {
    services: BTreeSet<String>,
    clusters: BTreeSet<String>,
}

impl Naming {
    pub(in crate::http::rewrite) fn new(services: &[String], clusters: &[String]) -> Self {
        Self {
            services: services.iter().cloned().collect(),
            clusters: clusters.iter().cloned().collect(),
        }
    }

    fn selected(&self, service: &str, cluster: &str) -> bool {
        (self.services.is_empty() || self.services.contains(service))
            && (self.clusters.is_empty() || self.clusters.contains(cluster))
    }
}

impl Plugin for Naming {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult> {
        let query = query(input);
        let action = required_query(&query, "action")?;
        let service = required_query(&query, "service")?;
        let cluster = required_query(&query, "cluster")?;
        if !self.selected(service, cluster) {
            return Ok(PluginResult::Unchanged);
        }

        match action {
            "lookup" | "lookupforupdate" => {
                let plan = match ResponsePlan::parse(input.body, service, cluster)? {
                    ParsedResponse::Success(plan) => plan,
                    ParsedResponse::ApplicationError { code } => {
                        debug!(
                            plugin = PLUGIN_NAME,
                            authority = input.authority.unwrap_or_default(),
                            service,
                            cluster,
                            application_code = %code,
                            response_body_bytes = input.body.len(),
                            "left Vintage application error response unchanged"
                        );
                        return Ok(PluginResult::Unchanged);
                    }
                };
                let targets = plan
                    .upstream_ips()
                    .into_iter()
                    .map(|connect_ip| DiscoveredTarget {
                        alias: alias_for_ip(connect_ip),
                        connect_ip,
                        upstream_authority: None,
                        upstream_protocol: None,
                    })
                    .collect();
                Ok(PluginResult::Rewritten {
                    body: Box::new(RewrittenBody::VintageNaming(plan)),
                    targets,
                    kubectl_proxy: None,
                })
            }
            _ => Ok(PluginResult::Unchanged),
        }
    }
}

enum ParsedResponse {
    Success(ResponsePlan),
    ApplicationError { code: String },
}

pub(in crate::http::rewrite) struct ResponsePlan {
    outer: Value,
    inner: Value,
    service: String,
    cluster: String,
    nodes: Vec<SocketAddrV4>,
}

impl ResponsePlan {
    fn parse(body: &[u8], service: &str, cluster: &str) -> Result<ParsedResponse> {
        let outer = parse_outer(body)?;
        if let Some(code) = application_error_code(&outer)? {
            return Ok(ParsedResponse::ApplicationError { code });
        }
        let inner_text = outer
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Vintage lookup response has no string body field"))?;
        let mut inner: Value =
            serde_json::from_str(inner_text).context("Vintage lookup body is not valid JSON")?;
        if inner.get("service").and_then(Value::as_str) != Some(service)
            || inner.get("cluster").and_then(Value::as_str) != Some(cluster)
        {
            bail!(
                "Vintage lookup response identity does not match request service={service:?} cluster={cluster:?}"
            );
        }
        let original_node_count = collect_nodes(&inner)?.len();
        if original_node_count > MAX_DISCOVERED_NODES {
            bail!(
                "Vintage lookup response has {} nodes, exceeding limit {}",
                original_node_count,
                MAX_DISCOVERED_NODES
            );
        }
        let counts = retain_one_node_per_state(&mut inner)?;
        if counts.working > 1 || counts.unreachable > 1 {
            debug!(
                plugin = PLUGIN_NAME,
                service,
                cluster,
                working_before = counts.working,
                unreachable_before = counts.unreachable,
                "reduced Vintage node states for deterministic traffic capture"
            );
        }
        let nodes = collect_nodes(&inner)?;
        Ok(ParsedResponse::Success(Self {
            outer,
            inner,
            service: service.to_string(),
            cluster: cluster.to_string(),
            nodes,
        }))
    }

    pub(super) fn upstream_ips(&self) -> BTreeSet<Ipv4Addr> {
        self.nodes.iter().map(|node| *node.ip()).collect()
    }

    pub(in crate::http::rewrite) fn render(
        mut self,
        registered: &BTreeMap<Ipv4Addr, FakeDnsEntry>,
    ) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)> {
        rewrite_nodes(&mut self.inner, registered)?;
        let mut discovered = BTreeSet::new();
        for node in &self.nodes {
            let entry = registered.get(node.ip()).ok_or_else(|| {
                anyhow!("Vintage node {} has no registered fake-IP route", node.ip())
            })?;
            discovered.insert((entry.fake_ip, *node.ip(), node.port(), entry.domain.clone()));
        }
        self.outer["body"] = Value::String(
            serde_json::to_string(&self.inner)
                .context("failed to serialize rewritten Vintage lookup body")?,
        );
        let body = serde_json::to_vec(&self.outer)
            .context("failed to serialize rewritten Vintage response")?;
        let targets = discovered
            .into_iter()
            .map(
                |(advertised_ip, upstream_ip, port, alias)| DiscoveredTcpTarget {
                    protocol: "motan".to_string(),
                    alias,
                    advertised_ip,
                    upstream_ip,
                    port,
                    service: Some(self.service.clone()),
                    cluster: Some(self.cluster.clone()),
                },
            )
            .collect();
        Ok((body, targets))
    }
}

struct NodeStateCounts {
    working: usize,
    unreachable: usize,
}

fn retain_one_node_per_state(inner: &mut Value) -> Result<NodeStateCounts> {
    let nodes = inner
        .get_mut("nodes")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("Vintage lookup body has no nodes object"))?;
    Ok(NodeStateCounts {
        working: retain_lowest_address(nodes, WORKING_NODES)?,
        unreachable: retain_lowest_address(nodes, UNREACHABLE_NODES)?,
    })
}

fn retain_lowest_address(
    nodes: &mut serde_json::Map<String, Value>,
    state: &'static str,
) -> Result<usize> {
    let Some(value) = nodes.get_mut(state) else {
        return Ok(0);
    };
    let values = value
        .as_array_mut()
        .ok_or_else(|| anyhow!("Vintage {state} nodes value is not an array"))?;
    let original_count = values.len();
    if original_count <= 1 {
        return Ok(original_count);
    }

    let mut selected = None;
    for (index, value) in values.iter().enumerate() {
        let address = node_address(value)?;
        if selected.is_none_or(|(_, current)| address < current) {
            selected = Some((index, address));
        }
    }
    let (selected, _) = selected.ok_or_else(|| anyhow!("Vintage {state} node state is empty"))?;
    let selected = values.swap_remove(selected);
    values.clear();
    values.push(selected);
    Ok(original_count)
}

fn collect_nodes(inner: &Value) -> Result<Vec<SocketAddrV4>> {
    let nodes = inner
        .get("nodes")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("Vintage lookup body has no nodes object"))?;
    let mut out = Vec::new();
    for values in nodes.values() {
        let Some(values) = values.as_array() else {
            continue;
        };
        for value in values {
            out.push(node_address(value)?);
        }
    }
    Ok(out)
}

fn node_address(value: &Value) -> Result<SocketAddrV4> {
    let host = value
        .get("host")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Vintage node has no string host field"))?;
    host.parse::<SocketAddrV4>()
        .with_context(|| format!("Vintage node host {host:?} is not IPv4:port"))
}

fn rewrite_nodes(inner: &mut Value, registered: &BTreeMap<Ipv4Addr, FakeDnsEntry>) -> Result<()> {
    let nodes = inner
        .get_mut("nodes")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("Vintage lookup body has no nodes object"))?;
    for values in nodes.values_mut() {
        let Some(values) = values.as_array_mut() else {
            continue;
        };
        for value in values {
            let host = value
                .get_mut("host")
                .ok_or_else(|| anyhow!("Vintage node has no host field"))?;
            let address = host
                .as_str()
                .ok_or_else(|| anyhow!("Vintage node host is not a string"))?
                .parse::<SocketAddrV4>()
                .context("Vintage node host is not IPv4:port")?;
            let entry = registered.get(address.ip()).ok_or_else(|| {
                anyhow!(
                    "Vintage node {} has no registered fake-IP route",
                    address.ip()
                )
            })?;
            *host = Value::String(format!("{}:{}", entry.fake_ip, address.port()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyper::{HeaderMap, Method, StatusCode, Uri};

    use super::*;

    fn input<'a>(uri: &'a Uri, body: &'a [u8]) -> RewriteInput<'a> {
        RewriteInput {
            method: &Method::GET,
            uri,
            authority: Some("static.config.api.demo.test"),
            status: StatusCode::OK,
            headers: Box::leak(Box::new(HeaderMap::new())),
            body,
        }
    }

    fn lookup_response(service: &str, cluster: &str) -> Vec<u8> {
        let inner = serde_json::json!({
            "service": service,
            "cluster": cluster,
            "sign": "abc",
            "nodes": {
                "working": [{"host": "10.145.1.107:8881", "extInfo": ""}]
            }
        });
        serde_json::to_vec(&serde_json::json!({"code": "200", "body": inner.to_string()})).unwrap()
    }

    #[test]
    fn leaves_getsign_unchanged() {
        let plugin = Naming::new(&[], &[]);
        let uri: Uri = "/naming/service?action=getsign&service=yf-rpc&cluster=user/service"
            .parse()
            .unwrap();

        assert!(matches!(
            plugin
                .rewrite(&input(&uri, br#"{"code":"200","body":"original-sign"}"#))
                .unwrap(),
            PluginResult::Unchanged
        ));
    }

    #[test]
    fn retains_one_deterministic_node_per_state_and_preserves_unknown_fields() {
        let plugin = Naming::new(&["yf-rpc".to_string()], &[]);
        let uri: Uri = "/naming/service?action=lookup&service=yf-rpc&cluster=user/service"
            .parse()
            .unwrap();
        let inner = serde_json::json!({
            "service": "yf-rpc",
            "cluster": "user/service",
            "sign": "abc",
            "nodes": {
                "working": [
                    {"host": "10.145.1.109:8881", "extInfo": "drop"},
                    {"host": "10.145.1.107:8882", "extInfo": "drop"},
                    {"host": "10.145.1.107:8881", "extInfo": "keep"}
                ],
                "unreachable": [
                    {"host": "10.145.1.110:8881", "extInfo": "drop"},
                    {"host": "10.145.1.108:8881", "extInfo": "keep"}
                ]
            },
            "futureField": {"keep": true}
        });
        let outer = serde_json::json!({"code": "200", "body": inner.to_string()});
        let bytes = serde_json::to_vec(&outer).unwrap();
        let PluginResult::Rewritten { body, targets, .. } =
            plugin.rewrite(&input(&uri, &bytes)).unwrap()
        else {
            panic!("expected rewrite");
        };
        assert_eq!(targets.len(), 2);
        let RewrittenBody::VintageNaming(plan) = *body else {
            panic!("expected Vintage plan");
        };
        let mut registered = BTreeMap::new();
        for (offset, target) in targets.iter().enumerate() {
            registered.insert(
                target.connect_ip,
                FakeDnsEntry {
                    domain: target.alias.clone(),
                    fake_ip: Ipv4Addr::new(198, 19, 0, (offset + 10) as u8),
                    real_ips: vec![target.connect_ip],
                    response_alias: true,
                    upstream_authority: None,
                    upstream_protocol: None,
                    first_seen: chrono::Utc::now(),
                    last_seen: chrono::Utc::now(),
                },
            );
        }

        let (body, discovered) = plan.render(&registered).unwrap();
        let outer: Value = serde_json::from_slice(&body).unwrap();
        let inner: Value = serde_json::from_str(outer["body"].as_str().unwrap()).unwrap();
        assert_eq!(inner["nodes"]["working"].as_array().unwrap().len(), 1);
        assert_eq!(inner["nodes"]["unreachable"].as_array().unwrap().len(), 1);
        assert_eq!(inner["nodes"]["working"][0]["host"], "198.19.0.10:8881");
        assert_eq!(inner["nodes"]["unreachable"][0]["host"], "198.19.0.11:8881");
        assert_eq!(inner["nodes"]["working"][0]["extInfo"], "keep");
        assert_eq!(inner["nodes"]["unreachable"][0]["extInfo"], "keep");
        assert_eq!(inner["futureField"]["keep"], true);
        assert_eq!(discovered.len(), 2);
    }

    #[test]
    fn leaves_unselected_service_unchanged() {
        let plugin = Naming::new(&["other".to_string()], &[]);
        let uri: Uri = "/naming/service?action=lookup&service=yf-rpc&cluster=user/service"
            .parse()
            .unwrap();
        let body = lookup_response("yf-rpc", "user/service");
        assert!(matches!(
            plugin.rewrite(&input(&uri, &body)).unwrap(),
            PluginResult::Unchanged
        ));
    }

    #[test]
    fn leaves_selected_application_error_unchanged() {
        let plugin = Naming::new(&["yf-rpc".to_string()], &[]);
        let uri: Uri = "/naming/service?action=lookup&service=yf-rpc&cluster=user/service"
            .parse()
            .unwrap();

        assert!(matches!(
            plugin
                .rewrite(&input(
                    &uri,
                    br#"{"code":"400","body":"{\"error_Code\":\"400\",\"error\":\"not found\",\"request\":\"/naming/service\"}"}"#,
                ))
                .unwrap(),
            PluginResult::Unchanged
        ));
    }

    #[test]
    fn rejects_malformed_success_response() {
        let plugin = Naming::new(&["yf-rpc".to_string()], &[]);
        let uri: Uri = "/naming/service?action=lookup&service=yf-rpc&cluster=user/service"
            .parse()
            .unwrap();

        let error = plugin
            .rewrite(&input(&uri, br#"{"code":"200","body":"not-json"}"#))
            .err()
            .expect("malformed successful response must fail");
        assert!(
            error
                .to_string()
                .contains("Vintage lookup body is not valid JSON")
        );
    }

    #[test]
    fn rejects_original_node_count_before_reduction() {
        let plugin = Naming::new(&[], &[]);
        let uri: Uri =
            "/naming/service?action=lookup&service=any-service&cluster=any-cluster/service"
                .parse()
                .unwrap();
        let working = (0..=MAX_DISCOVERED_NODES)
            .map(|index| {
                serde_json::json!({
                    "host": format!("10.0.0.1:{}", 10_000 + index),
                    "extInfo": ""
                })
            })
            .collect::<Vec<_>>();
        let inner = serde_json::json!({
            "service": "any-service",
            "cluster": "any-cluster/service",
            "sign": "abc",
            "nodes": {"working": working, "unreachable": []}
        });
        let body = serde_json::to_vec(&serde_json::json!({
            "code": "200",
            "body": inner.to_string()
        }))
        .unwrap();

        let error = plugin
            .rewrite(&input(&uri, &body))
            .err()
            .expect("oversized original node set must fail");

        assert!(error.to_string().contains("exceeding limit 4096"));
    }

    #[test]
    fn empty_filters_match_every_service_and_cluster() {
        let plugin = Naming::new(&[], &[]);
        let uri: Uri =
            "/naming/service?action=lookup&service=any-service&cluster=any-cluster/service"
                .parse()
                .unwrap();
        let body = lookup_response("any-service", "any-cluster/service");

        assert!(matches!(
            plugin.rewrite(&input(&uri, &body)).unwrap(),
            PluginResult::Rewritten { .. }
        ));
    }
}
