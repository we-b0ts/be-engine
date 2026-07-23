use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use url::form_urlencoded;

use crate::dependency::DiscoveredTcpTarget;
use crate::dns_mock::FakeDnsEntry;

use super::{DiscoveredTarget, Plugin, PluginResult, RewriteInput, RewrittenBody};

const PLUGIN_NAME: &str = "vintage-naming";
const MAX_DISCOVERED_NODES: usize = 4096;

pub(super) struct Naming {
    services: BTreeSet<String>,
    clusters: BTreeSet<String>,
}

impl Naming {
    pub(super) fn new(services: &[String], clusters: &[String]) -> Self {
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
        let query = query(input)?;
        let action = required_query(&query, "action")?;
        let service = required_query(&query, "service")?;
        let cluster = required_query(&query, "cluster")?;
        if !self.selected(service, cluster) {
            return Ok(PluginResult::Unchanged);
        }

        match action {
            "lookup" | "lookupforupdate" => {
                let plan = ResponsePlan::parse(input.body, service, cluster)?;
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
                    body: Box::new(RewrittenBody::Vintage(plan)),
                    targets,
                    kubectl_proxy: None,
                })
            }
            _ => Ok(PluginResult::Unchanged),
        }
    }
}

pub(super) struct ResponsePlan {
    outer: Value,
    inner: Value,
    service: String,
    cluster: String,
    nodes: Vec<SocketAddrV4>,
}

impl ResponsePlan {
    fn parse(body: &[u8], service: &str, cluster: &str) -> Result<Self> {
        let outer = parse_outer(body)?;
        ensure_success(&outer)?;
        let inner_text = outer
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Vintage lookup response has no string body field"))?;
        let inner: Value =
            serde_json::from_str(inner_text).context("Vintage lookup body is not valid JSON")?;
        if inner.get("service").and_then(Value::as_str) != Some(service)
            || inner.get("cluster").and_then(Value::as_str) != Some(cluster)
        {
            bail!(
                "Vintage lookup response identity does not match request service={service:?} cluster={cluster:?}"
            );
        }
        let nodes = collect_nodes(&inner)?;
        if nodes.len() > MAX_DISCOVERED_NODES {
            bail!(
                "Vintage lookup response has {} nodes, exceeding limit {}",
                nodes.len(),
                MAX_DISCOVERED_NODES
            );
        }
        Ok(Self {
            outer,
            inner,
            service: service.to_string(),
            cluster: cluster.to_string(),
            nodes,
        })
    }

    pub(super) fn upstream_ips(&self) -> BTreeSet<Ipv4Addr> {
        self.nodes.iter().map(|node| *node.ip()).collect()
    }

    pub(super) fn render(
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

fn query(input: &RewriteInput<'_>) -> Result<BTreeMap<String, String>> {
    Ok(
        form_urlencoded::parse(input.uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect(),
    )
}

fn required_query<'a>(query: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    query
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Vintage naming request has no {name} query parameter"))
}

fn parse_outer(body: &[u8]) -> Result<Value> {
    let outer: Value =
        serde_json::from_slice(body).context("Vintage response body is not valid JSON")?;
    if !outer.is_object() {
        bail!("Vintage response root is not an object");
    }
    Ok(outer)
}

fn ensure_success(outer: &Value) -> Result<()> {
    if matches!(outer.get("code"), Some(Value::String(code)) if code == "200")
        || matches!(outer.get("code"), Some(Value::Number(code)) if code.as_u64() == Some(200))
    {
        return Ok(());
    }
    bail!("Vintage response application code is not 200")
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
            let host = value
                .get("host")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Vintage node has no string host field"))?;
            out.push(
                host.parse::<SocketAddrV4>()
                    .with_context(|| format!("Vintage node host {host:?} is not IPv4:port"))?,
            );
        }
    }
    Ok(out)
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

fn alias_for_ip(ip: Ipv4Addr) -> String {
    format!("vintage-node-{}.trp.test", ip.to_string().replace('.', "-"))
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
    fn rewrites_all_node_sets_and_preserves_unknown_fields() {
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
                    {"host": "10.145.1.107:8881", "extInfo": "keep"},
                    {"host": "10.145.1.107:8882", "extInfo": ""}
                ],
                "unreachable": [{"host": "10.145.1.108:8881", "extInfo": ""}]
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
        let RewrittenBody::Vintage(plan) = *body else {
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
        assert_eq!(inner["nodes"]["working"][0]["host"], "198.19.0.10:8881");
        assert_eq!(inner["nodes"]["working"][1]["host"], "198.19.0.10:8882");
        assert_eq!(inner["nodes"]["unreachable"][0]["host"], "198.19.0.11:8881");
        assert_eq!(inner["nodes"]["working"][0]["extInfo"], "keep");
        assert_eq!(inner["futureField"]["keep"], true);
        assert_eq!(discovered.len(), 3);
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
    fn rejects_selected_application_error_instead_of_rewriting_it() {
        let plugin = Naming::new(&["yf-rpc".to_string()], &[]);
        let uri: Uri = "/naming/service?action=lookup&service=yf-rpc&cluster=user/service"
            .parse()
            .unwrap();

        let error = match plugin.rewrite(&input(
            &uri,
            br#"{"code":"400","body":"{\"error\":\"not found\"}"}"#,
        )) {
            Ok(_) => panic!("expected Vintage application error"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("application code is not 200"));
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
