use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping, Value as YamlValue};
use tracing::debug;

use crate::dependency::DiscoveredTcpTarget;
use crate::dns_mock::FakeDnsEntry;

use super::super::{DiscoveredTarget, Plugin, PluginResult, RewriteInput, RewrittenBody};
use super::{alias_for_ip, application_error_code, parse_outer, query, required_query};

const PLUGIN_NAME: &str = "vintage-cache-config";
const MAX_DISCOVERED_ENDPOINTS: usize = 4096;
const ENDPOINT_FIELDS: [&str; 4] = ["master", "slave", "master_l1", "slave_l1"];
const L1_GROUP_FIELDS: [&str; 2] = ["master_l1", "slave_l1"];

pub(in crate::http::rewrite) struct CacheConfig;

impl Plugin for CacheConfig {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult> {
        let query = query(input);
        let action = required_query(&query, "action")?;
        if action != "lookup" {
            return Ok(PluginResult::Unchanged);
        }
        let group = required_query(&query, "group")?;
        let plan = match ResponsePlan::parse(input.body, group)? {
            ParsedResponse::Success(Some(plan)) => plan,
            ParsedResponse::Success(None) => return Ok(PluginResult::Unchanged),
            ParsedResponse::ApplicationError { code } => {
                debug!(
                    plugin = PLUGIN_NAME,
                    authority = input.authority.unwrap_or_default(),
                    group,
                    application_code = %code,
                    response_body_bytes = input.body.len(),
                    "left Vintage config application error response unchanged"
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
            body: Box::new(RewrittenBody::VintageCacheConfig(plan)),
            targets,
            kubectl_proxy: None,
        })
    }
}

enum ParsedResponse {
    Success(Option<ResponsePlan>),
    ApplicationError { code: String },
}

struct ConfigDocument {
    node_index: usize,
    value: YamlValue,
}

pub(in crate::http::rewrite) struct ResponsePlan {
    outer: JsonValue,
    documents: Vec<ConfigDocument>,
    endpoints: BTreeSet<SocketAddrV4>,
    group: String,
}

impl ResponsePlan {
    fn parse(body: &[u8], requested_group: &str) -> Result<ParsedResponse> {
        let outer = parse_outer(body)?;
        if let Some(code) = application_error_code(&outer)? {
            return Ok(ParsedResponse::ApplicationError { code });
        }
        let Some(response_body) = outer.get("body").and_then(JsonValue::as_object) else {
            return Ok(ParsedResponse::Success(None));
        };
        if let Some(group) = response_body.get("groupId").and_then(JsonValue::as_str)
            && group != requested_group
        {
            bail!(
                "Vintage config response groupId {group:?} does not match request group {requested_group:?}"
            );
        }
        let Some(nodes) = response_body.get("nodes").and_then(JsonValue::as_array) else {
            return Ok(ParsedResponse::Success(None));
        };

        let mut documents = Vec::with_capacity(nodes.len());
        let mut endpoints = BTreeSet::new();
        let mut deferred_error = None;
        let mut endpoint_count = 0;
        let mut limited_l1_groups = false;
        for (node_index, node) in nodes.iter().enumerate() {
            let Some(config) = node.get("value").and_then(JsonValue::as_str) else {
                deferred_error.get_or_insert_with(|| {
                    anyhow!("Vintage config node {node_index} has no string value field")
                });
                continue;
            };
            let mut value = match serde_yaml::from_str(config)
                .with_context(|| format!("Vintage config node {node_index} value is not YAML"))
            {
                Ok(value) => value,
                Err(error) => {
                    deferred_error.get_or_insert(error);
                    continue;
                }
            };
            limited_l1_groups |= retain_first_l1_groups(&mut value);
            collect_document_endpoints(&value, &mut endpoints, &mut endpoint_count)
                .with_context(|| format!("failed to inspect Vintage config node {node_index}"))?;
            documents.push(ConfigDocument { node_index, value });
        }

        if endpoints.is_empty() && !limited_l1_groups {
            return Ok(ParsedResponse::Success(None));
        }
        if let Some(error) = deferred_error {
            return Err(error).context("Vintage cache config contains an unparseable sibling node");
        }
        Ok(ParsedResponse::Success(Some(Self {
            outer,
            documents,
            endpoints,
            group: requested_group.to_string(),
        })))
    }

    fn upstream_ips(&self) -> BTreeSet<Ipv4Addr> {
        self.endpoints.iter().map(|address| *address.ip()).collect()
    }

    pub(in crate::http::rewrite) fn render(
        mut self,
        registered: &BTreeMap<Ipv4Addr, FakeDnsEntry>,
    ) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)> {
        let nodes = self
            .outer
            .get_mut("body")
            .and_then(JsonValue::as_object_mut)
            .and_then(|body| body.get_mut("nodes"))
            .and_then(JsonValue::as_array_mut)
            .ok_or_else(|| anyhow!("Vintage cache config response lost its nodes array"))?;
        for mut document in self.documents {
            rewrite_document_endpoints(&mut document.value, registered).with_context(|| {
                format!(
                    "failed to rewrite Vintage config node {}",
                    document.node_index
                )
            })?;
            let rendered = serde_yaml::to_string(&document.value)
                .context("failed to serialize rewritten Vintage cache config")?;
            nodes
                .get_mut(document.node_index)
                .and_then(JsonValue::as_object_mut)
                .ok_or_else(|| {
                    anyhow!(
                        "Vintage cache config node {} disappeared",
                        document.node_index
                    )
                })?
                .insert("value".to_string(), JsonValue::String(rendered));
        }

        let discovered = self
            .endpoints
            .into_iter()
            .map(|address| {
                let entry = registered.get(address.ip()).ok_or_else(|| {
                    anyhow!(
                        "Vintage cache endpoint {} has no registered fake-IP route",
                        address
                    )
                })?;
                Ok(DiscoveredTcpTarget {
                    protocol: "auto".to_string(),
                    alias: entry.domain.clone(),
                    advertised_ip: entry.fake_ip,
                    upstream_ip: *address.ip(),
                    port: address.port(),
                    service: Some(self.group.clone()),
                    cluster: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let body = serde_json::to_vec(&self.outer)
            .context("failed to serialize rewritten Vintage config response")?;
        Ok((body, discovered))
    }
}

fn retain_first_l1_groups(document: &mut YamlValue) -> bool {
    let Some(resources) = document.as_mapping_mut() else {
        return false;
    };
    let mut limited = false;
    for resource in resources.values_mut() {
        let Some(resource) = resource.as_mapping_mut() else {
            continue;
        };
        for field in L1_GROUP_FIELDS {
            let Some(YamlValue::Sequence(groups)) = mapping_value_mut(resource, field) else {
                continue;
            };
            if groups.len() > 1 && groups.first().is_some_and(is_nested_group) {
                groups.truncate(1);
                limited = true;
            }
        }
    }
    limited
}

fn is_nested_group(value: &YamlValue) -> bool {
    match value {
        YamlValue::Sequence(_) | YamlValue::Mapping(_) => true,
        YamlValue::Tagged(value) => is_nested_group(&value.value),
        YamlValue::Null | YamlValue::Bool(_) | YamlValue::Number(_) | YamlValue::String(_) => false,
    }
}

fn collect_document_endpoints(
    document: &YamlValue,
    endpoints: &mut BTreeSet<SocketAddrV4>,
    endpoint_count: &mut usize,
) -> Result<()> {
    let Some(resources) = document.as_mapping() else {
        return Ok(());
    };
    for (resource_name, resource) in resources {
        let Some(resource) = resource.as_mapping() else {
            continue;
        };
        let resource_name = yaml_label(resource_name);
        for field in ENDPOINT_FIELDS {
            let Some(value) = mapping_value(resource, field) else {
                continue;
            };
            collect_socket_addresses(value, endpoints, endpoint_count).with_context(|| {
                format!("Vintage cache resource {resource_name:?} field {field:?} is invalid")
            })?;
        }
    }
    Ok(())
}

fn rewrite_document_endpoints(
    document: &mut YamlValue,
    registered: &BTreeMap<Ipv4Addr, FakeDnsEntry>,
) -> Result<()> {
    let Some(resources) = document.as_mapping_mut() else {
        return Ok(());
    };
    for (resource_name, resource) in resources {
        let Some(resource) = resource.as_mapping_mut() else {
            continue;
        };
        let resource_name = yaml_label(resource_name);
        for field in ENDPOINT_FIELDS {
            let Some(value) = mapping_value_mut(resource, field) else {
                continue;
            };
            rewrite_socket_scalars(value, registered).with_context(|| {
                format!("Vintage cache resource {resource_name:?} field {field:?} is invalid")
            })?;
        }
    }
    Ok(())
}

fn collect_socket_addresses(
    value: &YamlValue,
    addresses: &mut BTreeSet<SocketAddrV4>,
    endpoint_count: &mut usize,
) -> Result<()> {
    match value {
        YamlValue::Sequence(values) => {
            for value in values {
                collect_socket_addresses(value, addresses, endpoint_count)?;
            }
        }
        YamlValue::Mapping(values) => {
            for value in values.values() {
                collect_socket_addresses(value, addresses, endpoint_count)?;
            }
        }
        YamlValue::Tagged(value) => {
            collect_socket_addresses(&value.value, addresses, endpoint_count)?;
        }
        YamlValue::String(value) => {
            if let Ok(address) = value.parse::<SocketAddrV4>() {
                *endpoint_count += 1;
                if *endpoint_count > MAX_DISCOVERED_ENDPOINTS {
                    bail!(
                        "Vintage cache config has more than {} endpoints",
                        MAX_DISCOVERED_ENDPOINTS
                    );
                }
                addresses.insert(address);
            }
        }
        YamlValue::Null | YamlValue::Bool(_) | YamlValue::Number(_) => {}
    }
    Ok(())
}

fn rewrite_socket_scalars(
    value: &mut YamlValue,
    registered: &BTreeMap<Ipv4Addr, FakeDnsEntry>,
) -> Result<()> {
    match value {
        YamlValue::Sequence(values) => {
            for value in values {
                rewrite_socket_scalars(value, registered)?;
            }
        }
        YamlValue::Mapping(values) => {
            for value in values.values_mut() {
                rewrite_socket_scalars(value, registered)?;
            }
        }
        YamlValue::Tagged(value) => {
            rewrite_socket_scalars(&mut value.value, registered)?;
        }
        YamlValue::String(value) => {
            if let Ok(address) = value.parse::<SocketAddrV4>() {
                let entry = registered.get(address.ip()).ok_or_else(|| {
                    anyhow!(
                        "Vintage cache endpoint {} has no registered fake-IP route",
                        address
                    )
                })?;
                *value = format!("{}:{}", entry.fake_ip, address.port());
            }
        }
        YamlValue::Null | YamlValue::Bool(_) | YamlValue::Number(_) => {}
    }
    Ok(())
}

fn mapping_value<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a YamlValue> {
    mapping.get(YamlValue::String(key.to_string()))
}

fn mapping_value_mut<'a>(mapping: &'a mut Mapping, key: &str) -> Option<&'a mut YamlValue> {
    mapping.get_mut(YamlValue::String(key.to_string()))
}

fn yaml_label(value: &YamlValue) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{value:?}"))
}

#[cfg(test)]
mod tests {
    use hyper::{HeaderMap, Method, StatusCode, Uri};

    use super::*;

    fn input<'a>(uri: &'a Uri, body: &'a [u8]) -> RewriteInput<'a> {
        RewriteInput {
            method: &Method::GET,
            uri,
            authority: Some("config.api.demo.test"),
            status: StatusCode::OK,
            headers: Box::leak(Box::new(HeaderMap::new())),
            body,
        }
    }

    fn response(config: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "code": 200,
            "body": {
                "groupId": "cache.service.test",
                "sign": "keep",
                "nodes": [{"key": "all", "value": config}]
            },
            "future": {"keep": true}
        }))
        .unwrap()
    }

    fn registered(targets: &[DiscoveredTarget]) -> BTreeMap<Ipv4Addr, FakeDnsEntry> {
        targets
            .iter()
            .enumerate()
            .map(|(offset, target)| {
                (
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
                )
            })
            .collect()
    }

    fn sequence_len(value: &YamlValue) -> usize {
        value.as_sequence().unwrap().len()
    }

    #[test]
    fn rewrites_flat_and_nested_cache_endpoint_fields() {
        let plugin = CacheConfig;
        let uri: Uri = "/1/config/service?action=lookup&group=cache.service.test"
            .parse()
            .unwrap();
        let body = response(
            r#"
mem:
  redis: false
  master:
    - 10.0.0.1:3120
  slave_l1:
    -
      - 10.0.0.2:3120
redis-cache:
  redis: true
  slave:
    - 10.0.0.3:6379
  master_l1:
    -
      - 10.0.0.4:6379
global:
  lru_max_memory: 100
"#,
        );
        let PluginResult::Rewritten { body, targets, .. } =
            plugin.rewrite(&input(&uri, &body)).unwrap()
        else {
            panic!("expected rewrite");
        };
        assert_eq!(targets.len(), 4);
        let RewrittenBody::VintageCacheConfig(plan) = *body else {
            panic!("expected Vintage cache config plan");
        };

        let (body, discovered) = plan.render(&registered(&targets)).unwrap();
        let outer: JsonValue = serde_json::from_slice(&body).unwrap();
        let config = outer["body"]["nodes"][0]["value"].as_str().unwrap();
        let config: YamlValue = serde_yaml::from_str(config).unwrap();
        assert_eq!(
            config["mem"]["master"][0],
            YamlValue::String("198.19.0.10:3120".to_string())
        );
        assert_eq!(
            config["mem"]["slave_l1"][0][0],
            YamlValue::String("198.19.0.11:3120".to_string())
        );
        assert_eq!(
            config["redis-cache"]["slave"][0],
            YamlValue::String("198.19.0.12:6379".to_string())
        );
        assert_eq!(
            config["redis-cache"]["master_l1"][0][0],
            YamlValue::String("198.19.0.13:6379".to_string())
        );
        assert_eq!(config["global"]["lru_max_memory"], 100);
        assert_eq!(outer["future"]["keep"], true);
        assert!(discovered.iter().all(|target| target.protocol == "auto"));
    }

    #[test]
    fn leaves_other_config_shapes_unchanged() {
        let plugin = CacheConfig;
        let uri: Uri = "/1/config/service?action=lookup&group=rpc-group-command"
            .parse()
            .unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "code": "200",
            "body": {
                "groupId": "rpc-group-command",
                "nodes": [{"key": "api", "value": "command: keep"}]
            }
        }))
        .unwrap();

        assert!(matches!(
            plugin.rewrite(&input(&uri, &body)).unwrap(),
            PluginResult::Unchanged
        ));
    }

    #[test]
    fn leaves_socket_values_outside_cache_endpoint_fields_unchanged() {
        let plugin = CacheConfig;
        let uri: Uri = "/1/config/service?action=lookup&group=cache.service.test"
            .parse()
            .unwrap();
        let body = response(
            r#"
mem:
  redis: false
  master: [10.0.0.1:3120]
  future_endpoint: 10.0.0.9:3120
"#,
        );
        let PluginResult::Rewritten { body, targets, .. } =
            plugin.rewrite(&input(&uri, &body)).unwrap()
        else {
            panic!("expected rewrite");
        };
        let RewrittenBody::VintageCacheConfig(plan) = *body else {
            panic!("expected Vintage cache config plan");
        };
        let (body, _) = plan.render(&registered(&targets)).unwrap();
        let outer: JsonValue = serde_json::from_slice(&body).unwrap();
        let config: YamlValue =
            serde_yaml::from_str(outer["body"]["nodes"][0]["value"].as_str().unwrap()).unwrap();
        assert_eq!(config["mem"]["future_endpoint"], "10.0.0.9:3120");
    }

    #[test]
    fn retains_only_the_first_nested_l1_group() {
        let plugin = CacheConfig;
        let uri: Uri = "/1/config/service?action=lookup&group=cache.service.test"
            .parse()
            .unwrap();
        let body = response(
            r#"
cache:
  master: [10.0.0.1:3120, 10.0.0.2:3120]
  slave: [10.0.0.3:3120, 10.0.0.4:3120]
  master_l1:
    - [10.0.1.1:3120, 10.0.1.2:3120]
    - [10.0.2.1:3120]
  slave_l1:
    - [10.0.3.1:3120]
    - [10.0.4.1:3120]
flat-cache:
  master_l1: [10.0.7.1:3120, 10.0.7.2:3120]
"#,
        );
        let PluginResult::Rewritten { body, targets, .. } =
            plugin.rewrite(&input(&uri, &body)).unwrap()
        else {
            panic!("expected rewrite");
        };

        for dropped in ["10.0.2.1", "10.0.4.1"] {
            let dropped = dropped.parse::<Ipv4Addr>().unwrap();
            assert!(
                targets.iter().all(|target| target.connect_ip != dropped),
                "dropped L1 group endpoint must not be discovered"
            );
        }
        assert_eq!(targets.len(), 9);

        let RewrittenBody::VintageCacheConfig(plan) = *body else {
            panic!("expected Vintage cache config plan");
        };
        let (body, _) = plan.render(&registered(&targets)).unwrap();
        let outer: JsonValue = serde_json::from_slice(&body).unwrap();
        let config: YamlValue =
            serde_yaml::from_str(outer["body"]["nodes"][0]["value"].as_str().unwrap()).unwrap();

        assert_eq!(sequence_len(&config["cache"]["master"]), 2);
        assert_eq!(sequence_len(&config["cache"]["slave"]), 2);
        assert_eq!(sequence_len(&config["cache"]["master_l1"]), 1);
        assert_eq!(sequence_len(&config["cache"]["master_l1"][0]), 2);
        assert_eq!(sequence_len(&config["cache"]["slave_l1"]), 1);
        assert_eq!(sequence_len(&config["flat-cache"]["master_l1"]), 2);
    }
}
