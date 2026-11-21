//! Adapt registered transformations to the host network-route capability.
use super::*;
use crate::dns_mock::FakeDnsEntry;
use anyhow::ensure;
use serde::Deserialize;
use traffic_policy::PreparedTransform;
use traffic_policy_value::transformation::Transformation;

pub(super) struct RegisteredRewrite(PreparedTransform);
impl RegisteredRewrite {
    pub fn from_definition(definition: &traffic_policy::PolicyDefinition) -> Result<Self> {
        Ok(Self(
            traffic_extensions::policies().prepare_transform_definition(definition)?,
        ))
    }
    pub fn new(id: &str, configuration: &traffic_value::Value) -> Result<Self> {
        Ok(Self(
            traffic_extensions::policies().prepare_transform(id, configuration)?,
        ))
    }
}
impl Plugin for RegisteredRewrite {
    fn name(&self) -> &'static str {
        self.0.descriptor().id
    }
    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult> {
        let context = serde_json::from_value(serde_json::json!({"query":input.uri.query()}))?;
        let Some(plan) = Transformation::inspect(
            &self.0,
            input.body,
            &context,
            &traffic_value::Value::Null,
            traffic_extensions::codecs(),
        )?
        else {
            return Ok(PluginResult::Unchanged);
        };
        let routes = plan
            .requests()
            .iter()
            .map(|request| {
                ensure!(
                    request.capability == "network.route",
                    "recording capability {:?} is not installed",
                    request.capability
                );
                let route: NetworkRoute =
                    serde_json::from_value(serde_json::to_value(&request.parameters)?)?;
                ensure!(
                    route.alias == request.id && route.port != 0,
                    "network route request identity or port changed"
                );
                Ok(route)
            })
            .collect::<Result<Vec<_>>>()?;
        let targets = routes
            .iter()
            .map(|route| DiscoveredTarget {
                alias: route.alias.clone(),
                connect_ip: route.upstream_ip,
                upstream_authority: route.upstream_authority.clone(),
                upstream_protocol: match route.protocol.as_str() {
                    "http" if route.upstream_authority.is_some() => {
                        Some(FakeDnsUpstreamProtocol::Http)
                    }
                    "https" if route.upstream_authority.is_some() => {
                        Some(FakeDnsUpstreamProtocol::Https)
                    }
                    _ => None,
                },
            })
            .collect();
        Ok(PluginResult::Rewritten {
            body: Box::new(RegisteredBody { plan, routes }),
            targets,
            kubectl_proxy: None,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkRoute {
    alias: String,
    upstream_ip: Ipv4Addr,
    port: u16,
    protocol: String,
    upstream_authority: Option<String>,
}
struct RegisteredBody {
    plan: Transformation,
    routes: Vec<NetworkRoute>,
}
impl ResponseBody for RegisteredBody {
    fn materialize(
        self: Box<Self>,
        registered: &BTreeMap<String, FakeDnsEntry>,
    ) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)> {
        let resources = self
            .routes
            .iter()
            .map(|route| {
                let entry = registered
                    .get(&route.alias)
                    .context("transformation route has no registered address")?;
                Ok((
                    route.alias.clone(),
                    serde_json::from_value(
                        serde_json::json!({"advertised_ip":entry.fake_ip.to_string()}),
                    )?,
                ))
            })
            .collect::<Result<_>>()?;
        let targets = self
            .routes
            .iter()
            .map(|route| {
                let entry = registered
                    .get(&route.alias)
                    .context("transformation route has no registered address")?;
                Ok(DiscoveredTcpTarget {
                    protocol: route.protocol.clone(),
                    alias: route.alias.clone(),
                    advertised_ip: entry.fake_ip,
                    upstream_ip: route.upstream_ip,
                    port: route.port,
                    service: None,
                    cluster: None,
                })
            })
            .collect::<Result<_>>()?;
        Ok((self.plan.materialize(&resources)?, targets))
    }
}
