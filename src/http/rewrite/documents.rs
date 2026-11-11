//! Adapt pure document plans to framework-owned route registration.
use super::*;
use crate::dns_mock::FakeDnsEntry;
use traffic_response_rewrite::{
    CompiledRewrite, DocumentRule, ProtocolHint, RewriteBudget, RewritePlan,
};

pub(super) struct Documents(CompiledRewrite);

impl Documents {
    pub fn new(rules: &[DocumentRule]) -> Result<Self> {
        Ok(Self(CompiledRewrite::compile(rules)?))
    }
}

impl Plugin for Documents {
    fn name(&self) -> &'static str {
        "documents"
    }

    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult> {
        let Some(plan) =
            self.0
                .inspect_with_query(input.body, RewriteBudget::default(), input.uri.query())?
        else {
            return Ok(PluginResult::Unchanged);
        };
        let targets = plan
            .endpoints()
            .map(|endpoint| DiscoveredTarget {
                alias: endpoint.alias.clone(),
                connect_ip: endpoint.upstream_ip,
                upstream_authority: endpoint.upstream_authority.clone(),
                upstream_protocol: match endpoint.protocol {
                    ProtocolHint::Http if endpoint.upstream_authority.is_some() => {
                        Some(FakeDnsUpstreamProtocol::Http)
                    }
                    ProtocolHint::Https if endpoint.upstream_authority.is_some() => {
                        Some(FakeDnsUpstreamProtocol::Https)
                    }
                    _ => None,
                },
            })
            .collect();
        Ok(PluginResult::Rewritten {
            body: Box::new(RewrittenBody::Documents(plan)),
            targets,
            kubectl_proxy: None,
        })
    }
}

pub(super) fn render(
    plan: RewritePlan,
    registered: &BTreeMap<String, FakeDnsEntry>,
) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)> {
    let targets = plan
        .endpoints()
        .map(|endpoint| {
            let entry = registered
                .get(&endpoint.alias)
                .context("response endpoint has no registered fake route")?;
            Ok(DiscoveredTcpTarget {
                protocol: endpoint.protocol.as_str().into(),
                alias: endpoint.alias.clone(),
                advertised_ip: entry.fake_ip,
                upstream_ip: endpoint.upstream_ip,
                port: endpoint.port,
                service: None,
                cluster: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let routes = registered
        .iter()
        .map(|(alias, entry)| (alias.clone(), entry.fake_ip))
        .collect();
    Ok((plan.materialize(&routes)?, targets))
}
