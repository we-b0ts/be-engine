//! Format eligibility is distinct from actual field selection and decoding.
use super::*;
use crate::policy::GlobalField;
use crate::replay::execution_plan::PreparedFormat;
use crate::value_contract::plan::IndexRequirement;

#[derive(Debug)]
pub(super) struct FormatRequirement {
    name: &'static str,
    protocol: Option<ProtocolKind>,
    fields: usize,
    semantics: BTreeSet<String>,
}

fn kind(field: &GlobalField) -> &str {
    match field {
        GlobalField::Policy(definition) => &definition.id,
        GlobalField::Time { .. } => "time",
        GlobalField::Identity { .. } => "identity",
        GlobalField::Duration { .. } => "duration",
        GlobalField::Url { .. } => "url",
        GlobalField::Template { .. } => "template",
        GlobalField::Jwt { .. } => "jwt",
        GlobalField::Unordered => "unordered",
    }
}

pub(super) fn compile(policy: &crate::policy::CompiledPolicy) -> Vec<FormatRequirement> {
    let mut requirements = Vec::new();
    let mut add = |name, protocol, fields: Vec<&GlobalField>| {
        if !fields.is_empty() {
            requirements.push(FormatRequirement {
                name,
                protocol,
                fields: fields.len(),
                semantics: fields
                    .into_iter()
                    .map(|field| kind(field).to_owned())
                    .collect(),
            });
        }
    };
    if let Some(global) = &policy.global_json {
        add("global.json", None, global.fields.values().collect());
    }
    if let Some(mysql) = &policy.mysql {
        add(
            "global.mysql",
            Some(ProtocolKind::Mysql),
            mysql
                .tables
                .values()
                .flat_map(|table| table.fields.values())
                .collect(),
        );
    }
    if let Some(redis) = &policy.redis {
        add(
            "global.redis",
            Some(ProtocolKind::Redis),
            redis
                .keys
                .values()
                .chain(redis.key_identities.values())
                .collect(),
        );
    }
    if let Some(http) = &policy.http {
        add(
            "global.http",
            Some(ProtocolKind::Http),
            http.headers.values().collect(),
        );
    }
    requirements
}

impl RuleCatalogue {
    pub(super) fn prepare_formats(
        &self,
        result: &mut PreparedCaseRules,
        primary: Option<ProtocolKind>,
        facts: Option<&BTreeSet<SourceFact>>,
        pre_match: bool,
    ) {
        let dependencies = facts
            .into_iter()
            .flatten()
            .map(|fact| fact.protocol)
            .collect::<BTreeSet<_>>();
        for requirement in &self.formats {
            let mut protocols = dependencies
                .iter()
                .copied()
                .filter(|protocol| match requirement.protocol {
                    Some(selected) => *protocol == selected,
                    None => matches!(
                        protocol,
                        ProtocolKind::Http
                            | ProtocolKind::Redis
                            | ProtocolKind::Mysql
                            | ProtocolKind::Memcached
                    ),
                })
                .collect::<BTreeSet<_>>();
            // Primary assertions have their own native semantic projection,
            // including Motan. This does not authorize generic Motan value slots.
            if let Some(primary) = primary.filter(|primary| {
                requirement
                    .protocol
                    .is_none_or(|selected| selected == *primary)
            }) {
                protocols.insert(primary);
            }
            if protocols.is_empty() {
                continue;
            }
            result.formats.push(PreparedFormat {
                format: requirement.name,
                declared_fields: requirement.fields,
                eligible_protocols: protocols.into_iter().collect(),
                semantic_kinds: requirement.semantics.clone(),
            });
            result
                .requirements
                .required
                .extend([IndexRequirement::Scope, IndexRequirement::TypedSlot]);
            if requirement
                .semantics
                .iter()
                .any(|kind| matches!(kind.as_str(), "identity" | "jwt" | "url" | "template"))
            {
                result
                    .requirements
                    .required
                    .insert(IndexRequirement::SemanticLink);
            }
            result.evidence.source_record = true;
            result.evidence.independent_target = true;
            result.evidence.protected_values = true;
            result.evidence.native_delivery |= !dependencies.is_empty();
        }
        if pre_match {
            for protocol in dependencies {
                if matches!(
                    protocol,
                    ProtocolKind::Http | ProtocolKind::Redis | ProtocolKind::Mysql
                ) {
                    result.pre_match_protocols.push(protocol);
                } else {
                    result.unsupported_pre_match_protocols.push(protocol);
                }
            }
            if !result.pre_match_protocols.is_empty() {
                result.requirements.required.extend([
                    IndexRequirement::Scope,
                    IndexRequirement::EndpointOperation,
                    IndexRequirement::TypedSlot,
                    IndexRequirement::SemanticLink,
                ]);
                result.evidence.source_record = true;
                result.evidence.independent_target = true;
                result.evidence.protected_values = true;
                result.evidence.all_hypothesis_attempts = true;
            }
        }
    }
}
