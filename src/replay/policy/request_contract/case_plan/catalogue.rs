//! Compile API postings once; Case preparation never clones authored schemas.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RuleRef {
    Value(usize),
    Native(usize),
}

type ResourceEndpoint = (ProtocolKind, String, u16);
type OperationPostings = BTreeMap<Option<String>, Vec<RuleRef>>;

#[derive(Debug, Default)]
pub(in crate::replay::policy::request_contract) struct RuleCatalogue {
    any: Vec<RuleRef>,
    exact: BTreeMap<(String, String), Vec<RuleRef>>,
    patterns: BTreeMap<String, BTreeMap<String, Vec<RuleRef>>>,
    pub(super) formats: Vec<super::formats::FormatRequirement>,
    resources: BTreeMap<ResourceEndpoint, OperationPostings>,
    protocols: BTreeMap<ProtocolKind, Vec<RuleRef>>,
    unbound: Vec<RuleRef>,
}

impl RuleCatalogue {
    pub(in crate::replay::policy::request_contract) fn new(
        policy: &crate::policy::CompiledPolicy,
    ) -> Self {
        let mut catalogue = Self {
            formats: super::formats::compile(policy),
            ..Self::default()
        };
        for (index, rule) in policy.rules.iter().enumerate() {
            catalogue.insert(rule.rule.selector.api.as_deref(), RuleRef::Value(index));
            catalogue.bind(
                RuleRef::Value(index),
                &rule.execution_plan,
                rule.rule.selector.resource.as_ref(),
                rule.rule.selector.operation.as_deref(),
            );
        }
        for (index, rule) in policy.native.iter().enumerate() {
            catalogue.insert(rule.rule.selector.api.as_deref(), RuleRef::Native(index));
            catalogue.bind(
                RuleRef::Native(index),
                &rule.execution_plan,
                rule.rule.selector.resource.as_ref(),
                rule.rule.selector.operation.as_deref(),
            );
        }
        catalogue
    }

    fn insert(&mut self, api: Option<&str>, rule: RuleRef) {
        let Some((method, path)) = api.and_then(|api| api.split_once(' ')) else {
            self.any.push(rule);
            return;
        };
        if path.contains(['*', '?']) {
            self.patterns
                .entry(method.into())
                .or_default()
                .entry(path.into())
                .or_default()
                .push(rule);
        } else {
            self.exact
                .entry((method.into(), path.into()))
                .or_default()
                .push(rule);
        }
    }

    fn bind(
        &mut self,
        position: RuleRef,
        plan: &crate::value_contract::plan::RuleExecutionPlan,
        resource: Option<&crate::policy::Resource>,
        operation: Option<&str>,
    ) {
        if plan.role != Some(ProtocolRole::Dependency) {
            self.unbound.push(position);
        } else if let Some(resource) = resource {
            self.resources
                .entry((
                    resource.protocol.into(),
                    crate::replay::normalize_host(&resource.endpoint.host),
                    resource.endpoint.port,
                ))
                .or_default()
                .entry(operation.map(str::to_owned))
                .or_default()
                .push(position);
        } else if let Some(protocol) = plan.protocol {
            self.protocols.entry(protocol).or_default().push(position);
        } else {
            self.unbound.push(position);
        }
    }

    pub(super) fn candidates(
        &self,
        anchor: &CaseAnchor,
        facts: Option<&BTreeSet<SourceFact>>,
    ) -> BTreeSet<RuleRef> {
        let mut positions = self.any.iter().copied().collect::<BTreeSet<_>>();
        if let Some(exact) = self
            .exact
            .get(&(anchor.method.clone(), anchor.path.clone()))
        {
            positions.extend(exact.iter().copied());
        }
        if let Some(patterns) = self.patterns.get(&anchor.method) {
            for (pattern, rules) in patterns {
                if crate::path_pattern::matches_path_pattern(pattern, &anchor.path) {
                    positions.extend(rules.iter().copied());
                }
            }
        }
        let mut resources = self.unbound.iter().copied().collect::<BTreeSet<_>>();
        for fact in facts.into_iter().flatten() {
            if let Some(rules) = self.protocols.get(&fact.protocol) {
                resources.extend(rules.iter().copied());
            }
            let target = fact.target();
            if let Some(operations) = self
                .resources
                .get(&(fact.protocol, target.host, target.port))
            {
                for (operation, rules) in operations {
                    if operation.as_deref().is_none_or(|expected| {
                        fact.operation
                            .as_deref()
                            .is_none_or(|actual| actual == expected)
                    }) {
                        resources.extend(rules.iter().copied());
                    }
                }
            }
        }
        positions.retain(|position| resources.contains(position));
        positions
    }
}
