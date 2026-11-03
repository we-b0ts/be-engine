//! Private in-memory policy state for Source self validation. It has no replay
//! transport, claims, consumption, or witness store, and never reads a Target.
use super::*;
use std::{path::PathBuf, sync::Arc};

impl ReplayPolicyRuntime {
    pub(in crate::replay::policy) fn from_source_policy(
        compiled: &crate::policy::CompiledPolicy,
        target_root: &Path,
        requests: &BTreeMap<String, (PathBuf, Value)>,
    ) -> Result<Self> {
        let mut compiled = compiled.clone();
        // Native Source proof must not borrow a generic codec authorization.
        compiled.rules.clear();
        let compiled = Arc::new(compiled);
        let projection = super::super::native_projection::project_native(&compiled.native)?;
        let document = projection.document;
        let mut cases = BTreeMap::new();
        for (id, (_, request)) in requests {
            let method = request["method"]
                .as_str()
                .context("Source request method is missing")?;
            let uri = request["uri"]
                .as_str()
                .context("Source request URI is missing")?;
            uri.parse::<hyper::Uri>()?;
            cases.insert(
                id.clone(),
                CaseIdentity {
                    method: Some(method.into()),
                    path: Some(super::super::pattern::uri_path(uri)),
                    conditions: super::super::case_condition::matching_rule_ids(
                        request,
                        document.dependency_rules.iter().filter_map(|rule| {
                            rule.when.as_ref().map(|when| (rule.id.as_str(), when))
                        }),
                    ),
                },
            );
        }
        let mut dynamic_values = super::super::dynamic_values::DynamicValues::new(
            document.dynamic_values.clone(),
            cases
                .iter()
                .filter_map(|(id, case)| case.path.as_ref().map(|path| (id.clone(), path.clone())))
                .collect(),
        );
        dynamic_values.configure_native(&compiled.native);
        for (id, (_, request)) in requests {
            dynamic_values.set_request(id, request);
        }
        let mut request_contracts =
            super::super::request_contract::RequestContracts::from_source_policy(
                &document.dependency_rules,
                target_root,
                requests,
            )?;
        request_contracts.configure_compiled(Some(compiled.clone()))?;
        dynamic_values.configure_identities(request_contracts.clone());
        let mut usage: BTreeMap<String, DependencyRuleUsage> = document
            .dependency_rules
            .iter()
            .map(|rule| (rule.id.clone(), DependencyRuleUsage::default()))
            .collect();
        for rule in compiled.native.iter().filter(|r| {
            matches!(
                r.rule.effect,
                crate::policy::NativeEffect::RedisAppendStream
                    | crate::policy::NativeEffect::RedisReadCommutation(_)
                    | crate::policy::NativeEffect::RedisReadObservation(_)
                    | crate::policy::NativeEffect::RedisExpiryRefresh(_)
                    | crate::policy::NativeEffect::RedisActivityRefresh(_)
            )
        }) {
            usage.insert(rule.rule.id.clone(), DependencyRuleUsage::default());
        }
        Ok(Self {
            mysql_selectors: mysql_selectors::MysqlSelectors::new(&document.dependency_rules)?,
            usage,
            request_contracts,
            dynamic_values,
            loaded: LoadedReplayPolicy {
                document,
                path: PathBuf::from("<Source-self-validation>"),
                fingerprint: compiled.fingerprints.full.clone(),
                compiled: Some(compiled),
            },
            cases,
            applicable_dependency_rule_ids: BTreeSet::new(),
            recorded_mysql_rule_applicability: BTreeMap::new(),
        })
    }
}
