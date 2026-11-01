//! Provenance is accepted only under effective Source-owned task/lifecycle rules.
use super::{
    model::ProposedAttribution,
    source::{self, SourceSnapshot},
};
use crate::{
    dependency::attribution::{AttributionDecision, DependencyOwner},
    policy::{CompiledPolicy, NativeEffect},
};
use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use uuid::Uuid;

#[cfg(test)]
#[path = "rules_pubsub_tests.rs"]
mod pubsub_tests;

pub(super) fn load(root: &Path) -> Result<CompiledPolicy> {
    crate::policy::parse_and_compile_policy(&fs::read_to_string(
        crate::rewrite::fingerprint::policy_file(root)?,
    )?)
}

fn async_id(api: &str) -> String {
    format!("{}:{api}", crate::policy::ASYNC_API_ID)
}

pub(super) fn fingerprints(policy: &CompiledPolicy) -> Result<BTreeMap<String, String>> {
    let mut values = policy
        .native
        .iter()
        .map(|rule| (rule.rule.id.clone(), rule.fingerprint.clone()))
        .collect::<BTreeMap<_, _>>();
    for (api, rules) in &policy.async_api {
        values.insert(async_id(api), source::digest(&serde_json::to_vec(rules)?));
    }
    Ok(values)
}

pub(super) trait RuleBound {
    fn rule_bindings(&self) -> &BTreeMap<String, String>;
}
impl RuleBound for AttributionDecision {
    fn rule_bindings(&self) -> &BTreeMap<String, String> {
        &self.rule_bindings
    }
}
impl RuleBound for super::decisions::DecisionTemplate {
    fn rule_bindings(&self) -> &BTreeMap<String, String> {
        &self.rule_bindings
    }
}
impl<T: RuleBound + ?Sized> RuleBound for &T {
    fn rule_bindings(&self) -> &BTreeMap<String, String> {
        T::rule_bindings(*self)
    }
}

pub(super) fn current(decision: &impl RuleBound, active: &BTreeMap<String, String>) -> bool {
    !decision.rule_bindings().is_empty()
        && decision
            .rule_bindings()
            .iter()
            .all(|(id, fingerprint)| active.get(id) == Some(fingerprint))
}

pub(super) fn groups(policy: &CompiledPolicy) -> Result<Vec<Value>> {
    let mut tasks = BTreeMap::<String, Vec<Value>>::new();
    for rule in &policy.native {
        if let NativeEffect::ProcessOwned(effect) = &rule.rule.effect
            && effect.origin.is_none()
            && let Some(task) = &effect.task_name
        {
            tasks.entry(task.clone()).or_default().push(
                json!({"rule_id":rule.rule.id,"fingerprint":rule.fingerprint,
                "selector_digest":source::digest(&serde_json::to_vec(&effect.selector)?)}),
            );
        }
    }
    let mut groups = tasks.into_iter().map(|(task,rules)|json!({"kind":"process_task","source_task":task,
        "rules":rules,"association":"declared selector scope; individual occurrence ownership still requires independent Source proof"})).collect::<Vec<_>>();
    for (api, rules) in &policy.async_api {
        groups.push(json!({"kind":"async_api","api":crate::rewrite::api_selector::public_api(api),
        "method_api":api,"rule_id":async_id(api),"fingerprint":source::digest(&serde_json::to_vec(rules)?),
        "scenario_count":rules.len(),"dependency_requests":"automatically captured until the declared end; no intermediate request list"}));
    }
    Ok(groups)
}

pub(super) fn bind(
    root: &Path,
    state: &crate::rewrite::model::RewriteState,
    source: &SourceSnapshot,
    proposal: &mut ProposedAttribution,
) -> Result<BTreeMap<String, String>> {
    let policy = load(root)?;
    ensure!(
        proposal.rule_binding.policy_fingerprint == policy.fingerprints.full,
        "effective attribution policy changed; inspect rules and obtain fresh context"
    );
    ensure!(
        !proposal.rule_binding.rule_ids.is_empty(),
        "proven ownership must bind effective task/lifecycle rules"
    );
    let active = fingerprints(&policy)?;
    match &proposal.owner {
        DependencyOwner::Process {
            source_task,
            process_epoch,
            ..
        } => {
            ensure!(
                source_task == &proposal.source_task,
                "process owner must name the actual declared Source task"
            );
            let task_rules = policy
                .native
                .iter()
                .filter(|rule| {
                    matches!(&rule.rule.effect,NativeEffect::ProcessOwned(effect)
                if effect.task_name.as_deref() == Some(source_task) && effect.origin.is_none())
                })
                .cloned()
                .collect::<Vec<_>>();
            let ids = task_rules
                .iter()
                .map(|rule| rule.rule.id.clone())
                .collect::<BTreeSet<_>>();
            ensure!(
                !ids.is_empty() && ids == proposal.rule_binding.rule_ids,
                "process proof must bind the complete effective Source task selector group"
            );
            let covered = process_matches(source, &task_rules, Some(*process_epoch))?;
            let other_tasks=policy.native.iter().filter(|rule|matches!(&rule.rule.effect,NativeEffect::ProcessOwned(effect)
                if effect.origin.is_none() && effect.task_name.as_deref().is_some_and(|task|task!=source_task)))
                .cloned().collect::<Vec<_>>();
            if !other_tasks.is_empty() {
                let ambiguous = process_matches(source, &other_tasks, Some(*process_epoch))?;
                ensure!(
                    covered.is_disjoint(&ambiguous),
                    "Source request selectors overlap another logical task; narrow the complete task rules or retain unresolved ownership"
                );
            }
            ensure!(
                !covered.is_empty(),
                "task selectors have no original Source occurrences in this epoch"
            );
            if proposal.source_exchange_ids.is_empty() {
                proposal.source_exchange_ids = covered;
            } else {
                ensure!(
                    proposal.source_exchange_ids == covered,
                    "task proof must cover all Source occurrences selected by its complete declared task scope"
                );
            }
        }
        DependencyOwner::Case { origin_case_id, .. } => {
            let api = source
                .apis
                .get(origin_case_id)
                .context("async origin input absent")?;
            let rules = policy.async_api.get(api).context("publish an async_api end-only rule for the real origin before proving foreign ownership")?;
            ensure!(
                proposal.rule_binding.rule_ids == BTreeSet::from([async_id(api)]),
                "async proof must bind the real origin lifecycle rule"
            );
            let directory = source
                .inputs
                .get(origin_case_id)
                .context("original async input path absent")?;
            let request: Value =
                serde_json::from_slice(&source.read_input(&directory.join("request.json"))?)?;
            let response: Value = serde_json::from_slice(
                &source.read_input(&directory.join("expected-response.json"))?,
            )?;
            let body = crate::replay::native_source_request_body(&request);
            let response = crate::replay::native_source_request_body(&response);
            ensure!(
                rules.iter().any(|rule| crate::policy::async_api_matches(
                    api,
                    rule,
                    request["method"].as_str().unwrap_or_default(),
                    request["uri"].as_str().unwrap_or_default(),
                    body.as_ref()
                ) && crate::policy::async_response_matches(
                    rule,
                    response.as_ref()
                )),
                "effective async lifecycle does not select the original Source request/response scenario"
            );
            if proposal.source_exchange_ids.is_empty() {
                proposal.source_exchange_ids = proposal
                    .claim_ids
                    .iter()
                    .filter_map(|id| state.dependency_review.claims.get(id))
                    .flat_map(|claim| claim.source_exchange_ids.iter().copied())
                    .collect();
            }
            let scope = crate::recorder::async_api::AsyncScope::for_primary(
                &policy.async_api,
                &request["method"]
                    .as_str()
                    .context("origin method absent")?
                    .parse()?,
                &request["uri"]
                    .as_str()
                    .context("origin URI absent")?
                    .parse()?,
                &body
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?
                    .unwrap_or_default(),
            )
            .context("async origin scope absent")?;
            scope.select_response(response.as_ref());
            let mut observations = source.exchanges.iter().filter(|(id,event)|proposal.source_exchange_ids.contains(id)
                || matches!(event.capture.attribution,DependencyOwner::Case{origin_case_id:origin,..} if origin==*origin_case_id)
                || state.dependency_review.decisions.get(id).is_some_and(|decision|current(decision,&active)
                    && matches!(decision.owner,DependencyOwner::Case{origin_case_id:origin,..} if origin==*origin_case_id)))
                .collect::<Vec<_>>();
            observations
                .sort_by_key(|(_, event)| (event.capture.started_at, event.capture.effect_index));
            let mut reader = crate::dependency_index::RecordReader::new(16 * 1024 * 1024);
            let mut terminal = false;
            for (id, event) in observations {
                if !event.complete
                    || !matches!(
                        event.selector["event_type"].as_str(),
                        Some("mysql_exchange" | "redis_exchange" | "http_exchange")
                    )
                {
                    continue;
                }
                terminal |= scope
                    .observe_recorded(&source.original_selector(id, &mut reader)?)?
                    .is_some_and(|signal| {
                        signal.end_reason == crate::recorder::async_api::AsyncEndReason::Resource
                    });
            }
            if !terminal
                && proposal.impact
                    != crate::rewrite::verification_obligations::VerificationImpact::MissingCapture
            {
                proposal.impact =
                    crate::rewrite::verification_obligations::VerificationImpact::MissingCapture;
                proposal.missing_evidence=Some("proven origin scope has no complete successful declared async end; capture that origin through its end-only lifecycle".into());
            }
        }
        DependencyOwner::Startup { process_epoch, .. } => {
            ensure!(
                proposal.rule_binding.rule_ids.iter().all(|id| policy
                    .native
                    .iter()
                    .any(|rule| &rule.rule.id == id
                        && matches!(rule.rule.effect, NativeEffect::FiniteSharing(_)))),
                "startup ownership sharing requires explicit effective localcache request rules"
            );
            let covered = source
                .exchanges
                .iter()
                .filter(|(_, event)| {
                    event.capture.process_epoch == *process_epoch && event.capture.semantic_required
                })
                .filter(|(_, event)| {
                    policy.native.iter().any(|rule| {
                        proposal.rule_binding.rule_ids.contains(&rule.rule.id)
                            && startup_matches(&rule.rule, &event.selector)
                    })
                })
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>();
            ensure!(
                !covered.is_empty(),
                "startup rules do not cover any original Source request"
            );
            if proposal.source_exchange_ids.is_empty() {
                proposal.source_exchange_ids = covered;
            } else {
                ensure!(
                    proposal.source_exchange_ids == covered,
                    "startup proof must cover the complete selected initialization request scope"
                );
            }
        }
        DependencyOwner::Shutdown { .. } => {
            anyhow::bail!(
                "shutdown association is recorded at the lifecycle boundary, not authored by an attribution rule"
            )
        }
        DependencyOwner::Unattributed { .. } => {
            anyhow::bail!("unresolved ownership cannot bind a passing attribution rule")
        }
    }
    proposal
        .rule_binding
        .rule_ids
        .iter()
        .map(|id| {
            Ok((
                id.clone(),
                active
                    .get(id)
                    .context("attribution rule is not effective")?
                    .clone(),
            ))
        })
        .collect()
}

fn capture_bytes(value: &Value) -> Option<Vec<u8>> {
    if value["truncated"] == true {
        return None;
    }
    let data = value["data"].as_str()?;
    match value["encoding"].as_str()? {
        "utf8" => Some(data.as_bytes().to_vec()),
        "base64" => base64::engine::general_purpose::STANDARD.decode(data).ok(),
        _ => None,
    }
}

fn startup_matches(rule: &crate::policy::NativeRule, event: &Value) -> bool {
    use crate::policy::native::FiniteSharingEffect;
    if rule
        .selector
        .resource
        .as_ref()
        .is_some_and(|resource| !resource_matches(resource, event))
    {
        return false;
    }
    match &rule.effect {
        NativeEffect::FiniteSharing(FiniteSharingEffect::Http) => {
            let host = event["authority"]
                .as_str()
                .and_then(|authority| authority.parse::<hyper::http::uri::Authority>().ok())
                .map(|authority| authority.host().to_ascii_lowercase());
            event["event_type"] == "http_exchange"
                && rule.selector.http_host.as_ref().is_none_or(|expected| {
                    host.as_ref()
                        .is_some_and(|host| expected.eq_ignore_ascii_case(host))
                })
                && rule.selector.operation.as_deref() == event["method"].as_str()
                && rule.selector.path.as_deref() == event["uri"].as_str()
        }
        NativeEffect::FiniteSharing(FiniteSharingEffect::Redis { hash_field }) => {
            let Some(crate::policy::native::NativeKeySelector::Exact { value: key }) =
                &rule.selector.key
            else {
                return false;
            };
            event["event_type"] == "redis_exchange"
                && rule.selector.operation.as_deref() == event["command"].as_str()
                && capture_bytes(&event["args"][0]).as_deref() == Some(key.as_bytes())
                && hash_field.as_ref().is_none_or(|field| {
                    capture_bytes(&event["args"][1]).as_deref() == Some(field.as_bytes())
                })
        }
        _ => false,
    }
}

fn resource_matches(resource: &crate::policy::Resource, event: &Value) -> bool {
    use crate::policy::{Database, Protocol};
    let (protocol, host, port) = if event["event_type"] == "http_exchange" {
        let Some(authority) = event["authority"]
            .as_str()
            .and_then(|value| value.parse::<hyper::http::uri::Authority>().ok())
        else {
            return false;
        };
        (
            Protocol::Http,
            authority.host().to_owned(),
            authority.port_u16().unwrap_or(
                if event["scheme"]
                    .as_str()
                    .is_some_and(|scheme| scheme.contains("https"))
                {
                    443
                } else {
                    80
                },
            ),
        )
    } else if event["event_type"] == "redis_exchange" {
        let (Some(host), Some(port)) = (
            event["target_host"].as_str(),
            event["target_port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok()),
        ) else {
            return false;
        };
        (Protocol::Redis, host.to_owned(), port)
    } else {
        return false;
    };
    resource.protocol == protocol
        && resource.endpoint.host.eq_ignore_ascii_case(&host)
        && resource.endpoint.port == port
        && resource
            .database
            .as_ref()
            .is_none_or(|database| match database {
                Database::Index(index) => event["database"].as_i64() == Some(*index),
                Database::Name(name) => event["database"].as_str() == Some(name.as_str()),
            })
        && resource
            .username
            .as_ref()
            .is_none_or(|name| event["username"].as_str() == Some(name.as_str()))
}

fn process_matches(
    source: &SourceSnapshot,
    rules: &[crate::policy::CompiledNativeRule],
    epoch: Option<Uuid>,
) -> Result<BTreeSet<Uuid>> {
    let policy = crate::config::native_policy::project_source_policy(rules)?;
    let matcher = crate::recorder::background::BackgroundDependencyMatcher::from_rules(
        &policy.process_owned_dependencies,
    )?;
    let ports = matcher.resolved_memcached_rule_ports();
    let origins = crate::api_trigger::OriginIndex::default();
    let mut reader = crate::dependency_index::RecordReader::new(16 * 1024 * 1024);
    let mut covered = BTreeSet::new();
    let mut subscriptions = BTreeMap::new();
    for (id, event) in &source.exchanges {
        if epoch.is_some_and(|epoch| epoch != event.capture.process_epoch)
            || !event.capture.semantic_required
        {
            continue;
        }
        let original;
        let selector = if event.selector["_source_proof_requires_original"] == true
            || event.selector["event_type"] == "redis_pub_sub_push"
                && policy.process_owned_dependencies.iter().any(|rule| matches!(rule,
                    crate::config::process_owned_dependencies::BackgroundDependencyRuleConfig::RedisPubsub { .. })) {
            original = source.original_selector(id, &mut reader)?;
            &original
        } else {
            &event.selector
        };
        let case = event.capture.observed_case.map(|case| case.to_string());
        for rule in &policy.process_owned_dependencies {
            if crate::replay::report::source_owned_match(
                selector,
                case.as_deref(),
                rule,
                &ports,
                &origins,
            )? {
                if let crate::config::process_owned_dependencies::BackgroundDependencyRuleConfig::RedisPubsub { selector: input, .. } = rule {
                    let anchor = crate::config::process_owned_dependencies::pubsub::anchor(selector).context("Source Pub/Sub input anchor is invalid")?;
                    if let std::collections::btree_map::Entry::Vacant(entry) = subscriptions.entry(anchor) {
                        let ids = source.native.get(&("redis".into(), anchor.0.to_string(), anchor.1))
                            .context("Source Pub/Sub input lacks its original subscription")?;
                        ensure!(ids.len() == 1, "Source Pub/Sub subscription identity is ambiguous");
                        let subscription = source.original_selector(ids.first().expect("one original subscription"), &mut reader)?;
                        entry.insert(subscription);
                    }
                    crate::config::process_owned_dependencies::pubsub::validate_subscription(input, selector, &subscriptions[&anchor])?;
                }
                covered.insert(*id);
                break;
            }
        }
    }
    Ok(covered)
}

pub(super) fn claim_groups(
    policy: &CompiledPolicy,
    source: &SourceSnapshot,
    claims: &[super::model::ForeignUnusedClaim],
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut result = BTreeMap::new();
    for group in groups(policy)? {
        let Some(task) = group["source_task"].as_str() else {
            continue;
        };
        let rules = policy
            .native
            .iter()
            .filter(|rule| {
                matches!(&rule.rule.effect,NativeEffect::ProcessOwned(effect)
            if effect.task_name.as_deref() == Some(task) && effect.origin.is_none())
            })
            .cloned()
            .collect::<Vec<_>>();
        let selected = process_matches(source, &rules, None)?;
        let related = claims
            .iter()
            .filter(|claim| !claim.source_exchange_ids.is_disjoint(&selected))
            .map(|claim| claim.id.clone())
            .collect();
        result.insert(task.into(), related);
    }
    Ok(result)
}
