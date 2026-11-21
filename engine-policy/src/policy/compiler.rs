//! Validate native effects and registered value-policy declarations.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::*;
mod order;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledPolicy {
    pub global_json: Option<CompiledJsonPolicy>,
    pub mysql: Option<MysqlPolicy>,
    pub redis: Option<RedisPolicy>,
    pub http: Option<HttpPolicy>,
    pub async_api: BTreeMap<String, AsyncApiRules>,
    pub signatures: BTreeMap<String, SignatureDefinition>,
    pub rules: Vec<CompiledRule>,
    pub native: Vec<CompiledNativeRule>,
    pub fingerprints: PolicyFingerprints,
}

impl CompiledPolicy {
    pub fn field_formats(&self) -> impl Iterator<Item = &GlobalField> {
        self.global_json
            .iter()
            .flat_map(|json| json.fields.values())
            .chain(
                self.mysql
                    .iter()
                    .flat_map(|mysql| mysql.tables.values())
                    .flat_map(|table| table.fields.values()),
            )
            .chain(self.redis.iter().flat_map(|redis| redis.keys.values()))
            .chain(self.http.iter().flat_map(|http| http.headers.values()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFingerprints {
    pub full: String,
    pub runtime: String,
    pub capture: String,
    pub classification: String,
}

pub(super) fn decode_policy(yaml: &str) -> Result<TrafficPolicy> {
    serde_yaml::from_str(yaml).context("invalid traffic-policy/v3 document")
}

pub(super) fn compile_definition(document: &TrafficPolicy) -> Result<CompiledPolicy> {
    let expanded = super::authoring::expanded(document)?;
    compile_expanded(document, expanded.rules)
}

fn compile_expanded(
    document: &TrafficPolicy,
    expanded_rules: Vec<PolicyRule>,
) -> Result<CompiledPolicy> {
    ensure!(
        document.format == POLICY_FORMAT,
        "policy format must be {POLICY_FORMAT:?}"
    );
    ensure!(
        expanded_rules.len() <= 4096,
        "policy contains more than 4096 rules"
    );
    super::signatures::validate(&document.signatures)?;
    document.time.offset()?;
    let global_json = Some(
        document
            .json
            .clone()
            .unwrap_or_default()
            .compile_with_settings(&document.signatures, &document.time)?,
    );
    if let Some(mysql) = &document.mysql {
        mysql.validate()?;
    }
    if let Some(redis) = &document.redis {
        redis.validate()?;
    }
    let http = document
        .http
        .as_ref()
        .map(HttpPolicy::compile)
        .transpose()?;
    let async_api = compile_async_api(&document.async_api.clone().unwrap_or_default())?;
    let mut ids = BTreeSet::new();
    let mut rules = Vec::with_capacity(expanded_rules.len());
    let mut native = vec![];
    for rule in &expanded_rules {
        ensure!(ids.insert(rule.id()), "duplicate rule id {:?}", rule.id());
        match rule {
            PolicyRule::Value(rule) => {
                let compiled =
                    compile_rule(rule).with_context(|| format!("invalid rule {:?}", rule.id))?;
                rules.push(compiled);
            }
            PolicyRule::Native(rule) => {
                native.push(super::native_compile::compile_definition(rule)?)
            }
        }
    }
    rules.sort_by(|left, right| left.rule.id.cmp(&right.rule.id));
    order::native(&mut native);
    validate_rule_overlaps(&rules)?;
    traffic_policy_compiler::compiler::interaction::validate_identity_scopes(&rules)?;
    validate_field_claims(&rules, &native)?;
    let mut expanded = expanded_rules.iter().collect::<Vec<_>>();
    order::expanded(&mut expanded);
    let semantic = expanded
        .iter()
        .map(|rule| match rule {
            PolicyRule::Native(rule) => super::native_compile::semantic_rule(rule),
            PolicyRule::Value(rule) => {
                let mut value = serde_json::to_value(rule)?;
                value
                    .as_object_mut()
                    .expect("typed value rule")
                    .remove("proof");
                Ok(value)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let runtime = rules
        .iter()
        .map(|rule| RuntimeIdentity {
            id: &rule.rule.id,
            surface: rule.rule.surface,
            selector: &rule.rule.selector,
            slot: &rule.rule.slot,
            codec: &rule.rule.codec,
            contract: &rule.rule.contract,
            when: rule.rule.when.as_ref(),
            delivery_time: &rule.delivery_time,
            effect: rule.effect,
            capabilities: &rule.capabilities,
        })
        .collect::<Vec<_>>();
    Ok(CompiledPolicy {
        global_json,
        mysql: document.mysql.clone(),
        redis: document.redis.clone(),
        http,
        async_api: async_api.clone(),
        signatures: document.signatures.clone(),
        fingerprints: PolicyFingerprints {
            full: digest(
                "traffic-policy/full/v2",
                &(
                    &semantic,
                    &document.json,
                    &document.time,
                    &document.mysql,
                    &document.redis,
                    &document.http,
                    &document.async_api,
                    &document.signatures,
                    traffic_extensions::semantics(),
                ),
            )?,
            runtime: digest(
                "traffic-policy/runtime/v1",
                &(
                    runtime,
                    &document.json,
                    &document.time,
                    &document.mysql,
                    &document.redis,
                    &document.http,
                    &async_api,
                    &document.signatures,
                    traffic_extensions::semantics(),
                    native
                        .iter()
                        .filter(|rule| {
                            matches!(rule.domain, NativeDomain::Runtime | NativeDomain::Input)
                                || affects_snapshot(rule)
                        })
                        .map(|rule| &rule.fingerprint)
                        .collect::<Vec<_>>(),
                ),
            )?,
            capture: if async_api.is_empty() {
                digest(
                    "traffic-policy/capture/v1",
                    &native
                        .iter()
                        .filter(|rule| {
                            rule.domain == NativeDomain::Capture || affects_snapshot(rule)
                        })
                        .map(|rule| &rule.fingerprint)
                        .collect::<Vec<_>>(),
                )?
            } else {
                digest(
                    "traffic-policy/capture/v1",
                    &(
                        &native
                            .iter()
                            .filter(|rule| {
                                rule.domain == NativeDomain::Capture || affects_snapshot(rule)
                            })
                            .map(|rule| &rule.fingerprint)
                            .collect::<Vec<_>>(),
                        &async_api,
                    ),
                )?
            },
            classification: digest(
                "traffic-policy/classification/v1",
                &native
                    .iter()
                    .filter(|rule| rule.domain == NativeDomain::Classification)
                    .map(|rule| &rule.fingerprint)
                    .collect::<Vec<_>>(),
            )?,
        },
        rules,
        native,
    })
}

#[derive(Serialize)]
struct RuntimeIdentity<'a> {
    id: &'a str,
    surface: Surface,
    selector: &'a MatchSpec,
    slot: &'a Slot,
    codec: &'a Codec,
    contract: &'a BTreeMap<String, FieldContract>,
    when: Option<&'a SourceCondition>,
    delivery_time: &'a BTreeMap<String, TimeContract>,
    effect: RuleEffect,
    capabilities: &'a [CapabilityId],
}

/// Explicit initial-load contracts govern bootstrap and reusable seed admission.
/// Finite ownership changes classification without acquiring a snapshot.
fn affects_snapshot(rule: &CompiledNativeRule) -> bool {
    matches!(&rule.rule.effect, NativeEffect::ProcessOwned(effect)
        if matches!(&effect.selector, super::native::ProcessSelector::Redis {initial_load_timeout_ms:Some(_),..}))
}

pub use traffic_policy_compiler::compiler::{
    CompiledRule, RuleEffect, digest, disjoint_conditions, key_scopes_overlap, validate_api,
    validate_path, validate_pointer,
};

pub fn compile_rule(rule: &Rule) -> Result<CompiledRule> {
    traffic_policy_compiler::compiler::compile_rule(rule, &super::compilation_context())
}

fn validate_rule_overlaps(rules: &[CompiledRule]) -> Result<()> {
    traffic_policy_compiler::compiler::validate_rule_overlaps(rules, &super::compilation_context())
}
