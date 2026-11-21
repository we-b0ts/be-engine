//! Build and verify JWT rule proposals against authenticated Source evidence.
use super::execution_context::{case_source, e2e_context, group_id};
use super::{JwtPlanRecord, model::RewriteState};
use crate::e2e_run::jwt_evidence;
use crate::request_rules::{
    JwtAlgorithm, JwtProfile, JwtRule, JwtRules, JwtTime, JwtTokenLocation,
    keys::{self, SigningKeySource},
    policy,
};
use anyhow::{Context, Result, ensure};
use jwt_evidence::JwtTimeEvidence;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
#[derive(Debug, Clone)]
pub struct JwtRulePlanOptions {
    pub id: String,
    pub location: JwtTokenLocation,
    pub algorithm: JwtAlgorithm,
    pub signing_key_ref: String,
    pub key_source: Option<SigningKeySource>,
    pub leeway_seconds: i64,
}

pub fn build_spec(
    root: &Path,
    state: &RewriteState,
    options: JwtRulePlanOptions,
) -> Result<JwtPlanRecord> {
    let facts = facts(root, state)?;
    let (_, config) = crate::e2e_run::resolve_project(root)?;
    let key_source = options.key_source.context(
        "JWT rule requires --target-env or --target-key-file with --target-key-field; the selected source is stored in verification.yaml",
    )?;
    let spec = JwtPlanRecord {
        rule: JwtRule {
            id: options.id,
            header: match &options.location {
                JwtTokenLocation::BearerHeader { header } => Some(header.clone()),
                JwtTokenLocation::RawHeader { raw_header } => Some(raw_header.clone()),
                JwtTokenLocation::QueryParameter { .. }
                | JwtTokenLocation::SocketIoConnect { .. } => None,
            },
            scheme: match &options.location {
                JwtTokenLocation::BearerHeader { .. } => Some("bearer".into()),
                JwtTokenLocation::RawHeader { .. } => Some("raw".into()),
                JwtTokenLocation::QueryParameter { .. }
                | JwtTokenLocation::SocketIoConnect { .. } => None,
            },
            query_param: match &options.location {
                JwtTokenLocation::QueryParameter { query_param } => Some(query_param.clone()),
                JwtTokenLocation::BearerHeader { .. }
                | JwtTokenLocation::RawHeader { .. }
                | JwtTokenLocation::SocketIoConnect { .. } => None,
            },
            socketio_connect: match &options.location {
                JwtTokenLocation::SocketIoConnect { socketio_connect } => {
                    Some(socketio_connect.clone())
                }
                _ => None,
            },
            profile: options.signing_key_ref.clone(),
        },
        profile: JwtProfile {
            signing_key_ref: options.signing_key_ref,
            signing_key_source: Some(key_source),
            algorithm: options.algorithm,
            time: JwtTime::PreserveRelative,
        },
        policy_revision: jwt_evidence::digest(&std::fs::read(&config.replay_policy)?),
        evidence_revision: jwt_evidence::digest(&serde_json::to_vec(&facts)?),
        leeway_seconds: options.leeway_seconds,
    };
    Ok(spec)
}
pub fn build(
    root: &Path,
    state: &RewriteState,
    spec: &JwtPlanRecord,
) -> Result<(std::path::PathBuf, String, Value)> {
    let (_, config) = crate::e2e_run::resolve_project(root)?;
    let original = std::fs::read_to_string(&config.replay_policy)?;
    ensure!(
        jwt_evidence::digest(original.as_bytes()) == spec.policy_revision,
        "verification policy changed after JWT planning; rerun plan"
    );
    let key_source = spec.profile.signing_key_source.as_ref().context(
        "JWT plan has no signing_key_source; rerun plan with --target-env or --target-key-file",
    )?;
    let key = keys::resolve_source(root, key_source)?;
    let facts = facts(root, state)?;
    ensure!(
        jwt_evidence::digest(&serde_json::to_vec(&facts)?) == spec.evidence_revision,
        "JWT attempt evidence changed after planning; rerun plan"
    );
    let case_source = case_source(root, state)?;
    let selected = facts
        .candidates
        .iter()
        .filter(|c| {
            spec.rule
                .location()
                .is_ok_and(|location| c.location == location)
                && c.algorithm == spec.profile.algorithm
        })
        .collect::<Vec<_>>();
    ensure!(
        !selected.is_empty(),
        "no expired JWT evidence matches this rule"
    );
    for case in &selected {
        let path = crate::case_group::resolve_published_case_dir(&case_source, &case.case_id)?
            .join("request.json");
        ensure!(
            jwt_evidence::digest(&std::fs::read(&path)?) == case.request_fingerprint,
            "JWT request evidence changed"
        );
        let request = serde_json::from_slice(&crate::request_headers::load_request_file(&path)?)?;
        jwt_evidence::verify_candidate(case, &request, &key, spec.leeway_seconds)?;
    }
    let coverage = coverage(&case_source, &spec.rule, &spec.profile, &key)?;
    let updated = policy::add(&original, &spec.profile, &spec.rule)?;
    let rendered = serde_yaml::to_string(&crate::request_rules::RequestRules {
        jwt: JwtRules {
            profiles: BTreeMap::from([(spec.rule.profile.clone(), spec.profile.clone())]),
            rules: vec![spec.rule.clone()],
        },
    })?;
    let report = json!({
        "kind": "jwt", "policy": config.replay_policy, "rule": spec.rule, "profile": spec.profile,
        "signing_key_source": spec.profile.signing_key_source, "signature_verified": true,
        "evidence_cases": selected.len(), "coverage": coverage,
        "changed": original != updated, "applied": false,
        "requires_rerecording": false, "requires_request_execution": true,
        "diff": format!("@@ request_rules @@\n{rendered}"),
        "does_not_prove": ["JWT expiry may coexist with other authentication or target defects; execute the original cases again"]
    });
    Ok((config.replay_policy, updated, report))
}

fn coverage(source: &Path, rule: &JwtRule, profile: &JwtProfile, key: &[u8]) -> Result<Value> {
    let mut matched = 0;
    let mut invalid = 0;
    let mut apis = std::collections::BTreeSet::new();
    let paths = crate::case_group::published_request_paths(source)?;
    ensure!(
        paths.len() <= 100_000,
        "JWT coverage exceeds supported recording bound"
    );
    for path in paths {
        let request: Value =
            serde_json::from_slice(&crate::request_headers::load_request_file(&path)?)?;
        let location = rule.location()?;
        let Some(raw) = crate::request_rules::jwt::request_token(&request, &location)? else {
            continue;
        };
        let Some(token) = crate::request_rules::jwt::Token::parse(&raw)? else {
            continue;
        };
        if token.algorithm != profile.algorithm {
            continue;
        }
        if !token.verify(key) {
            invalid += 1;
            continue;
        }
        if !token.has_time_claims() {
            continue;
        }
        crate::request_rules::jwt::request_timestamp(&request)?;
        for claim in ["exp", "iat", "nbf"] {
            token.integer_claim(claim)?;
        }
        matched += 1;
        apis.insert(format!(
            "{} {}",
            request["method"].as_str().unwrap_or_default(),
            request["uri"]
                .as_str()
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
        ));
    }
    Ok(
        json!({ "matching_cases": matched, "distinct_request_paths": apis.len(), "unverified_tokens_preserved": invalid, "scope": "all APIs with the matching token location, algorithm and valid signature" }),
    )
}

pub fn facts(root: &Path, state: &RewriteState) -> Result<JwtTimeEvidence> {
    let evidence = jwt_evidence::query(e2e_context(root, state)?, group_id(state)?)?;
    ensure!(
        state
            .active_issue
            .as_ref()
            .is_some_and(|i| i.attempt == evidence.attempt),
        "JWT evidence belongs to another attempt"
    );
    Ok(evidence)
}
