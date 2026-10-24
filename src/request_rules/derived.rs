//! Private, Source-scoped reconstruction of actually delivered signed inputs.
use super::*;
use crate::value_contract::identities::IdentityPair;

impl RuntimeJwtRule {
    fn selects(&self, request: &Value) -> bool {
        let Some((scope, when)) = &self.scope else {
            return true;
        };
        let body = crate::replay::native_source_request_body(request);
        let method = request["method"].as_str().unwrap_or_default();
        let path = request["uri"]
            .as_str()
            .and_then(|uri| uri.parse::<hyper::Uri>().ok())
            .map(|uri| uri.path().to_string())
            .unwrap_or_default();
        scope.api.as_deref().is_none_or(|api| {
            api.split_once(' ').is_some_and(|(verb, pattern)| {
                verb == method && crate::path_pattern::matches_path_pattern(pattern, &path)
            })
        }) && when.as_ref().is_none_or(|condition| {
            body.as_ref()
                .is_some_and(|body| condition.matches_body(body))
        })
    }
}

impl RequestRuleRuntime {
    /// Only immutable Source-selected JWT branches resolve a startup key. The
    /// snapshot remains private and is checked again during reconstruction.
    pub(crate) fn freeze_for_request(&mut self, request: &Value) -> Result<()> {
        for configured in &mut self.rules {
            if !configured.selects(request) {
                continue;
            }
            let Some(token) = jwt::request_token(request, &configured.rule.location()?)? else {
                continue;
            };
            let Some(token) = jwt::Token::parse(&token)? else {
                continue;
            };
            if token.algorithm != configured.profile.algorithm || !token.has_time_claims() {
                continue;
            }
            if let RuntimeKey::TargetStartup(root) = &configured.key {
                let source = configured
                    .profile
                    .signing_key_source
                    .as_ref()
                    .context("selected input JWT has no startup signing input")?;
                configured.key =
                    RuntimeKey::Frozen(keys::ResolvedSigningKey::resolve(root, source)?);
            }
        }
        Ok(())
    }

    pub(crate) fn ensure_frozen_inputs_current(&self) -> Result<()> {
        for configured in &self.rules {
            if let RuntimeKey::Frozen(key) = &configured.key {
                key.ensure_current()?;
            }
        }
        Ok(())
    }

    pub(crate) fn derived_identity_pairs(
        &self,
        source: &Value,
        target: &Value,
    ) -> Result<Vec<IdentityPair>> {
        let mut pairs = BTreeMap::new();
        for configured in &self.rules {
            if !configured.selects(source) {
                continue;
            }
            let location = configured.rule.location()?;
            let (Some(before), Some(after)) = (
                jwt::request_token(source, &location)?,
                jwt::request_token(target, &location)?,
            ) else {
                continue;
            };
            if before == after {
                continue;
            }
            let before = serde_json::to_string(&before)?;
            let after = serde_json::to_string(&after)?;
            if let Some(previous) = pairs.insert(before, after.clone()) {
                ensure!(
                    previous == after,
                    "derived input identity correspondence differs"
                );
            }
            // Header identity declarations address the whole delivered value,
            // including its literal Bearer prefix. Keep that anchor as well as
            // the bare token reused by JSON bodies or query parameters.
            if let JwtTokenLocation::BearerHeader { header } = &location {
                let whole = |request: &Value| {
                    request["headers"]
                        .as_object()
                        .and_then(|headers| {
                            headers
                                .iter()
                                .find(|(name, _)| name.eq_ignore_ascii_case(header))
                        })
                        .and_then(|(_, values)| values.get(0))
                        .and_then(|value| crate::value_contract::json::identity_key(value, "").ok())
                };
                if let (Some(before), Some(after)) = (whole(source), whole(target))
                    && let Some(previous) = pairs.insert(before, after.clone())
                {
                    ensure!(
                        previous == after,
                        "derived header identity correspondence differs"
                    );
                }
            }
        }
        Ok(pairs
            .into_iter()
            .map(|(source, target)| IdentityPair { source, target })
            .collect())
    }
}
