//! Resolve authenticated key inputs before shared content verification.
use crate::policy::runtime::ResponseField;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
pub(crate) mod keys;
pub(crate) use traffic_policy_content::jwt::{companions, compare, identity_pair};

pub(crate) struct JwtComparison<'a>(
    traffic_policy_content::jwt::JwtComparison<'a, keys::VerificationKey>,
);
impl<'a> JwtComparison<'a> {
    pub(crate) fn load(
        fields: &[ResponseField],
        policy: &Path,
        request: &Path,
        source: &'a Value,
        target: &'a Value,
    ) -> Self {
        let root = policy
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("."));
        let keys = fields
            .iter()
            .filter_map(|field| {
                field.jwt.as_ref().map(|rule| {
                    (
                        field.id.clone(),
                        keys::VerificationKey::resolve(
                            root,
                            &rule.signing_key_source,
                            request.parent().unwrap_or(Path::new(".")),
                        ),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        Self(traffic_policy_content::jwt::JwtComparison::new(
            keys, source, target,
        ))
    }
}
impl traffic_policy_content::json::JwtVerifier for JwtComparison<'_> {
    fn compare(
        &mut self,
        field: &ResponseField,
        pointer: &str,
        times: super::RequestTimes,
    ) -> Result<(), super::ResponseDifferenceKind> {
        self.0.compare(field, pointer, times)
    }
}
impl traffic_policy_content::jwt::VerificationKey for keys::VerificationKey {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}
