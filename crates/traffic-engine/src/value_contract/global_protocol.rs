//! Application bindings for carrier-independent value formats.
pub(crate) use traffic_policy_value::formats::checks;
#[cfg(test)]
pub(crate) use traffic_policy_value::formats::looks_like_jwt;
#[cfg(test)]
mod jwt;
pub(crate) mod template;
pub(crate) mod url;

impl traffic_policy_value::formats::FormatHost for crate::policy::CompiledJsonPolicy {
    fn fields(&self) -> &std::collections::BTreeMap<String, crate::policy::GlobalField> {
        &self.fields
    }
    fn time(&self) -> &crate::policy::TimePolicy {
        &self.time
    }
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        traffic_extensions::policies()
    }
    fn signing_key(&self, signature: &str) -> anyhow::Result<(traffic_jwt::Algorithm, &[u8])> {
        use crate::policy::native::SignatureAlgorithm;
        let (algorithm, key) = self.signatures.get(signature)?;
        let algorithm = match algorithm {
            SignatureAlgorithm::HS256 => traffic_jwt::Algorithm::HS256,
            SignatureAlgorithm::HS384 => traffic_jwt::Algorithm::HS384,
            SignatureAlgorithm::HS512 => traffic_jwt::Algorithm::HS512,
            SignatureAlgorithm::RS256 => {
                anyhow::bail!("global RS256 JWT verification is unsupported")
            }
        };
        Ok((algorithm, key))
    }
    fn compare_document(
        &self,
        source: &serde_json::Value,
        target: &serde_json::Value,
        fields: &std::collections::BTreeMap<String, crate::policy::GlobalField>,
        clocks: traffic_contract::compare::AnchorClocks,
    ) -> anyhow::Result<traffic_contract::compare::Comparison> {
        let plan = Self {
            fields: fields.clone(),
            ..self.clone()
        };
        crate::value_contract::global::compare_logical_with_time_copies(
            source,
            target,
            &plan,
            &[],
            clocks,
            &[],
        )
    }
}

#[cfg(test)]
mod tests;
