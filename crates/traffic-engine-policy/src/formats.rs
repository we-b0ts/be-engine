//! Bind field formats to installed codec and comparison services.
pub struct PolicyMetadata;
impl traffic_contract::compare::RuleMetadata for PolicyMetadata {
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        traffic_extensions::policies()
    }
    fn permits_scalar_composition(&self, rule: &str) -> bool {
        rule == crate::policy::GLOBAL_JSON_ID
    }
    fn accepts_exact_time(&self, rule: &str) -> bool {
        matches!(
            rule,
            crate::policy::GLOBAL_JSON_ID
                | crate::policy::GLOBAL_HTTP_ID
                | crate::policy::GLOBAL_REDIS_ID
                | "global.mysql"
                | "builtin.time"
        )
    }
}

fn execution_context() -> traffic_policy_execution::ExecutionContext<'static> {
    traffic_policy_execution::ExecutionContext {
        codecs: traffic_extensions::codecs(),
        metadata: &PolicyMetadata,
    }
}
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
        let plan = crate::policy::CompiledJsonPolicy {
            fields: fields.clone(),
            ..self.clone()
        };
        traffic_policy_execution::global::compare_logical_with_time_copies::<
            crate::policy::CompiledRule,
        >(
            &execution_context(),
            source,
            target,
            &plan,
            &[],
            clocks,
            &[],
        )
    }
}
