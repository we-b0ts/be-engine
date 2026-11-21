use super::*;
pub fn evidence(root: &Path, state: &RewriteState) -> Result<crate::e2e_run::BatchRuleEvidence> {
    let evidence = crate::e2e_run::batch_rule_evidence(crate::E2eRunContext {
        target_root: root.into(),
        case_source: state
            .case_source
            .clone()
            .or_else(|| state.recording_input_case_source.clone())
            .context("batch rule evidence requires current Source inputs")?,
        run_key: None,
    })?;
    ensure!(
        evidence.recording_run_id == state.recording_run_id
            && state
                .source_revision
                .as_ref()
                .is_none_or(|revision| revision == &evidence.source_revision),
        "batch rule evidence belongs to a different workflow Source"
    );
    Ok(evidence)
}

/// Batch analysis cannot borrow an API implementer's primary/inbound scope.
pub fn validate_proposal(policy: &crate::policy::TrafficPolicy) -> Result<()> {
    use crate::policy::PolicyRule;
    for rule in &policy.rules {
        let valid = match rule {
            PolicyRule::Value(rule) => {
                rule.surface != crate::policy::Surface::ApiResponse
                    && rule.selector.api.is_none()
                    && rule.when.is_none()
            }
            PolicyRule::Native(rule) => {
                rule.selector.api.is_none()
                    && rule.when.is_none()
                    && !matches!(
                        rule.effect,
                        crate::policy::NativeEffect::ResponseJwt(_)
                            | crate::policy::NativeEffect::ResponseHeaderDate(_)
                            | crate::policy::NativeEffect::ResponseGenerated(_)
                            | crate::policy::NativeEffect::ResponseBody(_)
                            | crate::policy::NativeEffect::InputJwt(_)
                            | crate::policy::NativeEffect::InputSignedTimestamp(_)
                    )
            }
        };
        ensure!(
            valid,
            "unsupported in batch rule scope: API response/inbound/conditional rules require their real API issue; use an explicit supported dependency resource or global/task declaration"
        );
    }
    Ok(())
}
