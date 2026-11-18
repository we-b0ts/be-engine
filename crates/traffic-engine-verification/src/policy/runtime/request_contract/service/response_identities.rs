//! Validate response constraints against the compiled format declarations.
use super::*;
use crate::policy::GlobalFieldRuntime;

impl RequestContracts {
    pub(super) fn validate_response_identity_formats(&self, pairs: &[IdentityPair]) -> Result<()> {
        let compiled = self.compiled_rules();
        let formats = compiled
            .into_iter()
            .flat_map(|policy| &policy.rules)
            .flat_map(|rule| rule.rule.contract.values())
            .filter_map(|contract| match contract.unconditional() {
                crate::policy::FieldContract::Identity { prefix, format } => {
                    Some((prefix.as_str(), *format))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let global_fields = compiled
            .into_iter()
            .flat_map(|policy| policy.field_formats())
            .filter(|field| field.is_identity())
            .collect::<Vec<_>>();
        let template_tokens = compiled
            .into_iter()
            .flat_map(|policy| &policy.native)
            .flat_map(|rule| match &rule.rule.effect {
                crate::policy::NativeEffect::ResponseGenerated(effect) => effect
                    .fields
                    .values()
                    .filter_map(|field| match &field.contract {
                        crate::policy::native::GeneratedResponse::Template { fields, .. } => Some(
                            fields
                                .values()
                                .map(|field| &field.contract)
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    })
                    .flatten()
                    .collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect::<Vec<_>>();
        for pair in pairs {
            let source: Value = serde_json::from_str(&pair.source)?;
            let target: Value = serde_json::from_str(&pair.target)?;
            ensure!(
                (!global_fields.is_empty()
                    && source == target
                    && crate::value_contract::json::identity_key(&source, "").is_ok())
                    || formats.iter().any(|(prefix, format)| {
                        [&source, &target].into_iter().all(|value| {
                            crate::value_contract::json::identity_token(value, prefix, *format, "")
                                .is_ok()
                        })
                    })
                    || global_fields.iter().any(|field| {
                        match field.select_contract(&source) {
                            Ok(crate::policy::FieldContract::Identity { prefix, format }) => {
                                crate::value_contract::json::identity_token(
                                    &target, &prefix, format, "",
                                )
                                .is_ok()
                            }
                            _ => false,
                        }
                    })
                    || template_tokens.iter().any(|token| {
                        source
                            .as_str()
                            .zip(target.as_str())
                            .is_some_and(|(source, target)| {
                                (token.length.is_some() || source.len() == target.len())
                                    && crate::value_contract::generated::template::valid_token(
                                        source, token,
                                    )
                                    && crate::value_contract::generated::template::valid_token(
                                        target, token,
                                    )
                            })
                    }),
                "response identity representation has no declared format"
            );
        }
        Ok(())
    }
}
