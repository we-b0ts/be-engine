//! Header carriers reuse authenticated JWT comparison without decoding a body.
use super::*;
use crate::recorder::HeaderMapSnapshot;
use crate::replay::assertion::ResponseDifferenceKind;

impl NativeResponseContext {
    pub(crate) fn header_results(
        &self,
        source: Option<&HeaderMapSnapshot>,
        target: Option<&HeaderMapSnapshot>,
        times: super::super::RequestTimes,
    ) -> Vec<(
        String,
        String,
        std::result::Result<
            Vec<crate::value_contract::identities::IdentityPair>,
            ResponseDifferenceKind,
        >,
    )> {
        self.header_jwt
            .iter()
            .map(|field| {
                let name = field.rule.header.as_deref().expect("header carrier");
                let result = (|| {
                    field
                        .key
                        .ensure_current()
                        .map_err(|_| ResponseDifferenceKind::JwtSigningKeyUnavailable)?;
                    let values = |headers: Option<&HeaderMapSnapshot>| {
                        headers
                            .into_iter()
                            .flat_map(|h| h.iter())
                            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                            .flat_map(|(_, v)| v.iter())
                            .cloned()
                            .collect::<Vec<_>>()
                    };
                    let source = values(source);
                    let target = values(target);
                    let ([source], [target]) = (source.as_slice(), target.as_slice()) else {
                        return Err(ResponseDifferenceKind::JwtInvalid);
                    };
                    let before = Value::String(source.clone());
                    let after = Value::String(target.clone());
                    let checked = super::super::jwt::compare(
                        &field.rule,
                        &before,
                        &after,
                        times,
                        &field.key.bytes,
                        field.key.kid.as_deref(),
                    )?;
                    let mut pairs = vec![super::super::jwt::identity_pair(
                        &field.rule,
                        &before,
                        &after,
                    )?];
                    pairs.extend(checked.nonces.into_iter().map(|nonce| {
                        crate::value_contract::identities::IdentityPair {
                            source: serde_json::to_string(&nonce.source).expect("nonce string"),
                            target: serde_json::to_string(&nonce.target).expect("nonce string"),
                        }
                    }));
                    Ok(pairs)
                })();
                (field.id.clone(), name.into(), result)
            })
            .collect()
    }
}
