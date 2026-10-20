//! Validate owned HTTP JSON fields, then pass private copies to strict matching.
use super::*;
use crate::policy::HttpJsonField;
use crate::replay::assertion::RequestTimes;

pub(in crate::replay) struct PreparedHttpBody {
    pub source: Vec<u8>,
    pub actual: Vec<u8>,
    pub decision: Decision,
}

impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn prepare_http_body(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        actual: &[u8],
        clocks: RequestTimes,
    ) -> Option<Result<PreparedHttpBody>> {
        let rules = self
            .selected(case, target, DependencyProtocol::Http)
            .into_iter()
            .filter(|rule| {
                rule.http.as_ref().is_some_and(|http| {
                    !http.json.fields.is_empty()
                        && http.method.eq_ignore_ascii_case(method)
                        && super::super::pattern::path_pattern_matches(&http.path, path)
                })
            })
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            let mut source = crate::replay::json_order::parse(source)
                .context("Source HTTP body requires bounded complete unique-member JSON")?;
            let mut actual = crate::replay::json_order::parse(actual)
                .context("Target HTTP body requires bounded complete unique-member JSON")?;
            let mut decision = Decision::default();
            for rule in rules {
                for (pointer, field) in &rule.http.as_ref().expect("selected HTTP").json.fields {
                    let a = source
                        .pointer_mut(pointer)
                        .context("Source HTTP request field is absent")?;
                    let b = actual
                        .pointer_mut(pointer)
                        .context("Target HTTP request field is absent")?;
                    match field {
                        HttpJsonField::Random { format, length } => {
                            crate::value_contract::generated::compare_bounded_random(
                                a,
                                b,
                                format,
                                Some(*length),
                                None,
                            )
                            .map_err(|error| {
                                anyhow::anyhow!("HTTP random field failed: {error:?}")
                            })?;
                        }
                        HttpJsonField::Jwt {
                            algorithm, nonces, ..
                        } => {
                            let anchors = [clocks.source, clocks.target].map(|clock| {
                                clock.map(crate::value_contract::time::date_nanos).context(
                                    "HTTP JWT requires independent dependency request clocks",
                                )
                            });
                            let [a_clock, b_clock] = anchors;
                            let nonces = nonces
                                .iter()
                                .map(|nonce| {
                                    super::super::native_projection::dynamic_claim(&nonce.contract)
                                })
                                .collect::<Vec<_>>();
                            self.compare_jwt(
                                a,
                                b,
                                jwt::JwtContext {
                                    case,
                                    rule: &rule.id,
                                    pointer,
                                    algorithm: super::super::native_projection::hmac_algorithm(
                                        *algorithm,
                                    )?,
                                    anchors: [a_clock?, b_clock?],
                                    tolerance: 5_000_000_000,
                                    dynamic_claims: &nonces,
                                },
                                &mut decision,
                            )?;
                        }
                    }
                    // Both original values were validated. Other request fields
                    // still pass through the ordinary complete body comparator.
                    *a = Value::Null;
                    *b = Value::Null;
                }
                decision.ids.push(rule.id.clone());
            }
            Ok(PreparedHttpBody {
                source: serde_json::to_vec(&source)?,
                actual: serde_json::to_vec(&actual)?,
                decision,
            })
        })())
    }
}
