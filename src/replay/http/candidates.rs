//! Append-only HTTP envelope candidates shared by strict and hypothesis matching.
use super::*;
use crate::replay::execution_plan::CaseMembership;
use crate::replay::native_index::{CandidateCursor, CandidateIndex, HttpKey, ScopePartition};

#[derive(Debug, Default)]
pub(crate) struct Candidates {
    count: usize,
    index: CandidateIndex<HttpKey>,
    exempt: CandidateIndex<HttpKey>,
    members: CaseMembership,
}

impl Candidates {
    pub(in crate::replay) fn register_exempt(
        &mut self,
        exchanges: &[ReplayHttpExchange],
        indices: impl Iterator<Item = usize>,
    ) {
        for index in indices {
            let exchange = &exchanges[index];
            let exact = key(
                exchange.source,
                exchange.case_id.as_deref(),
                exchange.identity.scheme,
                &exchange.identity.target,
                &exchange.record.native.method,
                Some(&uri_path_only(&exchange.record.native.uri)),
            );
            let mut coarse = exact.clone();
            coarse.path = None;
            for mut key in [exact, coarse] {
                self.exempt.register(key.clone(), index);
                if exchange.shared_origin.is_some() {
                    key.scope = ScopePartition::Shared;
                    self.exempt.register(key, index);
                }
            }
        }
        self.exempt.seal();
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select_exempt(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &str,
        path: Option<&str>,
    ) -> CandidateCursor {
        let mut key = key(source, case, scheme, target, method, path);
        let scoped = self.exempt.lookup(&key);
        key.scope = ScopePartition::Shared;
        scoped.merge(self.exempt.lookup(&key))
    }
    pub(crate) fn register(&mut self, exchanges: &[ReplayHttpExchange]) {
        if self.count > exchanges.len() {
            *self = Self::default();
        }
        for (index, exchange) in exchanges.iter().enumerate().skip(self.count) {
            self.members
                .register(exchange.source, exchange.case_id.as_deref(), index);
            let exact = key(
                exchange.source,
                exchange.case_id.as_deref(),
                exchange.identity.scheme,
                &exchange.identity.target,
                &exchange.record.native.method,
                Some(&uri_path_only(&exchange.record.native.uri)),
            );
            let mut coarse = exact.clone();
            coarse.path = None;
            for mut key in [exact, coarse] {
                self.index.register(key.clone(), index);
                if exchange.shared_origin.is_some() {
                    key.scope = ScopePartition::Shared;
                    self.index.register(key, index);
                }
            }
        }
        self.count = exchanges.len();
        self.index.seal();
        self.members.seal();
    }

    pub(in crate::replay) fn case_members(&self, case: &str) -> Arc<[usize]> {
        self.members.for_case(case)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &str,
        path: &str,
    ) -> CandidateCursor {
        self.select_key(key(source, case, scheme, target, method, Some(path)))
    }

    pub(super) fn select_coarse(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &str,
    ) -> CandidateCursor {
        self.select_key(key(source, case, scheme, target, method, None))
    }

    fn select_key(&self, mut key: HttpKey) -> CandidateCursor {
        let scoped = self.index.lookup(&key);
        key.scope = ScopePartition::Shared;
        scoped.merge(self.index.lookup(&key))
    }
}

fn key(
    source: ReplaySource,
    case: Option<&str>,
    scheme: HttpReplayScheme,
    target: &TargetKey,
    method: &str,
    path: Option<&str>,
) -> HttpKey {
    HttpKey {
        scope: ScopePartition::new(source, case),
        secure: scheme == HttpReplayScheme::Https,
        host: target.host.clone(),
        port: target.port,
        method: method.to_ascii_uppercase(),
        path: path.map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exchange(source: ReplaySource, case: &str, path: &str, shared: bool) -> ReplayHttpExchange {
        ReplayHttpExchange {
            source,
            case_id: Some(case.into()),
            identity: HttpDependencyIdentity {
                scheme: HttpReplayScheme::Http,
                target: TargetKey {
                    host: "api.test".into(),
                    port: 80,
                },
            },
            record: serde_json::from_value(json!({
                "scheme":"http", "method":"post", "uri":path,
                "request_body":{"encoding":"utf8","data":"{}","truncated":false}
            }))
            .unwrap(),
            status: crate::replay::ReplayExchangeStatus::Available,
            shared_origin: shared.then(|| cross_case::SharedOrigin {
                rule_id: "finite-share".into(),
                case_id: case.into(),
                request_fingerprint: "original".into(),
            }),
            lifecycle_prefix: None,
            time_copy_delivery: None,
        }
    }

    #[test]
    fn http_provider_matches_scope_scan_and_keeps_generated_paths_in_coarse_postings() {
        let exchanges = vec![
            exchange(
                ReplaySource::Case,
                "active",
                "/x/source-id?token=original",
                false,
            ),
            exchange(ReplaySource::Case, "other", "/x/source-id", false),
            exchange(ReplaySource::Startup, "origin", "/x/source-id", false),
            exchange(ReplaySource::Case, "other", "/x/source-id", true),
            exchange(ReplaySource::Process, "origin", "/x/source-id", false),
            exchange(ReplaySource::Case, "active", "/unrelated", false),
        ];
        let mut index = Candidates::default();
        index.register(&exchanges);
        for source in [
            ReplaySource::Case,
            ReplaySource::Startup,
            ReplaySource::Process,
        ] {
            let expected = exchanges
                .iter()
                .enumerate()
                .filter(|(_, exchange)| {
                    (exchange.source.matches_scope(source)
                        || source.is_run_owned() && exchange.shared_origin.is_some())
                        && active_http_case_matches(Some("active"), exchange)
                        && uri_path_only(&exchange.record.native.uri) == "/x/source-id"
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            assert_eq!(
                index
                    .select(
                        source,
                        Some("active"),
                        HttpReplayScheme::Http,
                        &exchanges[0].identity.target,
                        "POST",
                        "/x/source-id"
                    )
                    .collect::<Vec<_>>(),
                expected
            );
        }
        assert!(
            index
                .select(
                    ReplaySource::Case,
                    Some("active"),
                    HttpReplayScheme::Http,
                    &exchanges[0].identity.target,
                    "POST",
                    "/x/target-id"
                )
                .next()
                .is_none()
        );
        assert_eq!(
            index
                .select_coarse(
                    ReplaySource::Case,
                    Some("active"),
                    HttpReplayScheme::Http,
                    &exchanges[0].identity.target,
                    "POST"
                )
                .collect::<Vec<_>>(),
            [0, 3, 5]
        );
        assert_eq!(index.case_members("active").as_ref(), [0, 5]);
    }
}
