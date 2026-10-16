//! Source confirmation converts observations into method-specific registrations.
use anyhow::{Result, ensure};

use crate::{
    RecordingApi,
    config::{AppConfig, HttpSourceRoutes},
};

pub(super) fn confirmed(config: &AppConfig) -> HttpSourceRoutes {
    config.http_gateway.source_routes.clone()
}

pub(super) fn submitted(
    config: &AppConfig,
    candidates: &[String],
    existing: &HttpSourceRoutes,
    explicit: Vec<String>,
) -> Result<HttpSourceRoutes> {
    let candidates = candidates
        .iter()
        .map(|s| s.parse::<RecordingApi>())
        .collect::<Result<Vec<_>>>()?;
    let routes = HttpSourceRoutes::try_from(explicit)?;
    for route in routes.entries() {
        ensure!(
            route.is_covered_by(&config.http_gateway.rules),
            "Source registration is outside recording scope: {route}"
        );
        ensure!(
            candidates.iter().any(|candidate| {
                candidate.method() == route.method()
                    && crate::path_pattern::matches_path_pattern(
                        route.path_pattern(),
                        candidate.path_pattern(),
                    )
            }),
            "HTTP Source registration {route} covers no candidate in this batch"
        );
    }
    let registrations = routes.entries().map(ToString::to_string);
    let combined = existing.merged(registrations)?;
    ensure!(
        candidates.iter().all(|candidate| {
            combined
                .resolve(candidate.method().as_str(), candidate.path_pattern())
                .is_some()
        }),
        "Source confirmations do not cover every candidate method/path in this batch"
    );
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_pattern_never_confirms_an_observed_post_source() {
        let config = AppConfig::default();
        let existing = vec!["GET /items/*".into()].try_into().unwrap();
        let candidates = vec!["POST /items/upload".into()];
        assert!(submitted(&config, &candidates, &existing, vec!["GET /items/*".into()]).is_err());
        let confirmed = submitted(
            &config,
            &candidates,
            &existing,
            vec!["POST /items/upload".into()],
        )
        .unwrap();
        assert_eq!(
            confirmed
                .resolve("GET", "/items/upload")
                .unwrap()
                .to_string(),
            "GET /items/*"
        );
        assert_eq!(
            confirmed
                .resolve("POST", "/items/upload")
                .unwrap()
                .to_string(),
            "POST /items/upload"
        );
    }

    #[test]
    fn static_confirmation_is_preserved_when_later_confirming_a_pattern() {
        let config = AppConfig::default();
        let existing = vec!["GET /items/upload".into()].try_into().unwrap();
        let confirmed = submitted(
            &config,
            &["GET /items/42".into()],
            &existing,
            vec!["GET /items/*".into()],
        )
        .unwrap();
        assert_eq!(confirmed.entries().count(), 2);
        assert_eq!(
            confirmed
                .resolve("GET", "/items/upload")
                .unwrap()
                .to_string(),
            "GET /items/upload"
        );
        assert!(submitted(&config, &["POST /items/upload".into()], &confirmed, vec![]).is_err());
    }
}
