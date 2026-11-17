//! Startup gateway policy input; Recorder capture policy remains independent.

use anyhow::{Context, Result, ensure};
use brz_http_gateway::{RouteRule, RouteTable, RoutesConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(super) struct ApiPolicy {
    pub(super) json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Document {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    case_limit: Option<u64>,
    #[serde(default)]
    includes: Vec<PathRule>,
    #[serde(default)]
    excludes: Vec<PathRule>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PathRule {
    path: String,
    #[serde(default, rename = "match")]
    kind: MatchKind,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum MatchKind {
    #[default]
    Prefix,
    Exact,
}

impl ApiPolicy {
    pub(super) fn load(path: &Path) -> Result<Self> {
        ensure!(
            path.is_file(),
            "gateway API policy must be a regular file: {}",
            path.display()
        );
        let bytes = std::fs::read(path)
            .with_context(|| format!("cannot read gateway API policy {}", path.display()))?;
        Self::parse(&bytes)
            .with_context(|| format!("invalid gateway API policy {}", path.display()))
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        // Serde also accepts struct sequences such as []; require the documented
        // JSON object so a mistaken empty array cannot enable uncapped capture.
        ensure!(
            bytes.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{'),
            "gateway API policy must be a JSON object"
        );
        let document: Document = serde_json::from_slice(bytes)?;
        ensure!(
            document
                .case_limit
                .is_none_or(|limit| limit <= i64::MAX as u64),
            "case-limit must fit a nonnegative Redis integer"
        );
        for rule in document.includes.iter().chain(&document.excludes) {
            let uri: hyper::Uri = rule.path.parse()?;
            ensure!(
                rule.path.starts_with('/')
                    && uri.path() == rule.path
                    && uri.query().is_none()
                    && !rule.path.contains('#'),
                "API policy rules require an absolute path without query or fragment"
            );
            let paths = match rule.kind {
                MatchKind::Exact => vec![rule.path.clone()],
                MatchKind::Prefix => {
                    ensure!(
                        !rule
                            .path
                            .split('/')
                            .any(|part| part.starts_with([':', '*'])),
                        "API policy prefix rules require literal paths"
                    );
                    let base = rule.path.trim_end_matches('/');
                    vec![
                        if base.is_empty() { "/" } else { base }.to_owned(),
                        format!("{base}/*__breeze_policy_path"),
                    ]
                }
            };
            // Reuse the SDK's router validation, including named segment and
            // terminal catch-all syntax. Matching remains gateway-owned.
            RouteTable::compile(RoutesConfig {
                routes: paths
                    .into_iter()
                    .map(|path| RouteRule {
                        methods: Vec::new(),
                        path,
                        admission: None,
                    })
                    .collect(),
                exclude: Vec::new(),
            })?;
        }
        Ok(Self {
            json: serde_json::to_string(&document)?,
        })
    }
}
