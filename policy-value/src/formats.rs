//! Protocol-shaped leaves share JSON pairing without carrier-specific scopes.
use crate::fields::{GLOBAL_JSON_ID, GlobalField, GlobalUrlFormat, MatchedFormatField};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use traffic_contract::compare::{LeafContext, LeafObservations, VerifiedField};
pub mod jwt;
pub mod template;
pub mod url;
type Check<'a> =
    Box<dyn Fn(LeafContext<'_>) -> Result<LeafObservations, String> + Send + Sync + 'a>;
pub struct FormatChecks<'a> {
    checks: Vec<(String, Check<'a>)>,
    clock_independent: bool,
    captured_bytes: usize,
}
impl FormatChecks<'_> {
    pub fn clock_independent(&self) -> bool {
        self.clock_independent
    }

    pub fn pointers(&self) -> impl Iterator<Item = &str> {
        self.checks.iter().map(|(pointer, _)| pointer.as_str())
    }

    pub fn fields(&self) -> Vec<VerifiedField<'_>> {
        self.checks
            .iter()
            .map(|(pointer, verify)| VerifiedField {
                rule_id: GLOBAL_JSON_ID,
                pointer,
                verifier: verify.as_ref(),
            })
            .collect()
    }

    pub fn retained_bytes(&self) -> usize {
        self.captured_bytes
            + self.checks.capacity() * std::mem::size_of::<(String, Check<'_>)>()
            + self
                .checks
                .iter()
                .map(|(pointer, _)| pointer.capacity() + 128)
                .sum::<usize>()
    }
}

/// Build reusable verifiers from paths already resolved against a prepared Source.
pub fn checks_at_matches<'a, Owner>(
    owner: Owner,
    host: for<'host> fn(&'host Owner) -> &'host dyn FormatHost,
    source: &serde_json::Value,
    matched: &[MatchedFormatField],
) -> Result<FormatChecks<'a>>
where
    Owner: Clone + Send + Sync + 'a,
{
    let mut checks = Vec::with_capacity(matched.len());
    let mut clock_independent = true;
    let mut captured_bytes = 0;
    for field in matched {
        let declaration = &host(&owner).fields()[&field.pattern];
        if matches!(declaration, GlobalField::Url { .. }) {
            require_url_scalar(source, &field.pointer)?;
        }
        clock_independent &= matches!(declaration, GlobalField::Template { .. });
        let pattern = field.pattern.clone();
        captured_bytes += pattern.capacity() + std::mem::size_of::<Owner>();
        let owner = owner.clone();
        let verify: Check<'a> = Box::new(move |context| {
            let plan = host(&owner);
            match &plan.fields()[&pattern] {
                GlobalField::Template { formats } => {
                    template::compare(context, formats, plan.policies())
                }
                GlobalField::Jwt { signature } => jwt::compare(context, plan, signature),
                GlobalField::Url { formats } => compare_url(context, plan, formats),
                _ => unreachable!("matched protocol field changed kind"),
            }
        });
        checks.push((field.pointer.clone(), verify));
    }
    Ok(FormatChecks {
        checks,
        clock_independent,
        captured_bytes,
    })
}

pub fn checks<'a>(
    plan: &'a dyn FormatHost,
    source: &serde_json::Value,
) -> anyhow::Result<FormatChecks<'a>> {
    let mut checks: Vec<(String, Check<'a>)> = Vec::new();
    let mut clock_independent = true;
    for (pattern, field) in plan.fields() {
        if let GlobalField::Template { formats } = field {
            for pointer in plan.select_paths(pattern, source)? {
                checks.push((
                    pointer,
                    Box::new(move |context| template::compare(context, formats, plan.policies())),
                ));
            }
            continue;
        }
        if let GlobalField::Jwt { signature } = field {
            for pointer in plan.select_paths(pattern, source)? {
                clock_independent = false;
                checks.push((
                    pointer,
                    Box::new(move |context| jwt::compare(context, plan, signature)),
                ));
            }
            continue;
        }
        let GlobalField::Url { formats } = field else {
            continue;
        };
        for pointer in plan.select_paths(pattern, source)? {
            clock_independent = false;
            require_url_scalar(source, &pointer)?;
            checks.push((
                pointer,
                Box::new(move |context| compare_url(context, plan, formats)),
            ));
        }
    }
    Ok(FormatChecks {
        checks,
        clock_independent,
        captured_bytes: 0,
    })
}

fn require_url_scalar(source: &serde_json::Value, pointer: &str) -> Result<()> {
    anyhow::ensure!(
        source
            .pointer(pointer)
            .is_some_and(|value| !value.is_array() && !value.is_object()),
        "URL format requires a scalar JSON leaf"
    );
    Ok(())
}

fn compare_url(
    context: LeafContext<'_>,
    plan: &dyn FormatHost,
    formats: &[GlobalUrlFormat],
) -> Result<LeafObservations, String> {
    if context.source == context.target && formats.first() != Some(&GlobalUrlFormat::Url) {
        return Ok(LeafObservations::default());
    }
    match formats.first() {
        Some(GlobalUrlFormat::AwsSigv4) => aws_sigv4(context),
        Some(GlobalUrlFormat::Url) => url::compare(context, plan),
        None => Err("URL format unavailable".into()),
    }
}
/// Compact JWT syntax only. Claims and signatures remain opaque token content;
/// correspondence uses the complete typed string, never a decoded field.
pub use traffic_jwt::is_jwt;

/// Recognition is intentionally broader than authentication: duplicate JSON
/// members or a disallowed algorithm cannot turn a compact JWS into an exact
/// equality fallback. The authenticated parser still rejects those documents.
pub fn looks_like_jwt(value: &serde_json::Value) -> bool {
    let Some(token) = value.as_str().filter(|token| token.len() <= 64 * 1024) else {
        return false;
    };
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().take(2).all(|part| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|value| value.is_object())
    })
}

pub(crate) fn aws_sigv4(context: LeafContext<'_>) -> Result<LeafObservations, String> {
    let compare = || -> anyhow::Result<LeafObservations> {
        use anyhow::{Context, ensure};
        let names =
            std::collections::BTreeSet::from(["X-Amz-Date", "X-Amz-Signature", "X-Amz-Credential"]);
        let source = crate::url_query::select(context.source, &names)?;
        let target = crate::url_query::select(context.target, &names)?;
        ensure!(
            source.remainder == target.remainder,
            "unselected URL components differ"
        );
        let date = |query: &crate::url_query::SelectedQuery| {
            traffic_contract::time::parse_timestamp(
                &query.values["X-Amz-Date"],
                traffic_contract::time::TimestampFormat::AmzDate,
                None,
            )
        };
        let a = date(&source)?;
        let b = date(&target)?;
        traffic_contract::time::compare_timestamp_nanos(
            a,
            b,
            traffic_contract::time::TimeMode::PreserveRelative,
            context.clocks.observation(),
        )?;
        let signature = |query: &crate::url_query::SelectedQuery| -> anyhow::Result<()> {
            let value = query.values["X-Amz-Signature"]
                .as_str()
                .context("URL signature must be text")?;
            ensure!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "URL signature must be 64 lowercase hexadecimal characters"
            );
            Ok(())
        };
        signature(&source)?;
        signature(&target)?;
        ensure!(
            crate::url_query::date_segment_remainder(
                &source.values["X-Amz-Credential"],
                '/',
                1,
                a
            )? == crate::url_query::date_segment_remainder(
                &target.values["X-Amz-Credential"],
                '/',
                1,
                b
            )?,
            "URL credential scope differs"
        );
        Ok(LeafObservations {
            time_validations: 1,
            ..Default::default()
        })
    };
    compare().map_err(|error| format!("URL protocol format rejected value: {error:#}"))
}

use anyhow::Result;
use std::collections::BTreeMap;
use traffic_contract::compare::{AnchorClocks, Comparison};
use traffic_policy::PolicyRegistry;

/// The host supplies compiled fields, immutable keys and document comparison.
/// Value-format implementations use these services independently of execution phase.
pub trait FormatHost: Send + Sync {
    fn fields(&self) -> &BTreeMap<String, GlobalField>;
    fn time(&self) -> &crate::fields::TimePolicy;
    fn policies(&self) -> &PolicyRegistry;
    fn signing_key(&self, signature: &str) -> Result<(traffic_jwt::Algorithm, &[u8])>;
    fn auth_matcher(&self) -> Option<crate::auth::Matcher> {
        None
    }
    fn compare_document(
        &self,
        source: &serde_json::Value,
        target: &serde_json::Value,
        fields: &BTreeMap<String, GlobalField>,
        clocks: AnchorClocks,
    ) -> Result<Comparison>;
    fn selectors(&self) -> Option<&crate::fields::FieldSelectors> {
        None
    }
    fn field_plan(&self) -> crate::fields::FieldPlan<'_> {
        crate::fields::FieldPlan::new(self.fields(), self.time(), self.policies())
            .with_selectors(self.selectors())
    }
    fn select_paths(&self, pattern: &str, source: &serde_json::Value) -> Result<Vec<String>> {
        self.field_plan().select_paths(pattern, source)
    }
}

struct FilteredHost<'a> {
    parent: &'a dyn FormatHost,
    fields: BTreeMap<String, GlobalField>,
}
impl FormatHost for FilteredHost<'_> {
    fn fields(&self) -> &BTreeMap<String, GlobalField> {
        &self.fields
    }
    fn time(&self) -> &crate::fields::TimePolicy {
        self.parent.time()
    }
    fn policies(&self) -> &PolicyRegistry {
        self.parent.policies()
    }
    fn selectors(&self) -> Option<&crate::fields::FieldSelectors> {
        self.parent.selectors()
    }
    fn signing_key(&self, signature: &str) -> Result<(traffic_jwt::Algorithm, &[u8])> {
        self.parent.signing_key(signature)
    }
    fn compare_document(
        &self,
        source: &serde_json::Value,
        target: &serde_json::Value,
        fields: &BTreeMap<String, GlobalField>,
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        self.parent.compare_document(source, target, fields, clocks)
    }
}
