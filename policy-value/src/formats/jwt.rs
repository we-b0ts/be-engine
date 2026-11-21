//! Authenticated JWT claims reuse the carrier-independent JSON strategy.
use anyhow::{Context, Result, ensure};

use super::FormatHost;
use crate::fields::GlobalField;
use traffic_contract::compare::{LeafContext, LeafObservations};
use traffic_contract::identity::IdentityPair;
use traffic_jwt::{Token, contract};

const TIME_TOLERANCE_NANOS: i128 = traffic_contract::time::DEFAULT_TOLERANCE.as_nanos() as i128;

pub fn compare(
    context: LeafContext<'_>,
    plan: &dyn FormatHost,
    signature: &str,
) -> Result<LeafObservations, String> {
    compare_authenticated(context, plan, signature)
        .map_err(|error| format!("JWT format rejected value: {error:#}"))
}

fn compare_authenticated(
    context: LeafContext<'_>,
    plan: &dyn FormatHost,
    signature: &str,
) -> Result<LeafObservations> {
    if !super::looks_like_jwt(context.source) {
        ensure!(
            context.source == context.target,
            "unknown JWT value differs"
        );
        return Ok(LeafObservations::default());
    }
    ensure!(super::is_jwt(context.target), "Target changed JWT encoding");
    // A recognized token always authenticates, including byte-identical pairs.
    // This lookup borrows a frozen key snapshot and never performs payload I/O.
    let (algorithm, key) = plan.signing_key(signature)?;
    let parse = |value: &serde_json::Value| -> Result<Token> {
        Token::parse(value.as_str().context("JWT must be a string")?)?
            .context("JWT has unsupported or malformed protected content")
    };
    let source = parse(context.source)?;
    let target = parse(context.target)?;
    ensure!(
        source.algorithm == algorithm && target.algorithm == algorithm,
        "JWT algorithm differs from its signature definition"
    );
    ensure!(
        source.verify(key) && target.verify(key),
        "JWT signature is invalid"
    );
    ensure!(
        source.header_value()? == target.header_value()?,
        "JWT protected header differs"
    );

    let anchors = context
        .clocks
        .observation()
        .source
        .zip(context.clocks.observation().target)
        .map(|(source, target)| [source, target].map(traffic_contract::time::date_nanos));
    let mut source = source.claims;
    let mut target = target.claims;
    let dates = contract::compare_numeric_dates(
        &mut source,
        &mut target,
        anchors,
        TIME_TOLERANCE_NANOS,
        contract::NumericDateMode::Format,
    )
    .map_err(|reason| anyhow::anyhow!("JWT NumericDate contract failed: {reason:?}"))?;

    // JWTs and URLs inside claims stay exact here. Removing those protocol
    // selectors prevents recursive leaf verification while retaining every
    // declared scalar identity, time, duration and unordered-array contract.
    let fields = plan
        .fields()
        .iter()
        .filter(|(_, field)| !matches!(field, GlobalField::Jwt { .. } | GlobalField::Url { .. }))
        .map(|(pointer, field)| (pointer.clone(), field.clone()))
        .collect();
    let comparison = plan.compare_document(&source, &target, &fields, context.clocks)?;
    ensure!(
        comparison.passed(),
        "JWT claims differ: {:?}",
        comparison.differences
    );
    let mut identities = comparison.identity_pairs();
    identities.push(IdentityPair {
        source: serde_json::to_string(context.source)?,
        target: serde_json::to_string(context.target)?,
    });
    Ok(LeafObservations {
        identities,
        time_validations: dates.time_validations
            + comparison.time_validations.values().sum::<usize>(),
        ..Default::default()
    })
}
