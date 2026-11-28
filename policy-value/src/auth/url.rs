//! Match credentials at their existing URL query locations.
use std::{borrow::Cow, collections::BTreeSet};

use serde_json::Value;
use traffic_contract::compare::{AnchorClocks, LeafContext, LeafObservations};

use super::Matcher;

pub(super) fn compare(
    matcher: &Matcher,
    source: &str,
    target: &str,
    clocks: AnchorClocks,
) -> Option<LeafObservations> {
    let a = Query::parse(source)?;
    let b = Query::parse(target)?;
    if a.prefix != b.prefix || a.fragment != b.fragment {
        return None;
    }
    if a.members
        .clone()
        .any(|part| part == "X-Amz-Algorithm=AWS4-HMAC-SHA256")
    {
        return compare_presigned(source, target, &a, &b, clocks);
    }
    matcher.jwt.as_ref()?;
    let mut pairs = a.members.zip(b.members);
    let mut seen = BTreeSet::new();
    let mut observed = LeafObservations::default();
    let mut changed = false;
    for (source, target) in pairs.by_ref() {
        let (name, source_value) = parse_member(source)?;
        if !seen.insert(decoded_parameter(name)?) {
            return None;
        }
        if source == target {
            continue;
        }
        let (target_name, target_value) = parse_member(target)?;
        if name != target_name {
            return None;
        }
        let source_value = decoded_parameter(source_value?)?;
        let target_value = decoded_parameter(target_value?)?;
        let pair = matcher.jwt(&source_value, &target_value, clocks)?;
        observed.identities.extend(pair.identities);
        observed.time_validations += pair.time_validations;
        changed = true;
    }
    (changed && seen.len() == a.count && a.count == b.count).then_some(observed)
}

fn parse_member(raw: &str) -> Option<(&str, Option<&str>)> {
    let (name, value) = raw
        .split_once('=')
        .map_or((raw, None), |(n, v)| (n, Some(v)));
    (!name.is_empty()).then_some((name, value))
}

struct Query<'a> {
    prefix: &'a str,
    fragment: Option<&'a str>,
    members: std::str::Split<'a, char>,
    count: usize,
}

impl<'a> Query<'a> {
    fn parse(raw: &'a str) -> Option<Self> {
        if raw.len() > 16_384
            || !(raw.starts_with('/') || raw.starts_with("http"))
            || raw.bytes().any(|byte| byte.is_ascii_control())
        {
            return None;
        }
        let (head, fragment) = raw
            .split_once('#')
            .map_or((raw, None), |(a, b)| (a, Some(b)));
        let (prefix, query) = head.split_once('?')?;
        if !prefix.starts_with('/') || prefix.starts_with("//") {
            let url = ::url::Url::parse(raw).ok()?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return None;
            }
        }
        let members = query.split('&');
        let count = members.clone().take(65).count();
        (count <= 64).then_some(Self {
            prefix,
            fragment,
            members,
            count,
        })
    }
}

fn compare_presigned(
    source: &str,
    target: &str,
    a: &Query<'_>,
    b: &Query<'_>,
    clocks: AnchorClocks,
) -> Option<LeafObservations> {
    let complete = |query: &Query<'_>| {
        let mut expires = false;
        let mut headers = false;
        let mut algorithm = false;
        for member in query.members.clone() {
            if let Some((name, value)) = member.split_once('=') {
                match name {
                    "X-Amz-Expires" => {
                        expires = value
                            .parse::<u32>()
                            .is_ok_and(|n| (1..=604800).contains(&n))
                    }
                    "X-Amz-SignedHeaders" => {
                        headers = decoded_parameter(value)
                            .is_some_and(|value| value.split(';').any(|name| name == "host"))
                    }
                    "X-Amz-Algorithm" => algorithm = value == "AWS4-HMAC-SHA256",
                    _ => {}
                }
            }
        }
        expires && headers && algorithm
    };
    if !complete(a) || !complete(b) {
        return None;
    }
    let stored = |raw: &str| {
        Value::String(if raw.starts_with('/') {
            format!("https://replay.invalid{raw}")
        } else {
            raw.to_owned()
        })
    };
    let source = stored(source);
    let target = stored(target);
    crate::formats::aws_sigv4(LeafContext {
        source: &source,
        target: &target,
        source_pointer: "",
        target_pointer: "",
        source_root: &source,
        target_root: &target,
        clocks,
    })
    .ok()
}

pub(super) fn decoded_parameter(raw: &str) -> Option<Cow<'_, str>> {
    if !raw
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'+' | b'%'))
    {
        return Some(Cow::Borrowed(raw));
    }
    let mut output = Vec::with_capacity(raw.len());
    let mut remaining = raw.as_bytes();
    while let Some((&byte, rest)) = remaining.split_first() {
        remaining = rest;
        match byte {
            b'+' => output.push(b' '),
            b'%' => {
                let (encoded, rest) = rest.split_at_checked(2)?;
                output.push(u8::from_str_radix(std::str::from_utf8(encoded).ok()?, 16).ok()?);
                remaining = rest;
            }
            byte => output.push(byte),
        }
    }
    String::from_utf8(output).ok().map(Cow::Owned)
}
