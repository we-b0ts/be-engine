//! Automatic references in decoded HTTP paths, query values and JSON bodies.
use super::{DynamicDecision, DynamicValueCapture, DynamicValues, IdentityPair, strings};
use crate::replay::TargetKey;
use anyhow::{Context, Result};

pub(in crate::replay) struct HttpInput<'a> {
    pub uri: &'a str,
    pub body: &'a [u8],
}

pub(in crate::replay) struct HttpNormalization {
    pub source_uri: String,
    pub actual_uri: hyper::Uri,
    pub source_body: Vec<u8>,
    pub actual_body: Vec<u8>,
    pub decision: DynamicDecision,
}

impl DynamicValues {
    pub(in crate::replay) fn http(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        method: &str,
        source: HttpInput<'_>,
        actual: HttpInput<'_>,
    ) -> Option<Result<HttpNormalization>> {
        let case = case?;
        let source_uri = source.uri;
        let actual_uri: hyper::Uri = match actual.uri.parse() {
            Ok(uri) => uri,
            Err(error) => return Some(Err(error.into())),
        };
        let source_body = source.body;
        let actual_body = actual.body;
        if self.selected(case, target).is_empty() {
            return None;
        }
        Some((|| {
            let mut decision = DynamicDecision::default();
            for rule in self.selected(case, target) {
                let DynamicValueCapture::Http {
                    target: endpoint,
                    method: expected_method,
                    path,
                    json_pointer,
                } = &rule.capture
                else {
                    continue;
                };
                if !endpoint.matches(target)
                    || method != expected_method
                    || !super::super::pattern::path_pattern_matches(
                        path,
                        &super::super::pattern::uri_path(source_uri),
                    )
                    || !super::super::pattern::path_pattern_matches(path, actual_uri.path())
                {
                    continue;
                }
                let pair = IdentityPair {
                    source: strings::capture(source_body, Some(json_pointer))?,
                    target: strings::capture(actual_body, Some(json_pointer))?,
                };
                self.check_pair(case, rule, &pair, &decision)?;
                decision.pairs.push((rule.id.clone(), pair));
            }
            let pairs = self.pairs(case, target, &decision);
            Ok(HttpNormalization {
                source_uri: uri(source_uri, &pairs, false)?,
                actual_uri: uri(&actual_uri.to_string(), &pairs, true)?.parse()?,
                source_body: strings::normalize(source_body, &pairs, false)?,
                actual_body: strings::normalize(actual_body, &pairs, true)?,
                decision,
            })
        })())
    }
}

fn uri(value: &str, pairs: &[IdentityPair], actual: bool) -> Result<String> {
    let uri: hyper::Uri = value.parse()?;
    let mut path = Vec::new();
    for segment in uri.path().split('/') {
        let decoded = percent_decode(segment)?;
        let normalized = strings::normalize(&decoded, pairs, actual)?;
        if strings::contains_identity(&decoded, pairs) || normalized != decoded {
            path.push(
                url::form_urlencoded::byte_serialize(&normalized)
                    .collect::<String>()
                    .replace('+', "%20"),
            );
        } else {
            path.push(segment.to_owned());
        }
    }
    let mut out = path.join("/");
    if let Some(query) = uri.query() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = String::from_utf8(strings::normalize(key.as_bytes(), pairs, actual)?)?;
            let value = String::from_utf8(strings::normalize(value.as_bytes(), pairs, actual)?)?;
            serializer.append_pair(&key, &value);
        }
        out.push('?');
        out.push_str(&serializer.finish());
    }
    Ok(out)
}

fn percent_decode(value: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut index = 0;
    while index < value.len() {
        if value.as_bytes()[index] == b'%' {
            let digits = value
                .get(index + 1..index + 3)
                .context("invalid HTTP path escape")?;
            bytes.push(u8::from_str_radix(digits, 16)?);
            index += 3;
        } else {
            bytes.push(value.as_bytes()[index]);
            index += 1;
        }
    }
    Ok(bytes)
}
