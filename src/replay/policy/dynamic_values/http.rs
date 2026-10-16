//! Automatic references in decoded HTTP paths, query values and JSON bodies.
use super::{
    DynamicDecision, DynamicValueCapture, DynamicValueType, DynamicValues, IdentityPair, strings,
};
use crate::replay::TargetKey;
use anyhow::{Context, Result};

pub(in crate::replay) struct HttpInput<'a> {
    pub uri: &'a str,
    pub body: &'a [u8],
    pub request_started_at: Option<chrono::DateTime<chrono::Utc>>,
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
        let scope = super::scopes::ResourceContext {
            protocol: crate::policy::Protocol::Http,
            target,
            database: None,
            username: None,
            operation: method,
        };
        if self.selected_scoped(case, scope, true).is_empty()
            && self.selected_scoped(case, scope, false).is_empty()
        {
            return None;
        }
        Some((|| {
            let mut decision = DynamicDecision::default();
            let mut integer_body = None;
            let mut path_capture = false;
            for rule in self.selected_scoped(case, scope, true) {
                let DynamicValueCapture::Http {
                    target: endpoint,
                    method: expected_method,
                    path,
                    json_pointer,
                    path_segment,
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
                let pair = if let Some(segment) = path_segment {
                    path_capture = true;
                    let pair = IdentityPair {
                        source: segment.extract(source_uri)?,
                        target: segment.extract(actual.uri)?,
                    };
                    segment.compare(
                        &pair.source,
                        &pair.target,
                        crate::replay::assertion::time::RequestTimes {
                            source: source.request_started_at,
                            target: actual.request_started_at,
                        },
                    )?;
                    pair
                } else {
                    let pointer = json_pointer
                        .as_deref()
                        .context("HTTP capture pointer absent")?;
                    IdentityPair {
                        source: capture(source_body, pointer, rule.value_type)?,
                        target: capture(actual_body, pointer, rule.value_type)?,
                    }
                };
                self.check_pair(case, rule, &pair, &decision)?;
                if rule.value_type == DynamicValueType::Integer {
                    let body = integer_body.get_or_insert_with(|| {
                        crate::replay::json_order::parse(actual_body)
                            .expect("validated JSON capture")
                    });
                    *body
                        .pointer_mut(json_pointer.as_deref().expect("integer capture pointer"))
                        .expect("validated pointer") = serde_json::from_str(&pair.source)?;
                }
                decision.pairs.push((rule.id.clone(), pair));
            }
            let pairs = self.scoped_pairs(case, scope, &decision);
            Ok(HttpNormalization {
                source_uri: uri(source_uri, &pairs, false)?,
                actual_uri: uri(&actual_uri.to_string(), &pairs, true)?.parse()?,
                source_body: if path_capture {
                    source_body.to_vec()
                } else {
                    strings::normalize(source_body, &pairs, false)?
                },
                actual_body: if path_capture {
                    actual_body.to_vec()
                } else {
                    strings::normalize(
                        &integer_body
                            .map(|body| serde_json::to_vec(&body))
                            .transpose()?
                            .unwrap_or_else(|| actual_body.to_vec()),
                        &pairs,
                        true,
                    )?
                },
                decision,
            })
        })())
    }
}

pub(super) fn capture(body: &[u8], pointer: &str, value_type: DynamicValueType) -> Result<String> {
    if value_type == DynamicValueType::String {
        return strings::capture(body, Some(pointer));
    }
    let body = crate::replay::json_order::parse(body)
        .context("dynamic integer requires complete unique-member JSON")?;
    let value = body
        .pointer(pointer)
        .context("dynamic integer pointer is absent")?;
    anyhow::ensure!(
        value.is_i64() || value.is_u64(),
        "dynamic identity must be a JSON integer"
    );
    Ok(value.to_string())
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

pub(super) fn percent_decode(value: &str) -> Result<Vec<u8>> {
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
