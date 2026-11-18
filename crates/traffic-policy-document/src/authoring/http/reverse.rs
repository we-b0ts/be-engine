//! Fold only generated HTTP declarations that reconstruct the complete native rule.
use super::*;

pub fn field(value: &PathIdentityField) -> Option<PathField> {
    Some(match value {
        PathIdentityField::Exact => PathField::Exact(Exact::Exact),
        PathIdentityField::Random {
            format: PathRandomFormat::Hex,
            length,
        } => PathField::Hex { hex: *length },
        PathIdentityField::Timestamp {
            format,
            timezone,
            mode,
        } => PathField::Timestamp {
            timestamp: format.clone(),
            timezone: timezone.clone(),
            mode: *mode,
        },
        _ => return None,
    })
}

pub fn resource_reference(
    resource: &Resource,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> ResourceReference {
    named
        .iter()
        .find_map(|(name, declaration)| {
            (declaration.resource == *resource).then(|| ResourceReference::Name(name.clone()))
        })
        .unwrap_or_else(|| ResourceReference::Physical(resource.clone()))
}

pub fn entry(rule: &NativeRule, named: &BTreeMap<String, ResourceDeclaration>) -> Option<Request> {
    match &rule.effect {
        NativeEffect::CaptureHttpResponse(effect) => {
            let [host] = effect.authorities.as_slice() else {
                return None;
            };
            let [method] = effect.methods.as_slice() else {
                return None;
            };
            let (capture_urls, documents, policy) = match &effect.contract {
                CaptureResponseContract::Policy(definition) => {
                    (vec![], vec![], Some(definition.clone()))
                }
                CaptureResponseContract::Urls { pointers } => (
                    pointers
                        .iter()
                        .map(|pointer| Annotated::Bare(pointer.contract.clone()))
                        .collect(),
                    vec![],
                    None,
                ),
                CaptureResponseContract::Documents { rules } => (vec![], rules.clone(), None),
                _ => return None,
            };
            let path = match &effect.path {
                CapturePath::Exact { value } | CapturePath::Pattern { value } => value.clone(),
            };
            Some(Request {
                host: host.clone(),
                method: method.clone(),
                path,
                api: None,
                path_identity: None,
                response: Some(Capture {
                    name: None,
                    capture_urls,
                    documents,
                    policy,
                    status_codes: effect.status_codes.clone(),
                    content_types: effect.content_types.clone(),
                }),
                proof: None,
            })
        }
        NativeEffect::Identity(effect)
            if effect.value_type == IdentityType::String
                && effect.format.is_none()
                && effect.read_back.is_empty() =>
        {
            let IdentityCapture::HttpPath { segment } = &effect.capture else {
                return None;
            };
            let resource = rule.selector.resource.as_ref()?;
            if resource.protocol != Protocol::Http {
                return None;
            }
            let fields = segment
                .fields
                .iter()
                .map(|(name, value)| Some((name.clone(), Annotated::Bare(field(&value.contract)?))))
                .collect::<Option<_>>()?;
            Some(Request {
                host: resource.endpoint.to_string(),
                method: rule.selector.operation.clone()?,
                path: rule.selector.path.clone()?,
                api: rule.selector.api.clone(),
                path_identity: Some(PathIdentity {
                    segment: segment.index,
                    template: segment.template.clone(),
                    fields,
                    references: effect
                        .references
                        .iter()
                        .map(|reference| {
                            Annotated::Bare(resource_reference(&reference.contract.resource, named))
                        })
                        .collect(),
                    proof: None,
                }),
                response: None,
                proof: None,
            })
        }
        _ => None,
    }
}

pub fn compact(
    rule: &PolicyRule,
    named: &BTreeMap<String, ResourceDeclaration>,
    root: &mut Mapping,
    context: &crate::AuthoringContext<'_>,
) -> Result<bool> {
    let Some(native) = rule.as_native().filter(|native| {
        generated(rule) || matches!(native.effect, NativeEffect::CaptureHttpResponse(_))
    }) else {
        return Ok(false);
    };
    let Some(mut entry) = entry(native, named) else {
        return Ok(false);
    };
    if let Some(capture) = &mut entry.response {
        // Capture names identify Recorder acquisition rules. Moving an
        // existing rule into declarations must preserve that identity.
        capture.name = Some(native.id.clone());
        let mut unnamed = entry.clone();
        unnamed.response.as_mut().expect("capture position").name = None;
        if lower(&unnamed, named, context).is_ok_and(|canonical| canonical.id == native.id) {
            entry.response.as_mut().expect("capture position").name = None;
        }
    }
    let Ok(canonical) = lower(&entry, named, context) else {
        return Ok(false);
    };
    if without_proofs(native.clone()) != canonical {
        return Ok(false);
    }
    let http = root
        .entry("http".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("HTTP declarations require a mapping")?;
    let collection = if entry.response.is_some() {
        "response_rewrite"
    } else {
        "requests"
    };
    let requests = http
        .entry(collection.into())
        .or_insert_with(|| Value::Sequence(vec![]))
        .as_sequence_mut()
        .context("HTTP requests require a list")?;
    let selected = position(&entry)?;
    for existing in requests.iter() {
        let existing: Request = if collection == "response_rewrite" {
            serde_yaml::from_value::<ResponseRewrite>(existing.clone())?.into()
        } else {
            serde_yaml::from_value::<PathRequest>(existing.clone())?.into()
        };
        ensure!(
            position(&existing)? != selected,
            "duplicate HTTP request position"
        );
    }
    let rendered = if let Some(capture) = entry.response {
        serde_yaml::to_value(ResponseRewrite {
            name: capture.name,
            host: entry.host,
            method: entry.method,
            path: entry.path,
            json_urls: capture.capture_urls,
            documents: capture.documents,
            policy: capture.policy,
            status_codes: capture.status_codes,
            content_types: capture.content_types,
            proof: None,
        })?
    } else {
        serde_yaml::to_value(PathRequest {
            host: entry.host,
            method: entry.method,
            path: entry.path,
            api: entry.api,
            path_identity: entry
                .path_identity
                .context("HTTP path identity is absent")?,
            proof: None,
        })?
    };
    requests.push(rendered);
    Ok(true)
}
