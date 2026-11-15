//! Fold only exact canonical crypto owners; additional native scope stays intact.
use super::*;

pub fn profile_name(
    definitions: &BTreeMap<String, SignatureDefinition>,
    matches: impl Fn(&SignatureDefinition) -> bool,
) -> Option<String> {
    if definitions.get("default").is_some_and(&matches) {
        return Some("default".into());
    }
    definitions
        .iter()
        .find_map(|(name, value)| matches(value).then(|| name.clone()))
}

pub fn jwt_name(
    definitions: &BTreeMap<String, SignatureDefinition>,
    algorithm: crate::native::SignatureAlgorithm,
    key: &StartupKey,
) -> Option<String> {
    profile_name(definitions, |value| {
        matches!(value,
        SignatureDefinition::Jwt { algorithm: selected, key: selected_key }
        if *selected == algorithm && selected_key == key)
    })
}

pub struct Entry {
    pub api: String,
    pub surface: &'static str,
    pub container: Option<&'static str>,
    pub name: Option<String>,
    pub value: Value,
    pub canonical: NativeRule,
}

pub fn entry(
    rule: &NativeRule,
    definitions: &BTreeMap<String, SignatureDefinition>,
    context: &crate::AuthoringContext<'_>,
) -> Result<Option<Entry>> {
    let api = rule.selector.api.as_deref().unwrap_or("*");
    let (surface, container, name, value, canonical) = match &rule.effect {
        NativeEffect::InputJwt(effect) => {
            let Some(profile) = jwt_name(definitions, effect.algorithm, &effect.signing_key) else {
                return Ok(None);
            };
            match &effect.location {
                InputTokenLocation::BearerHeader { name }
                | InputTokenLocation::RawHeader { name } => {
                    let selected = Header {
                        signature: profile,
                        scheme: if matches!(
                            effect.location,
                            InputTokenLocation::BearerHeader { .. }
                        ) {
                            HeaderScheme::Bearer
                        } else {
                            HeaderScheme::Raw
                        },
                        proof: None,
                    };
                    let canonical =
                        lower(api, Position::Header(name, &selected), definitions, context)?;
                    let mut value = Mapping::new();
                    value.insert("signature".into(), selected.signature.into());
                    if matches!(selected.scheme, HeaderScheme::Bearer) {
                        value.insert("scheme".into(), "bearer".into());
                    }
                    (
                        "request",
                        Some("headers"),
                        Some(name.clone()),
                        Value::Mapping(value),
                        canonical,
                    )
                }
                InputTokenLocation::Query { name } => {
                    let selected = Reference::Name(profile.clone());
                    let canonical =
                        lower(api, Position::Query(name, &selected), definitions, context)?;
                    (
                        "request",
                        Some("query"),
                        Some(name.clone()),
                        profile.into(),
                        canonical,
                    )
                }
                InputTokenLocation::SocketIoConnect { .. } => return Ok(None),
            }
        }
        NativeEffect::InputSignedTimestamp(effect) => {
            let Some(profile) = profile_name(definitions, |value| {
                matches!(value,
                SignatureDefinition::Md5SortedFields { key } if key == &effect.signing_key)
            }) else {
                return Ok(None);
            };
            let selected = Body {
                signature: profile,
                fields: effect.fields.clone(),
                timestamp_pointer: effect.timestamp_pointer.clone(),
                signature_pointer: effect.signature_pointer.clone(),
                secret_parameter: effect.secret_parameter.clone(),
                proof: None,
            };
            let canonical = lower(api, Position::Body(&selected), definitions, context)?;
            (
                "request",
                None,
                Some("body".into()),
                serde_yaml::to_value(selected)?,
                canonical,
            )
        }
        NativeEffect::ResponseJwt(effect) => {
            let ResponseSigningKey::Startup { source } = &effect.signing_key else {
                return Ok(None);
            };
            let Some(profile) = jwt_name(definitions, effect.algorithm, source) else {
                return Ok(None);
            };
            let mut selected = JwtResponse::new(profile);
            selected.query = effect.url_query_param.clone();
            selected.nonces = effect
                .nonces
                .iter()
                .map(|nonce| Nonce {
                    pointer: nonce.contract.pointer.clone(),
                    format: nonce.contract.format.clone(),
                    echo_query_param: nonce.contract.echo_query_param.clone(),
                    proof: None,
                })
                .collect();
            selected.expires_at = effect.expires_at.clone();
            selected.expires_at_format = effect.expires_at_format;
            selected.issued_at = effect.issued_at.clone();
            selected.ttl = effect.ttl.clone();
            let (container, name, position) = if let Some(location) = &effect.location {
                (
                    "headers",
                    location.header.clone(),
                    Position::ResponseHeader(&location.header, &selected),
                )
            } else {
                (
                    "json",
                    effect.pointer.clone(),
                    Position::Json(&effect.pointer, &selected),
                )
            };
            let canonical = lower(api, position, definitions, context)?;
            (
                "response",
                Some(container),
                Some(name),
                serde_yaml::to_value(selected)?,
                canonical,
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(Entry {
        api: api.into(),
        surface,
        container,
        name,
        value,
        canonical,
    }))
}

pub fn mapping<'a>(parent: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping> {
    parent
        .entry(key.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .with_context(|| format!("API signature {key} requires a mapping"))
}

pub fn compact(
    rule: &PolicyRule,
    definitions: &BTreeMap<String, SignatureDefinition>,
    root: &mut Mapping,
    context: &crate::AuthoringContext<'_>,
) -> Result<bool> {
    let Some(native) = rule.as_native().filter(|_| generated(rule)) else {
        return Ok(false);
    };
    if let NativeEffect::InputJwt(effect) = &native.effect
        && let InputTokenLocation::SocketIoConnect { namespace, pointer } = &effect.location
    {
        let Some(profile) = jwt_name(definitions, effect.algorithm, &effect.signing_key) else {
            return Ok(false);
        };
        let api = native.selector.api.as_deref().unwrap_or("*");
        let reference = Reference::Name(profile.clone());
        let canonical = lower(
            api,
            Position::SocketIoConnect(namespace, pointer, &reference),
            definitions,
            context,
        )?;
        if without_proofs(native.clone()) != canonical {
            return Ok(false);
        }
        let positions = mapping(
            mapping(
                mapping(mapping(mapping(root, "api")?, api)?, "request")?,
                "socketio_connect",
            )?,
            namespace,
        )?;
        ensure!(
            !positions.contains_key(pointer),
            "duplicate API signature position"
        );
        positions.insert(pointer.clone().into(), profile.into());
        return Ok(true);
    }
    let Some(entry) = entry(native, definitions, context)? else {
        return Ok(false);
    };
    if without_proofs(native.clone()) != entry.canonical {
        return Ok(false);
    }
    let positions = mapping(mapping(mapping(root, "api")?, &entry.api)?, entry.surface)?;
    let positions = if let Some(container) = entry.container {
        mapping(positions, container)?
    } else {
        positions
    };
    let name = entry.name.context("API signature position has no name")?;
    ensure!(
        !positions.contains_key(&name),
        "duplicate API signature position"
    );
    positions.insert(name.into(), entry.value);
    Ok(true)
}
