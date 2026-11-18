//! Declarative address acquisition in JSON and explicitly decoded embedded documents.
//! The caller owns matching HTTP resources, route registration, I/O and evidence.
mod policy;
mod selector;
mod transform;
pub use policy::ResponseRewritePolicy;
pub use transform::Transform;

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::Range;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use selector::Selector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentCodec {
    Json,
    Yaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFormat {
    Url,
    HostPort,
    Ipv4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolHint {
    #[default]
    Auto,
    Http,
    Https,
    Mysql,
    Redis,
}

impl ProtocolHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http => "http",
            Self::Https => "https",
            Self::Mysql => "mysql",
            Self::Redis => "redis",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeAt {
    pub path: String,
    pub codec: DocumentCodec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressField {
    pub path: String,
    pub format: AddressFormat,
    #[serde(default)]
    pub protocol: ProtocolHint,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRule {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub when: BTreeMap<String, Value>,
    #[serde(default)]
    pub decode: Vec<DecodeAt>,
    #[serde(default)]
    pub transforms: Vec<Transform>,
    #[serde(default)]
    pub fields: Vec<AddressField>,
}

#[derive(Debug, Clone, Copy)]
pub struct RewriteBudget {
    pub max_decoded_bytes: usize,
    pub max_endpoints: usize,
}

impl Default for RewriteBudget {
    fn default() -> Self {
        Self {
            max_decoded_bytes: 64 * 1024 * 1024,
            max_endpoints: 4096,
        }
    }
}

#[derive(Debug)]
struct CompiledRule {
    query: BTreeMap<String, Vec<String>>,
    when: BTreeMap<String, Value>,
    decode: Vec<(Selector, DocumentCodec)>,
    transforms: Vec<transform::CompiledTransform>,
    fields: Vec<CompiledAddress>,
}

#[derive(Debug)]
struct CompiledAddress {
    selector: Selector,
    format: AddressFormat,
    protocol: ProtocolHint,
    recursive: bool,
    port_field: Option<String>,
}

#[derive(Debug)]
pub struct CompiledRewrite {
    rules: Vec<CompiledRule>,
}

impl CompiledRewrite {
    /// Compile selectors once when the project's rules are admitted.
    pub fn compile(rules: &[DocumentRule]) -> Result<Self> {
        ensure!(
            !rules.is_empty() && rules.len() <= 4096,
            "response rewrite requires 1..4096 document rules"
        );
        let rules = rules
            .iter()
            .map(|rule| {
                ensure!(
                    rule.query
                        .iter()
                        .all(|(key, values)| !key.is_empty() && !values.is_empty()),
                    "response query predicates require a key and accepted values"
                );
                for pointer in rule.when.keys() {
                    Selector::compile(pointer)?;
                    ensure!(
                        !pointer.split('/').any(|part| part == "*"),
                        "response when predicates require exact JSON pointers"
                    );
                }
                ensure!(
                    rule.decode.len() <= 8,
                    "embedded response decoding exceeds eight levels"
                );
                ensure!(
                    !rule.fields.is_empty() || !rule.transforms.is_empty(),
                    "response rewrite requires address fields or transforms"
                );
                ensure!(
                    rule.fields.len() <= 4096 && rule.transforms.len() <= 128,
                    "response rewrite exceeds its field or transform budget"
                );
                let decode = rule
                    .decode
                    .iter()
                    .map(|step| Ok((Selector::compile(&step.path)?, step.codec)))
                    .collect::<Result<Vec<_>>>()?;
                let fields = rule
                    .fields
                    .iter()
                    .map(|field| {
                        ensure!(
                            (field.format == AddressFormat::Ipv4) == field.port_field.is_some(),
                            "IPv4 response fields require their sibling port_field"
                        );
                        ensure!(
                            field
                                .port_field
                                .as_ref()
                                .is_none_or(|field| !field.is_empty()),
                            "response port_field is empty"
                        );
                        Ok(CompiledAddress {
                            selector: Selector::compile(&field.path)?,
                            format: field.format,
                            protocol: field.protocol,
                            recursive: field.recursive,
                            port_field: field.port_field.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let transforms = rule
                    .transforms
                    .iter()
                    .map(transform::CompiledTransform::compile)
                    .collect::<Result<_>>()?;
                Ok(CompiledRule {
                    query: rule.query.clone(),
                    when: rule.when.clone(),
                    decode,
                    transforms,
                    fields,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules })
    }

    /// Parse each selected embedded document once. Discovery returns an immutable
    /// route inventory before the caller allocates addresses or changes bytes.
    pub fn inspect(&self, body: &[u8], budget: RewriteBudget) -> Result<Option<RewritePlan>> {
        self.inspect_with_query(body, budget, None)
    }

    pub fn inspect_with_query(
        &self,
        body: &[u8],
        budget: RewriteBudget,
        query: Option<&str>,
    ) -> Result<Option<RewritePlan>> {
        ensure!(
            body.len() <= budget.max_decoded_bytes,
            "response rewrite body exceeds its decoded byte budget"
        );
        let root =
            serde_json::from_slice(body).context("response rewrite body is not valid JSON")?;
        self.inspect_root(root, body.len(), budget, query)
    }

    pub fn inspect_value(
        &self,
        root: Value,
        budget: RewriteBudget,
        query: Option<&str>,
    ) -> Result<Option<RewritePlan>> {
        let size = serde_json::to_vec(&root)?.len();
        ensure!(
            size <= budget.max_decoded_bytes,
            "response rewrite value exceeds its decoded byte budget"
        );
        self.inspect_root(root, size, budget, query)
    }

    fn inspect_root(
        &self,
        root: Value,
        size: usize,
        budget: RewriteBudget,
        query: Option<&str>,
    ) -> Result<Option<RewritePlan>> {
        let mut plan = RewritePlan {
            documents: vec![Document {
                value: root,
                parent: None,
            }],
            endpoints: BTreeMap::new(),
            patches: BTreeMap::new(),
            transformed: false,
        };
        let mut decoded = HashMap::new();
        let mut decoded_bytes = size;
        let query: Vec<_> =
            url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()).collect();
        for rule in &self.rules {
            if !rule.query.iter().all(|(key, values)| {
                query.iter().any(|(name, value)| {
                    name == key && values.iter().any(|expected| expected == value)
                })
            }) || !rule
                .when
                .iter()
                .all(|(path, value)| plan.documents[0].value.pointer(path) == Some(value))
            {
                continue;
            }
            let mut current = vec![0];
            for (selector, codec) in &rule.decode {
                let mut next = Vec::new();
                for parent in current {
                    for path in selector.select(&plan.documents[parent].value)? {
                        let key = (parent, path.clone());
                        if let Some((previous_codec, index)) = decoded.get(&key) {
                            ensure!(
                                previous_codec == codec,
                                "embedded response document has conflicting codecs"
                            );
                            next.push(*index);
                            continue;
                        }
                        let text = plan.documents[parent]
                            .value
                            .pointer(&path)
                            .and_then(Value::as_str)
                            .context("selected embedded response document must be a string")?;
                        decoded_bytes = decoded_bytes
                            .checked_add(text.len())
                            .context("response rewrite decoded byte count overflowed")?;
                        ensure!(
                            decoded_bytes <= budget.max_decoded_bytes,
                            "embedded response documents exceed the decoded byte budget"
                        );
                        let value = match codec {
                            DocumentCodec::Json => serde_json::from_str(text)
                                .context("embedded response document is not valid JSON")?,
                            DocumentCodec::Yaml => serde_yaml::from_str(text)
                                .context("embedded response document is not supported YAML")?,
                        };
                        let index = plan.documents.len();
                        plan.documents.push(Document {
                            value,
                            parent: Some((parent, path, *codec)),
                        });
                        decoded.insert(key, (*codec, index));
                        next.push(index);
                    }
                }
                current = next;
            }
            for document in current {
                for transform in &rule.transforms {
                    plan.transformed |= transform.apply(&mut plan.documents[document].value)?;
                }
                for field in &rule.fields {
                    for path in field.selector.select(&plan.documents[document].value)? {
                        let value = plan.documents[document]
                            .value
                            .pointer(&path)
                            .context("selected response address disappeared")?;
                        let mut leaves = Vec::new();
                        scalar_paths(value, &path, field.recursive, 0, &mut leaves)?;
                        for path in leaves {
                            let text = plan.documents[document]
                                .value
                                .pointer(&path)
                                .and_then(Value::as_str)
                                .context("selected response address must be a string")?;
                            let port = field
                                .port_field
                                .as_ref()
                                .map(|name| {
                                    let (parent, _) = path
                                        .rsplit_once('/')
                                        .context("response IPv4 address has no parent")?;
                                    let value = plan.documents[document]
                                        .value
                                        .pointer(parent)
                                        .and_then(|value| value.get(name))
                                        .context("response IPv4 port_field is missing")?;
                                    let port = match value {
                                        Value::String(text) => text.parse::<u16>()?,
                                        Value::Number(number) => u16::try_from(
                                            number
                                                .as_u64()
                                                .context("response IPv4 port is not an integer")?,
                                        )?,
                                        _ => anyhow::bail!(
                                            "response IPv4 port must be an integer or string"
                                        ),
                                    };
                                    Ok::<_, anyhow::Error>(port)
                                })
                                .transpose()?;
                            if let Some((endpoint, host)) =
                                inspect_address(text, field.format, field.protocol, port)?
                            {
                                ensure!(
                                    plan.patches.len() < budget.max_endpoints,
                                    "response address occurrences exceed their budget"
                                );
                                let patch = Patch {
                                    alias: endpoint.alias.clone(),
                                    port: endpoint.port,
                                    host,
                                    ip_only: field.format == AddressFormat::Ipv4,
                                };
                                if let Some(previous) =
                                    plan.patches.insert((document, path), patch.clone())
                                {
                                    ensure!(
                                        previous == patch,
                                        "response address declarations overlap incompatibly"
                                    );
                                }
                                if let Some(previous) = plan
                                    .endpoints
                                    .insert(endpoint.alias.clone(), endpoint.clone())
                                {
                                    ensure!(
                                        previous == endpoint,
                                        "response address aliases conflict"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok((plan.transformed || !plan.patches.is_empty()).then_some(plan))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub alias: String,
    pub upstream_ip: Ipv4Addr,
    pub port: u16,
    pub protocol: ProtocolHint,
    pub upstream_authority: Option<String>,
}

#[derive(Debug)]
struct Document {
    value: Value,
    parent: Option<(usize, String, DocumentCodec)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Patch {
    alias: String,
    port: u16,
    host: Option<Range<usize>>,
    ip_only: bool,
}

#[derive(Debug)]
pub struct RewritePlan {
    documents: Vec<Document>,
    endpoints: BTreeMap<String, Endpoint>,
    patches: BTreeMap<(usize, String), Patch>,
    transformed: bool,
}

impl RewritePlan {
    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        self.endpoints.values()
    }

    pub fn materialize(self, routes: &BTreeMap<String, Ipv4Addr>) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.materialize_value(routes)?).map_err(Into::into)
    }

    pub fn materialize_value(mut self, routes: &BTreeMap<String, Ipv4Addr>) -> Result<Value> {
        for ((document, path), patch) in self.patches {
            let ip = routes
                .get(&patch.alias)
                .context("response endpoint has no registered route")?;
            let value = self.documents[document]
                .value
                .pointer_mut(&path)
                .context("response address disappeared before materialization")?;
            let Value::String(text) = value else {
                anyhow::bail!("response address changed type before materialization");
            };
            match patch.host {
                Some(range) => text.replace_range(range, &patch.alias),
                None if patch.ip_only => *text = ip.to_string(),
                None => *text = format!("{ip}:{}", patch.port),
            }
        }
        for index in (1..self.documents.len()).rev() {
            let document = self.documents.pop().expect("embedded document exists");
            let (parent, path, codec) =
                document.parent.context("embedded document has no parent")?;
            ensure!(
                parent < index,
                "embedded response document has an invalid parent"
            );
            let rendered = match codec {
                DocumentCodec::Json => serde_json::to_string(&document.value)?,
                DocumentCodec::Yaml => serde_yaml::to_string(&document.value)?,
            };
            *self.documents[parent]
                .value
                .pointer_mut(&path)
                .context("embedded response document disappeared")? = Value::String(rendered);
        }
        Ok(self.documents.remove(0).value)
    }
}

fn inspect_address(
    text: &str,
    format: AddressFormat,
    hint: ProtocolHint,
    port: Option<u16>,
) -> Result<Option<(Endpoint, Option<Range<usize>>)>> {
    if matches!(format, AddressFormat::HostPort | AddressFormat::Ipv4) {
        let address = if format == AddressFormat::Ipv4 {
            text.parse::<Ipv4Addr>()
                .map(|ip| SocketAddrV4::new(ip, port.unwrap_or_default()))
        } else {
            text.parse::<SocketAddrV4>()
        };
        let Ok(address) = address else {
            return Ok(None);
        };
        ensure!(address.port() != 0, "response endpoint has a zero port");
        let ip = *address.ip();
        usable_ip(ip)?;
        return Ok(Some((
            Endpoint {
                alias: format!(
                    "{}-{}-{}.trp.test",
                    hint.as_str(),
                    ip.to_string().replace('.', "-"),
                    address.port()
                ),
                upstream_ip: ip,
                port: address.port(),
                protocol: hint,
                upstream_authority: None,
            },
            None,
        )));
    }
    ensure!(
        text.trim() == text && !text.chars().any(|ch| ch.is_control() || ch == '\\'),
        "response URL has ambiguous separators"
    );
    let url = Url::parse(text).context("selected response URL is invalid")?;
    let protocol = match url.scheme() {
        "http" => ProtocolHint::Http,
        "https" => ProtocolHint::Https,
        _ => anyhow::bail!("response URL requires HTTP or HTTPS"),
    };
    ensure!(
        hint == ProtocolHint::Auto || hint == protocol,
        "response URL protocol conflicts with its declaration"
    );
    let ip = match url.host() {
        Some(Host::Ipv4(ip)) => ip,
        Some(Host::Domain(_)) => return Ok(None),
        _ => anyhow::bail!("response URL requires an IPv4 host or domain"),
    };
    usable_ip(ip)?;
    let port = url
        .port_or_known_default()
        .context("response URL has no effective port")?;
    ensure!(port != 0, "response URL has a zero port");
    let start = text.find("://").context("response URL has no authority")? + 3;
    let end = text[start..]
        .find(['/', '?', '#'])
        .map_or(text.len(), |offset| start + offset);
    let host_start = text[start..end]
        .rfind('@')
        .map_or(start, |offset| start + offset + 1);
    let host_end = text[host_start..end]
        .find(':')
        .map_or(end, |offset| host_start + offset);
    ensure!(
        text[host_start..host_end] == ip.to_string(),
        "response URL requires a canonical IPv4 host"
    );
    let authority_hash = format!("{:x}", Sha256::digest(&text[host_start..end]));
    Ok(Some((
        Endpoint {
            alias: format!("{}-{}.trp.test", protocol.as_str(), &authority_hash[..24]),
            upstream_ip: ip,
            port,
            protocol,
            upstream_authority: Some(text[host_start..end].into()),
        },
        Some(host_start..host_end),
    )))
}

fn usable_ip(ip: Ipv4Addr) -> Result<()> {
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        "response endpoint has an unusable upstream address"
    );
    Ok(())
}

fn scalar_paths(
    value: &Value,
    path: &str,
    recursive: bool,
    depth: usize,
    output: &mut Vec<String>,
) -> Result<()> {
    ensure!(
        depth <= 64 && output.len() <= 4096,
        "response address selection exceeds its traversal budget"
    );
    match value {
        Value::String(_) => output.push(path.into()),
        Value::Array(values) if recursive => {
            for (index, value) in values.iter().enumerate() {
                scalar_paths(value, &format!("{path}/{index}"), true, depth + 1, output)?;
            }
        }
        Value::Object(values) if recursive => {
            for (name, value) in values {
                scalar_paths(
                    value,
                    &format!("{path}/{}", selector::escape(name)),
                    true,
                    depth + 1,
                    output,
                )?;
            }
        }
        Value::Null => (),
        _ if recursive => (),
        _ => anyhow::bail!("selected response address must be a string"),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
