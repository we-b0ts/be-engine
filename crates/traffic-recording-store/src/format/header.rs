//! Standard dependency cells and protocol-declared scalar extensions.
use std::{borrow::Cow, io::Write, num::NonZeroU64};

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use traffic_model::recording::identity::IdentityKind;
use traffic_protocol::{
    capture::RecordingLayout, connection::endpoint_from_addr, observation::format_endpoint,
};
use uuid::Uuid;

use crate::dependency_columns::{ReadTerms, WriteTerms};

use super::{
    atoms, reference,
    row::{DependencyPrefix, Optional, ProtocolExtension},
};

#[derive(Default)]
pub struct RowLayout {
    pub declaration: Option<RecordingLayout>,
    pub target: Option<String>,
    pub upstream: Option<String>,
}

pub(super) struct RecordProjection {
    pub capture: Map<String, Value>,
    pub native: Map<String, Value>,
    pub outcome: Value,
    pub complete: bool,
}

impl RecordProjection {
    pub(super) fn project(
        &mut self,
        terms: &mut WriteTerms,
        layout: &RowLayout,
    ) -> Result<(DependencyPrefix<'static>, Vec<u8>)> {
        let epoch = terms.recording_id();
        let process_epoch = self.capture.remove("process_epoch");
        ensure!(
            process_epoch.as_ref().and_then(Value::as_str) == Some(terms.process_epoch()),
            "dependency belongs to a different process epoch"
        );
        let sequence = self
            .capture
            .remove("sequence")
            .and_then(|value| value.as_u64())
            .and_then(NonZeroU64::new)
            .context("dependency has no sequence")?;
        let dependency_id = IdentityKind::Dependency.bridge(epoch, sequence.get());
        let derive_exchange = value_id(self.capture.get("exchange_id")) == Some(dependency_id);
        if derive_exchange {
            self.capture.remove("exchange_id");
        }
        let protocol = layout
            .declaration
            .map(|layout| layout.protocol.to_owned())
            .or_else(|| {
                self.capture
                    .get("protocol_ref")
                    .and_then(|reference| reference.get("protocol"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let (case, case_fields) = self.take_case();
        let (target, address_fields) = self.take_target(layout.target.as_deref());
        let ref_form = reference::project(&mut self.capture, &self.native, protocol.as_deref());
        let derive_native = value_id(self.native.get("id")) == Some(dependency_id);
        if derive_native {
            self.native.remove("id");
        }
        let mut upstream = take_text(self.native.remove("upstream_addr"))?;
        let mut projected_upstream = false;
        if matches!(upstream, Optional::Absent)
            && let Some(address) = &layout.upstream
        {
            projected_upstream = true;
            upstream = Optional::Present(Cow::Owned(address.clone()));
        }
        let prefix = DependencyPrefix {
            sequence,
            protocol: optional(protocol).map(Cow::Owned),
            case: optional(case),
            target: optional(target).map(Cow::Owned),
            client: take_text(self.native.remove("client_addr"))?,
            upstream,
            connection: take_text(self.native.remove("connection_id"))?
                .try_map(|value| Ok(value.parse()?))?,
            duration_ms: match self.native.remove("duration_ms") {
                None => Optional::Absent,
                Some(Value::Null) => Optional::Null,
                Some(value) => {
                    Optional::Present(value.as_u64().context("invalid dependency duration")?)
                }
            },
        };
        let mut extension = Vec::with_capacity(160);
        let out = &mut extension;
        out.extend_from_slice(b"ext:");
        if let Some(layout) = layout.declaration {
            terms.declare(layout)?;
            if !layout.variant.is_empty() {
                atoms::text(out, layout.variant);
                out.push(b':');
            }
            ensure!(
                self.native.remove("event_type") == Some(Value::from(layout.event_type)),
                "dependency event type disagrees with its declared layout"
            );
            out.push(b'[');
            for (index, (key, kind)) in layout.fields.iter().enumerate() {
                if index != 0 {
                    out.push(b' ');
                }
                atoms::scalar(out, self.native.remove(*key).as_ref(), *kind)?;
            }
            out.push(b']');
        } else {
            out.push(b'-');
        }

        let flags = u8::from(derive_exchange)
            | (u8::from(derive_native) << 1)
            | (u8::from(!self.complete) << 2)
            | (u8::from(projected_upstream) << 3)
            | (case_fields << 4);
        if flags != 0 {
            write!(out, " f={flags}")?;
        }
        if address_fields != 0 {
            write!(out, " a={address_fields}")?;
        }
        if let Some(form) = ref_form {
            write!(out, " r={form}")?;
        }
        if self.outcome != "response" {
            let mut outcome = Map::new();
            outcome.insert("outcome".into(), std::mem::take(&mut self.outcome));
            atoms::named(out, "", &outcome, terms)?;
        }
        project_empty(&mut self.capture, &mut self.native, out)?;
        atoms::named(out, "c.", &self.capture, terms)?;
        atoms::named(out, "n.", &self.native, terms)?;
        Ok((prefix, extension))
    }

    pub(super) fn materialize(
        prefix: DependencyPrefix<'_>,
        extension: ProtocolExtension<'_>,
        epoch: Uuid,
        terms: &ReadTerms,
    ) -> Result<Self> {
        let DependencyPrefix {
            sequence,
            protocol,
            case,
            target,
            client,
            upstream,
            connection,
            duration_ms,
        } = prefix;
        let sequence = sequence.get();
        let mut capture = Map::new();
        capture.insert("sequence".into(), sequence.into());
        capture.insert("process_epoch".into(), Value::from(terms.process_epoch()));
        let mut native = Map::new();
        let protocol = as_option(protocol);
        let case = as_option(case);
        let target = as_option(target);
        put(
            &mut native,
            "client_addr",
            client.map(|value| Value::from(value.as_ref())),
        );
        put(
            &mut native,
            "upstream_addr",
            upstream.map(|value| Value::from(value.as_ref())),
        );
        put(
            &mut native,
            "connection_id",
            connection.map(|value| Value::from(value.to_string())),
        );
        put(&mut native, "duration_ms", duration_ms.map(Value::from));

        if let Some(variant) = extension.variant {
            let variant = atoms::untext(variant)?;
            let layout = terms.layout(
                protocol.as_deref().context("extension has no protocol")?,
                &variant,
            )?;
            let mut cells = extension.fields.split(' ').filter(|cell| !cell.is_empty());
            for (key, kind) in &layout.fields {
                let cell = cells.next().context("missing dependency extension field")?;
                if let Some(value) = atoms::read_scalar(cell, *kind)? {
                    insert(&mut native, key.clone(), value)?;
                }
            }
            ensure!(
                cells.next().is_none(),
                "unexpected dependency extension field"
            );
            insert(
                &mut native,
                "event_type".into(),
                Value::from(layout.event_type.as_str()),
            )?;
        }

        let mut flags: u8 = 0;
        let mut address_fields: u8 = 0;
        let mut reference = None;
        let mut outcome = Value::from("response");
        let mut empty: u8 = 0;
        for item in extension.metadata.split_ascii_whitespace() {
            let (key, value) = item
                .split_once('=')
                .context("invalid dependency metadata")?;
            match key {
                "f" => flags = value.parse()?,
                "a" => address_fields = value.parse()?,
                "r" => reference = Some(value),
                "d" => empty = value.parse()?,
                "outcome" => outcome = atoms::read_named(value, terms)?,
                _ => {
                    let (scope, field) =
                        key.split_once('.').context("unknown dependency metadata")?;
                    let field = atoms::untext(field)?;
                    let mut value = atoms::read_named(value, terms)?;
                    let map = match scope {
                        "c" => {
                            if matches!(field.as_str(), "observed_case" | "admitted_case")
                                && let Some(id) = value.as_str()
                                && let Some(id) = IdentityKind::Case.parse(epoch, id)
                            {
                                value = Value::String(id.to_string());
                            }
                            &mut capture
                        }
                        "n" => &mut native,
                        _ => anyhow::bail!("invalid dependency metadata scope"),
                    };
                    insert(map, field, value)?;
                }
            }
        }

        let dependency_id = IdentityKind::Dependency.bridge(epoch, sequence);
        if flags & 1 != 0 {
            insert(
                &mut capture,
                "exchange_id".into(),
                Value::from(dependency_id.to_string()),
            )?;
        }
        if flags & 2 != 0 {
            insert(
                &mut native,
                "id".into(),
                Value::from(dependency_id.to_string()),
            )?;
        }
        if flags & 8 != 0 {
            native.remove("upstream_addr");
        }
        if let Some(case) = case {
            capture
                .entry("attribution")
                .or_insert_with(|| json!({"kind":"case","origin_case_id":case}));
            for (key, bit) in [("observed_case", 16), ("admitted_case", 32)] {
                if flags & bit != 0 {
                    insert(&mut capture, key.into(), Value::from(case.to_string()))?;
                }
            }
        }
        if address_fields != 0 {
            let address = target.context("missing dependency target")?;
            if address_fields & 1 != 0 {
                insert(
                    &mut native,
                    "target_addr".into(),
                    Value::from(address.as_ref()),
                )?;
            }
            if address_fields & 6 != 0 {
                let endpoint =
                    endpoint_from_addr(&address).context("invalid dependency target endpoint")?;
                if address_fields & 2 != 0 {
                    insert(
                        &mut native,
                        "target_host".into(),
                        Value::from(endpoint.host),
                    )?;
                }
                if address_fields & 4 != 0 {
                    insert(
                        &mut native,
                        "target_port".into(),
                        Value::from(endpoint.port),
                    )?;
                }
            }
        }
        restore_empty(&mut capture, &mut native, empty)?;
        if let Some(form) = reference {
            reference::restore(
                &mut capture,
                &native,
                protocol.as_deref().context("reference has no protocol")?,
                form,
            )?;
        }
        Ok(Self {
            capture,
            native,
            outcome,
            complete: flags & 4 == 0,
        })
    }

    fn take_case(&mut self) -> (Option<Uuid>, u8) {
        let Some(owner) = self.capture.get("attribution").and_then(Value::as_object) else {
            return (None, 0);
        };
        if owner.get("kind").and_then(Value::as_str) != Some("case") {
            return (None, 0);
        }
        let Some(case) = value_id(owner.get("origin_case_id")) else {
            return (None, 0);
        };
        if owner.len() == 2 {
            self.capture.remove("attribution");
        }
        let mut same = 0;
        for (key, bit) in [("observed_case", 1), ("admitted_case", 2)] {
            if value_id(self.capture.get(key)) == Some(case) {
                self.capture.remove(key);
                same |= bit;
            }
        }
        (Some(case), same)
    }

    fn take_target(&mut self, projected: Option<&str>) -> (Option<String>, u8) {
        let address = projected
            .or_else(|| self.native.get("target_addr").and_then(Value::as_str))
            .map(str::to_owned)
            .or_else(|| {
                let host = self.native.get("target_host")?.as_str()?;
                let port = u16::try_from(self.native.get("target_port")?.as_u64()?).ok()?;
                Some(format_endpoint(host, port))
            });
        let mut fields = 0;
        if let Some(address) = &address {
            if self.native.get("target_addr").and_then(Value::as_str) == Some(address.as_str()) {
                self.native.remove("target_addr");
                fields |= 1;
            }
            if let Some(endpoint) = endpoint_from_addr(address) {
                if self.native.get("target_host").and_then(Value::as_str)
                    == Some(endpoint.host.as_str())
                {
                    self.native.remove("target_host");
                    fields |= 2;
                }
                if self.native.get("target_port").and_then(Value::as_u64)
                    == Some(u64::from(endpoint.port))
                {
                    self.native.remove("target_port");
                    fields |= 4;
                }
            }
        }
        (address, fields)
    }
}

fn value_id(value: Option<&Value>) -> Option<Uuid> {
    value?.as_str()?.parse().ok()
}

fn optional<T>(value: Option<T>) -> Optional<T> {
    value.map_or(Optional::Absent, Optional::Present)
}

fn as_option<T>(value: Optional<T>) -> Option<T> {
    match value {
        Optional::Present(value) => Some(value),
        _ => None,
    }
}

fn take_text(value: Option<Value>) -> Result<Optional<Cow<'static, str>>> {
    Ok(match value {
        None => Optional::Absent,
        Some(Value::Null) => Optional::Null,
        Some(Value::String(value)) => Optional::Present(Cow::Owned(value)),
        Some(_) => anyhow::bail!("invalid dependency text field"),
    })
}

fn put(native: &mut Map<String, Value>, key: &str, value: Optional<Value>) {
    match value {
        Optional::Absent => {}
        Optional::Null => {
            native.insert(key.into(), Value::Null);
        }
        Optional::Present(value) => {
            native.insert(key.into(), value);
        }
    }
}

fn insert(map: &mut Map<String, Value>, key: String, value: Value) -> Result<()> {
    ensure!(
        map.insert(key, value).is_none(),
        "duplicate dependency field"
    );
    Ok(())
}

fn defaults() -> [(bool, &'static str, Value); 8] {
    [
        (true, "matched_rule_id", Value::Null),
        (true, "matched_rule_ids", json!([])),
        (true, "semantic_required", Value::Bool(true)),
        (false, "error", Value::Null),
        (false, "parse_warnings", json!([])),
        (false, "session_setup", Value::Bool(false)),
        (false, "replay_safe", Value::Bool(true)),
        (false, "statement_id", Value::Null),
    ]
}

fn project_empty(
    capture: &mut Map<String, Value>,
    native: &mut Map<String, Value>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut fields: u8 = 0;
    for (index, (shared, key, default)) in defaults().into_iter().enumerate() {
        let map = if shared { &mut *capture } else { &mut *native };
        if map.get(key) == Some(&default) {
            map.remove(key);
            fields |= 1 << index;
        }
    }
    if fields != 0 {
        write!(out, " d={fields}")?;
    }
    Ok(())
}

fn restore_empty(
    capture: &mut Map<String, Value>,
    native: &mut Map<String, Value>,
    fields: u8,
) -> Result<()> {
    for (index, (shared, key, default)) in defaults().into_iter().enumerate() {
        if fields & (1 << index) != 0 {
            let map = if shared { &mut *capture } else { &mut *native };
            insert(map, key.into(), default)?;
        }
    }
    Ok(())
}
