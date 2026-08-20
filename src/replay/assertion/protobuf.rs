use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};

use super::binary_body::extract_simple_payload;
use super::model::{ProtobufBodyDifference, ProtobufBodyDifferenceKind};
use crate::replay::policy::{
    ProtobufFieldPath, ProtobufRepeatedElementType, ProtobufUnorderedPath,
};

const MAX_DISCOVERED_PATHS: usize = 32;
const MAX_NESTING_DEPTH: usize = 32;
const MAX_FIELDS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtobufOrderDiscovery {
    pub(super) unordered_paths: Vec<ProtobufFieldPath>,
    pub(super) differences: Vec<ProtobufBodyDifference>,
    pub(super) order_only: bool,
}

#[derive(Debug)]
struct Field<'a> {
    number: u32,
    wire_type: u8,
    raw: &'a [u8],
    payload: Option<&'a [u8]>,
    value_offset: usize,
    payload_offset: usize,
}

pub(crate) fn is_motan_protobuf_body(body: &[u8]) -> bool {
    extract_simple_payload(body)
        .and_then(|payload| parse_fields(payload).map(|_| ()))
        .is_ok()
}

pub(in crate::replay) fn compare_motan_protobuf(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[ProtobufUnorderedPath],
) -> Result<bool> {
    let expected = extract_simple_payload(expected)?;
    let actual = extract_simple_payload(actual)?;
    parse_fields(expected)?;
    parse_fields(actual)?;
    let expected = canonicalize_rules(expected, unordered_paths)?;
    let actual = canonicalize_rules(actual, unordered_paths)?;
    Ok(expected == actual)
}

pub(super) fn evaluate_motan_protobuf(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[ProtobufUnorderedPath],
) -> Result<(bool, ProtobufOrderDiscovery)> {
    let mut discovery = discover_motan_protobuf_order(expected, actual)?;
    let matches = compare_motan_protobuf(expected, actual, unordered_paths)?;
    for rule in unordered_paths {
        for difference in discovery
            .differences
            .iter_mut()
            .filter(|difference| difference.field_path == rule.field_path)
        {
            difference.display_path.clone_from(&rule.display_path);
        }
    }
    if matches {
        for (index, rule) in unordered_paths.iter().enumerate() {
            let without_rule = unordered_paths
                .iter()
                .enumerate()
                .filter(|(candidate, _)| *candidate != index)
                .map(|(_, rule)| rule.clone())
                .collect::<Vec<_>>();
            if compare_motan_protobuf(expected, actual, &without_rule)? {
                continue;
            }
            discovery.differences.retain(|difference| {
                difference.kind == ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch
                    || !difference.field_path.0.starts_with(&rule.field_path.0)
            });
            discovery.unordered_paths.push(rule.field_path.clone());
            discovery.differences.push(ProtobufBodyDifference {
                field_path: rule.field_path.clone(),
                display_path: rule.display_path.clone(),
                kind: ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch,
            });
        }
        discovery.order_only = true;
    }
    discovery.unordered_paths.sort();
    discovery.unordered_paths.dedup();
    discovery.differences.sort_by(|left, right| {
        left.field_path
            .cmp(&right.field_path)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    discovery
        .differences
        .dedup_by(|left, right| left.field_path == right.field_path && left.kind == right.kind);
    Ok((matches, discovery))
}

pub(super) fn discover_motan_protobuf_order(
    expected: &[u8],
    actual: &[u8],
) -> Result<ProtobufOrderDiscovery> {
    let mut expected = extract_simple_payload(expected)?.to_vec();
    let mut actual = extract_simple_payload(actual)?.to_vec();
    parse_fields(&expected)?;
    parse_fields(&actual)?;
    let mut selected = BTreeSet::new();

    while expected != actual && selected.len() < MAX_DISCOVERED_PATHS {
        let mut discovered = BTreeSet::new();
        discover_paths(&expected, &actual, &[], 0, &mut discovered);
        discovered.retain(|path| !selected.contains(path));
        if discovered.is_empty() {
            break;
        }
        let remaining = MAX_DISCOVERED_PATHS - selected.len();
        selected.extend(discovered.into_iter().take(remaining));
        let paths = selected.iter().cloned().collect::<Vec<_>>();
        let next_expected = canonicalize_paths(&expected, &paths)?;
        let next_actual = canonicalize_paths(&actual, &paths)?;
        if next_expected == expected && next_actual == actual {
            break;
        }
        expected = next_expected;
        actual = next_actual;
    }

    let order_only = expected == actual;
    let mut differences = selected
        .iter()
        .cloned()
        .map(|field_path| ProtobufBodyDifference {
            display_path: field_path.display_path(),
            field_path,
            kind: ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch,
        })
        .collect::<Vec<_>>();
    if !order_only {
        collect_residual_differences(&expected, &actual, &[], 0, &mut differences);
    }
    differences.sort_by(|left, right| {
        left.field_path
            .cmp(&right.field_path)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    differences
        .dedup_by(|left, right| left.field_path == right.field_path && left.kind == right.kind);
    Ok(ProtobufOrderDiscovery {
        unordered_paths: selected.into_iter().collect(),
        differences,
        order_only,
    })
}

fn collect_residual_differences(
    expected: &[u8],
    actual: &[u8],
    prefix: &[u32],
    depth: usize,
    differences: &mut Vec<ProtobufBodyDifference>,
) {
    if expected == actual || depth >= MAX_NESTING_DEPTH {
        return;
    }
    let (Ok(expected_fields), Ok(actual_fields)) = (parse_fields(expected), parse_fields(actual))
    else {
        push_difference(
            prefix,
            ProtobufBodyDifferenceKind::ValueMismatch,
            differences,
        );
        return;
    };
    let numbers = expected_fields
        .iter()
        .map(|field| field.number)
        .chain(actual_fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();
    for number in numbers {
        let expected_group = expected_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let actual_group = actual_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let mut path = prefix.to_vec();
        path.push(number);
        if expected_group.len() != actual_group.len() {
            push_difference(
                &path,
                ProtobufBodyDifferenceKind::OccurrenceCountMismatch,
                differences,
            );
            continue;
        }
        if expected_group
            .iter()
            .map(|field| field.wire_type)
            .ne(actual_group.iter().map(|field| field.wire_type))
        {
            push_difference(
                &path,
                ProtobufBodyDifferenceKind::WireTypeMismatch,
                differences,
            );
            continue;
        }
        let expected_payloads = expected_group
            .iter()
            .filter_map(|field| field.payload)
            .collect::<Vec<_>>();
        let actual_payloads = actual_group
            .iter()
            .filter_map(|field| field.payload)
            .collect::<Vec<_>>();
        if expected_payloads.len() == expected_group.len() {
            let pairs =
                pair_nested_payloads(&expected_payloads, &actual_payloads).unwrap_or_else(|| {
                    (0..expected_payloads.len())
                        .map(|index| (index, index))
                        .collect()
                });
            let before = differences.len();
            for (expected_index, actual_index) in pairs {
                collect_residual_differences(
                    expected_payloads[expected_index],
                    actual_payloads[actual_index],
                    &path,
                    depth + 1,
                    differences,
                );
            }
            if differences.len() == before
                && expected_group
                    .iter()
                    .zip(&actual_group)
                    .any(|(expected, actual)| expected.raw != actual.raw)
            {
                push_difference(
                    &path,
                    ProtobufBodyDifferenceKind::ValueMismatch,
                    differences,
                );
            }
        } else if expected_group
            .iter()
            .zip(&actual_group)
            .any(|(expected, actual)| expected.raw != actual.raw)
        {
            push_difference(
                &path,
                ProtobufBodyDifferenceKind::ValueMismatch,
                differences,
            );
        }
    }
}

fn push_difference(
    path: &[u32],
    kind: ProtobufBodyDifferenceKind,
    differences: &mut Vec<ProtobufBodyDifference>,
) {
    if path.is_empty() {
        return;
    }
    let field_path = ProtobufFieldPath(path.to_vec());
    differences.push(ProtobufBodyDifference {
        display_path: field_path.display_path(),
        field_path,
        kind,
    });
}

fn canonicalize_paths(payload: &[u8], paths: &[ProtobufFieldPath]) -> Result<Vec<u8>> {
    let mut canonical = payload.to_vec();
    let mut ordered = paths.to_vec();
    ordered.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.cmp(right))
    });
    for path in ordered {
        let (next, found) = canonicalize_path(&canonical, &path.0, None, 0)?;
        ensure!(
            found,
            "protobuf unordered path {:?} is missing from the Motan body",
            path.0
        );
        canonical = next;
    }
    Ok(canonical)
}

fn canonicalize_rules(payload: &[u8], rules: &[ProtobufUnorderedPath]) -> Result<Vec<u8>> {
    let mut canonical = payload.to_vec();
    let mut ordered = rules.to_vec();
    ordered.sort_by(|left, right| {
        right
            .field_path
            .0
            .len()
            .cmp(&left.field_path.0.len())
            .then_with(|| left.field_path.cmp(&right.field_path))
    });
    for rule in ordered {
        let (next, _) =
            canonicalize_path(&canonical, &rule.field_path.0, Some(rule.element_type), 0)?;
        canonical = next;
    }
    Ok(canonical)
}

fn canonicalize_path(
    payload: &[u8],
    path: &[u32],
    element_type: Option<ProtobufRepeatedElementType>,
    depth: usize,
) -> Result<(Vec<u8>, bool)> {
    ensure!(depth < MAX_NESTING_DEPTH, "protobuf nesting is too deep");
    let fields = parse_fields(payload)?;
    let number = *path.first().expect("validated protobuf path is non-empty");
    let mut replacements = fields
        .iter()
        .map(|field| field.raw.to_vec())
        .collect::<Vec<_>>();
    if path.len() == 1 {
        let indexes = fields
            .iter()
            .enumerate()
            .filter(|(_, field)| field.number == number)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok((payload.to_vec(), false));
        }
        canonicalize_terminal(&fields, &indexes, element_type, &mut replacements)?;
        return Ok((replacements.concat(), true));
    }

    let mut found = false;
    for (index, field) in fields.iter().enumerate() {
        if field.number != number {
            continue;
        }
        ensure!(
            field.wire_type == 2,
            "intermediate protobuf unordered field {number} is not length-delimited"
        );
        let nested = field.payload.expect("wire type 2 has a payload");
        let (nested, nested_found) =
            canonicalize_path(nested, &path[1..], element_type, depth + 1)?;
        if nested_found {
            ensure!(
                nested.len() == field.payload.expect("wire type 2 has a payload").len(),
                "protobuf unordered canonicalization changed message length"
            );
            let mut replacement = field.raw[..field.payload_offset].to_vec();
            replacement.extend_from_slice(&nested);
            replacements[index] = replacement;
            found = true;
        }
    }
    Ok((replacements.concat(), found))
}

fn canonicalize_terminal(
    fields: &[Field<'_>],
    indexes: &[usize],
    element_type: Option<ProtobufRepeatedElementType>,
    replacements: &mut [Vec<u8>],
) -> Result<()> {
    let Some(element_type) = element_type else {
        let wire_type = fields[indexes[0]].wire_type;
        ensure!(
            indexes
                .iter()
                .all(|index| fields[*index].wire_type == wire_type),
            "protobuf unordered field uses multiple wire types"
        );
        let mut sorted = indexes
            .iter()
            .map(|index| fields[*index].raw.to_vec())
            .collect::<Vec<_>>();
        sorted.sort();
        for (index, value) in indexes.iter().copied().zip(sorted) {
            replacements[index] = value;
        }
        return Ok(());
    };

    match element_type {
        ProtobufRepeatedElementType::String | ProtobufRepeatedElementType::Message => {
            for index in indexes {
                let field = &fields[*index];
                ensure!(
                    field.wire_type == 2,
                    "protobuf {:?} repeated field is not length-delimited",
                    element_type
                );
                let payload = field.payload.expect("wire type 2 has a payload");
                match element_type {
                    ProtobufRepeatedElementType::String => {
                        std::str::from_utf8(payload).map_err(|_| {
                            anyhow::anyhow!("protobuf repeated string is not UTF-8")
                        })?;
                    }
                    ProtobufRepeatedElementType::Message => {
                        parse_fields(payload)
                            .context("protobuf repeated message element is malformed")?;
                    }
                    _ => unreachable!(),
                }
            }
            let mut sorted = indexes
                .iter()
                .map(|index| fields[*index].raw.to_vec())
                .collect::<Vec<_>>();
            sorted.sort();
            for (index, value) in indexes.iter().copied().zip(sorted) {
                replacements[index] = value;
            }
        }
        numeric => canonicalize_numeric(fields, indexes, numeric, replacements)?,
    }
    Ok(())
}

fn canonicalize_numeric(
    fields: &[Field<'_>],
    indexes: &[usize],
    element_type: ProtobufRepeatedElementType,
    replacements: &mut [Vec<u8>],
) -> Result<()> {
    let scalar_wire = numeric_wire_type(element_type);
    let mut layouts = Vec::new();
    let mut elements = Vec::new();
    for index in indexes {
        let field = &fields[*index];
        if field.wire_type == scalar_wire {
            elements.push(field.raw[field.value_offset..].to_vec());
            layouts.push((*index, false, 1));
            continue;
        }
        ensure!(
            field.wire_type == 2,
            "protobuf {:?} repeated field has incompatible wire type {}",
            element_type,
            field.wire_type
        );
        let packed = split_packed_numeric(
            field.payload.expect("wire type 2 has a payload"),
            scalar_wire,
        )?;
        ensure!(
            !packed.is_empty(),
            "packed protobuf repeated field is empty"
        );
        let count = packed.len();
        elements.extend(packed);
        layouts.push((*index, true, count));
    }
    elements.sort();
    let mut elements = elements.into_iter();
    for (index, packed, count) in layouts {
        let field = &fields[index];
        let selected = elements.by_ref().take(count).collect::<Vec<_>>();
        if packed {
            let payload = selected.concat();
            let mut replacement = field.raw[..field.value_offset].to_vec();
            write_varint(&mut replacement, payload.len() as u64);
            replacement.extend(payload);
            replacements[index] = replacement;
        } else {
            let mut replacement = field.raw[..field.value_offset].to_vec();
            replacement.extend_from_slice(&selected[0]);
            replacements[index] = replacement;
        }
    }
    Ok(())
}

fn numeric_wire_type(element_type: ProtobufRepeatedElementType) -> u8 {
    match element_type {
        ProtobufRepeatedElementType::Int32
        | ProtobufRepeatedElementType::Int64
        | ProtobufRepeatedElementType::Uint32
        | ProtobufRepeatedElementType::Uint64
        | ProtobufRepeatedElementType::Sint32
        | ProtobufRepeatedElementType::Sint64
        | ProtobufRepeatedElementType::Bool
        | ProtobufRepeatedElementType::Enum => 0,
        ProtobufRepeatedElementType::Fixed64
        | ProtobufRepeatedElementType::Sfixed64
        | ProtobufRepeatedElementType::Double => 1,
        ProtobufRepeatedElementType::Fixed32
        | ProtobufRepeatedElementType::Sfixed32
        | ProtobufRepeatedElementType::Float => 5,
        ProtobufRepeatedElementType::String | ProtobufRepeatedElementType::Message => {
            unreachable!("non-numeric protobuf type")
        }
    }
}

fn split_packed_numeric(payload: &[u8], wire_type: u8) -> Result<Vec<Vec<u8>>> {
    let mut elements = Vec::new();
    let mut index = 0;
    while index < payload.len() {
        let start = index;
        match wire_type {
            0 => {
                read_varint(payload, &mut index)?;
            }
            1 => advance(payload, &mut index, 8)?,
            5 => advance(payload, &mut index, 4)?,
            _ => unreachable!("validated numeric protobuf wire type"),
        }
        elements.push(payload[start..index].to_vec());
    }
    Ok(elements)
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn discover_paths(
    expected: &[u8],
    actual: &[u8],
    prefix: &[u32],
    depth: usize,
    discovered: &mut BTreeSet<ProtobufFieldPath>,
) {
    if depth >= MAX_NESTING_DEPTH || discovered.len() >= MAX_DISCOVERED_PATHS {
        return;
    }
    let (Ok(expected_fields), Ok(actual_fields)) = (parse_fields(expected), parse_fields(actual))
    else {
        return;
    };
    let numbers = expected_fields
        .iter()
        .map(|field| field.number)
        .chain(actual_fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();

    for number in numbers {
        let expected_group = expected_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let actual_group = actual_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        if expected_group.len() > 1
            && expected_group.len() == actual_group.len()
            && expected_group
                .iter()
                .map(|field| field.wire_type)
                .eq(actual_group.iter().map(|field| field.wire_type))
        {
            let expected_raw = expected_group
                .iter()
                .map(|field| field.raw)
                .collect::<Vec<_>>();
            let actual_raw = actual_group
                .iter()
                .map(|field| field.raw)
                .collect::<Vec<_>>();
            let mut sorted_expected = expected_raw.clone();
            let mut sorted_actual = actual_raw.clone();
            sorted_expected.sort();
            sorted_actual.sort();
            if expected_raw != actual_raw && sorted_expected == sorted_actual {
                let mut path = prefix.to_vec();
                path.push(number);
                discovered.insert(ProtobufFieldPath(path));
            }
        }

        if expected_group.len() != actual_group.len()
            || expected_group.is_empty()
            || expected_group
                .iter()
                .chain(&actual_group)
                .any(|field| field.wire_type != 2)
        {
            continue;
        }
        let expected_payloads = expected_group
            .iter()
            .map(|field| field.payload.expect("wire type 2 has a payload"))
            .collect::<Vec<_>>();
        let actual_payloads = actual_group
            .iter()
            .map(|field| field.payload.expect("wire type 2 has a payload"))
            .collect::<Vec<_>>();
        let pairs =
            pair_nested_payloads(&expected_payloads, &actual_payloads).unwrap_or_else(|| {
                (0..expected_payloads.len())
                    .map(|index| (index, index))
                    .collect()
            });
        let mut nested_prefix = prefix.to_vec();
        nested_prefix.push(number);
        for (expected_index, actual_index) in pairs {
            discover_paths(
                expected_payloads[expected_index],
                actual_payloads[actual_index],
                &nested_prefix,
                depth + 1,
                discovered,
            );
        }
    }
}

fn pair_nested_payloads(expected: &[&[u8]], actual: &[&[u8]]) -> Option<Vec<(usize, usize)>> {
    let expected_fields = expected
        .iter()
        .map(|payload| parse_fields(payload).ok())
        .collect::<Option<Vec<_>>>()?;
    let actual_fields = actual
        .iter()
        .map(|payload| parse_fields(payload).ok())
        .collect::<Option<Vec<_>>>()?;
    let candidate_numbers = expected_fields
        .iter()
        .flat_map(|fields| fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();
    for number in candidate_numbers {
        let Some(expected_keys) = unique_identity_keys(&expected_fields, number) else {
            continue;
        };
        let Some(actual_keys) = unique_identity_keys(&actual_fields, number) else {
            continue;
        };
        if expected_keys.keys().eq(actual_keys.keys()) {
            return Some(
                expected_keys
                    .iter()
                    .map(|(key, expected_index)| (*expected_index, actual_keys[key]))
                    .collect(),
            );
        }
    }
    None
}

fn unique_identity_keys(
    messages: &[Vec<Field<'_>>],
    number: u32,
) -> Option<BTreeMap<Vec<u8>, usize>> {
    let mut keys = BTreeMap::new();
    for (index, fields) in messages.iter().enumerate() {
        let mut matching = fields.iter().filter(|field| field.number == number);
        let field = matching.next()?;
        if matching.next().is_some() || keys.insert(field.raw.to_vec(), index).is_some() {
            return None;
        }
    }
    Some(keys)
}

fn parse_fields(payload: &[u8]) -> Result<Vec<Field<'_>>> {
    let mut fields = Vec::new();
    let mut index = 0;
    while index < payload.len() {
        ensure!(
            fields.len() < MAX_FIELDS,
            "protobuf message has too many fields"
        );
        let start = index;
        let tag = read_varint(payload, &mut index)?;
        let number = u32::try_from(tag >> 3)
            .map_err(|_| anyhow::anyhow!("protobuf field number overflow"))?;
        let wire_type = (tag & 7) as u8;
        ensure!(
            number != 0 && number < (1 << 29),
            "invalid protobuf field number"
        );
        let mut nested = None;
        let value_offset = index - start;
        let mut payload_offset = 0;
        match wire_type {
            0 => {
                read_varint(payload, &mut index)?;
            }
            1 => advance(payload, &mut index, 8)?,
            2 => {
                let length = usize::try_from(read_varint(payload, &mut index)?)
                    .map_err(|_| anyhow::anyhow!("protobuf length is not representable"))?;
                payload_offset = index - start;
                let end = index
                    .checked_add(length)
                    .ok_or_else(|| anyhow::anyhow!("protobuf length overflow"))?;
                ensure!(
                    end <= payload.len(),
                    "truncated protobuf length-delimited field"
                );
                nested = Some(&payload[index..end]);
                index = end;
            }
            5 => advance(payload, &mut index, 4)?,
            3 | 4 => bail!("protobuf groups are not supported"),
            _ => bail!("invalid protobuf wire type {wire_type}"),
        }
        fields.push(Field {
            number,
            wire_type,
            raw: &payload[start..index],
            payload: nested,
            value_offset,
            payload_offset,
        });
    }
    Ok(fields)
}

fn read_varint(payload: &[u8], index: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *payload
            .get(*index)
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))?;
        *index += 1;
        ensure!(shift < 63 || byte <= 1, "protobuf varint overflow");
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint overflow")
}

fn advance(payload: &[u8], index: &mut usize, length: usize) -> Result<()> {
    let end = index
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("protobuf field length overflow"))?;
    ensure!(end <= payload.len(), "truncated protobuf fixed-width field");
    *index = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_field(number: u32, value: &[u8]) -> Vec<u8> {
        assert!(number < 16 && value.len() < 128);
        let mut field = vec![((number << 3) | 2) as u8, value.len() as u8];
        field.extend_from_slice(value);
        field
    }

    fn varint_field(number: u32, value: u8) -> Vec<u8> {
        assert!(number < 16 && value < 128);
        vec![(number << 3) as u8, value]
    }

    fn message(fields: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        fields.into_iter().flatten().collect()
    }

    fn body(payload: Vec<u8>) -> Vec<u8> {
        let mut body = vec![3];
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend(payload);
        body
    }

    #[test]
    fn discovers_and_applies_nested_repeated_field_order() {
        let expected_group = message([bytes_field(3, b"alice"), bytes_field(3, b"bob")]);
        let actual_group = message([bytes_field(3, b"bob"), bytes_field(3, b"alice")]);
        let expected = body(message([bytes_field(
            3,
            &message([bytes_field(1, &message([bytes_field(6, &expected_group)]))]),
        )]));
        let actual = body(message([bytes_field(
            3,
            &message([bytes_field(1, &message([bytes_field(6, &actual_group)]))]),
        )]));

        let discovery = discover_motan_protobuf_order(&expected, &actual).unwrap();

        assert_eq!(
            discovery.unordered_paths,
            vec![ProtobufFieldPath(vec![3, 1, 6, 3])]
        );
        assert!(discovery.order_only);
        let rules = discovery
            .unordered_paths
            .iter()
            .cloned()
            .map(|field_path| ProtobufUnorderedPath {
                display_path: field_path.display_path(),
                field_path,
                element_type: ProtobufRepeatedElementType::String,
                source_evidence: "test source contract".to_string(),
            })
            .collect::<Vec<_>>();
        assert!(compare_motan_protobuf(&expected, &actual, &rules).unwrap());
    }

    #[test]
    fn changed_repeated_value_is_not_hidden() {
        let expected = body(message([bytes_field(3, b"alice"), bytes_field(3, b"bob")]));
        let actual = body(message([bytes_field(3, b"bob"), bytes_field(3, b"carol")]));

        let discovery = discover_motan_protobuf_order(&expected, &actual).unwrap();

        assert!(discovery.unordered_paths.is_empty());
        assert!(!discovery.order_only);
    }

    #[test]
    fn absent_unordered_path_is_a_no_op_without_hiding_presence_mismatch() {
        let absent = body(message([varint_field(1, 81), varint_field(4, 0)]));
        let present = body(message([bytes_field(
            3,
            &message([bytes_field(3, &message([bytes_field(2, &message([]))]))]),
        )]));
        let rule = ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3, 3, 2]),
            display_path: "rule_collection.group_config.groups".to_string(),
            element_type: ProtobufRepeatedElementType::Message,
            source_evidence: "test source contract".to_string(),
        };

        assert!(compare_motan_protobuf(&absent, &absent, std::slice::from_ref(&rule)).unwrap());
        assert!(!compare_motan_protobuf(&absent, &present, &[rule]).unwrap());
    }

    #[test]
    fn present_unordered_path_still_requires_compatible_wire_types() {
        let malformed = body(message([bytes_field(
            3,
            &message([bytes_field(3, &message([varint_field(2, 1)]))]),
        )]));
        let rule = ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3, 3, 2]),
            display_path: "rule_collection.group_config.groups".to_string(),
            element_type: ProtobufRepeatedElementType::Message,
            source_evidence: "test source contract".to_string(),
        };

        let error = compare_motan_protobuf(&malformed, &malformed, &[rule]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("protobuf Message repeated field is not length-delimited")
        );
    }

    #[test]
    fn rejects_invalid_envelope_length() {
        assert!(discover_motan_protobuf_order(&[3, 0, 0, 0, 2, 8], &[3, 0, 0, 0, 1, 8]).is_err());
    }

    #[test]
    fn compares_packed_integer_elements_without_treating_bytes_as_a_collection() {
        let expected = body(message([bytes_field(2, &[1, 0x80, 1, 2])]));
        let actual = body(message([bytes_field(2, &[2, 1, 0x80, 1])]));
        let rule = ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![2]),
            display_path: "config_scene.values".to_string(),
            element_type: ProtobufRepeatedElementType::Uint32,
            source_evidence: "test source contract".to_string(),
        };

        let (matches, discovery) = evaluate_motan_protobuf(&expected, &actual, &[rule]).unwrap();

        assert!(matches);
        assert!(discovery.order_only);
        assert_eq!(discovery.unordered_paths, vec![ProtobufFieldPath(vec![2])]);
        assert_eq!(
            discovery.differences,
            vec![ProtobufBodyDifference {
                field_path: ProtobufFieldPath(vec![2]),
                display_path: "config_scene.values".to_string(),
                kind: ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch,
            }]
        );
    }

    #[test]
    fn discovers_inner_then_outer_message_order() {
        let entry = |key: &[u8], values: [&[u8]; 2]| {
            message([
                bytes_field(1, key),
                bytes_field(2, &message([bytes_field(1, values[0])])),
                bytes_field(2, &message([bytes_field(1, values[1])])),
            ])
        };
        let expected = body(message([bytes_field(
            3,
            &message([
                bytes_field(3, &entry(b"a", [b"x", b"y"])),
                bytes_field(3, &entry(b"b", [b"p", b"q"])),
            ]),
        )]));
        let actual = body(message([bytes_field(
            3,
            &message([
                bytes_field(3, &entry(b"b", [b"q", b"p"])),
                bytes_field(3, &entry(b"a", [b"y", b"x"])),
            ]),
        )]));

        let discovery = discover_motan_protobuf_order(&expected, &actual).unwrap();

        assert_eq!(
            discovery.unordered_paths,
            vec![
                ProtobufFieldPath(vec![3, 3]),
                ProtobufFieldPath(vec![3, 3, 2]),
            ]
        );
        assert!(discovery.order_only);
        let rules = [
            ProtobufUnorderedPath {
                field_path: ProtobufFieldPath(vec![3, 3, 2]),
                display_path: "rule_collection.group_config.values".to_string(),
                element_type: ProtobufRepeatedElementType::Message,
                source_evidence: "test source contract".to_string(),
            },
            ProtobufUnorderedPath {
                field_path: ProtobufFieldPath(vec![3, 3]),
                display_path: "rule_collection.group_config".to_string(),
                element_type: ProtobufRepeatedElementType::Message,
                source_evidence: "test source contract".to_string(),
            },
        ];
        assert!(compare_motan_protobuf(&expected, &actual, &rules).unwrap());
    }
}
