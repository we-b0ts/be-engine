use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read as _};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::model::{DocxBodyDifference, DocxBodyDifferenceKind, ResponseBodyAssertionReport};
use super::time::RequestTimes;
use traffic_policy_schema::response::{DocxTimestampRule, ResponseBodyCodec};

const MAX_ENTRIES: usize = 4096;
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const CORE_PROPERTIES_PART: &str = "docProps/core.xml";
const CREATED_ELEMENT: &str = "dcterms:created";
const DOCUMENT_CONTENT_TYPE: &[u8] =
    b"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";

pub fn is_docx_body(body: &[u8]) -> bool {
    package(body).is_ok()
}

pub fn diagnose_docx(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[u8],
    actual: &[u8],
) -> Result<ResponseBodyAssertionReport> {
    let candidate = DocxTimestampRule {
        part: CORE_PROPERTIES_PART.into(),
        element: CREATED_ELEMENT.into(),
        format: traffic_policy_schema::response::ResponseTimestampFormat::Rfc3339,
        source_evidence: "diagnostic candidate only".into(),
        source_example: "source".into(),
        target_example: "target".into(),
    };
    let discovery = compare_packages(
        policies,
        expected,
        actual,
        std::slice::from_ref(&candidate),
        None,
    )?;
    Ok(ResponseBodyAssertionReport {
        codec: ResponseBodyCodec::Docx,
        envelope: "opc_zip".into(),
        configured: false,
        used_for_verdict: false,
        codec_candidates: vec![ResponseBodyCodec::Docx],
        unordered_path_candidates: Vec::new(),
        unordered_joined_string_candidates: Vec::new(),
        differences: discovery.differences.into_iter().map(Into::into).collect(),
        candidates_explain_all_differences: discovery.matches,
        order_only: false,
    })
}

pub fn evaluate_docx(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[u8],
    actual: &[u8],
    rules: &[DocxTimestampRule],
    times: RequestTimes,
) -> Result<(bool, ResponseBodyAssertionReport)> {
    let comparison = compare_packages(policies, expected, actual, rules, Some(times))?;
    let report = ResponseBodyAssertionReport {
        codec: ResponseBodyCodec::Docx,
        envelope: "opc_zip".into(),
        configured: true,
        used_for_verdict: true,
        codec_candidates: vec![ResponseBodyCodec::Docx],
        unordered_path_candidates: Vec::new(),
        unordered_joined_string_candidates: Vec::new(),
        differences: comparison.differences.into_iter().map(Into::into).collect(),
        candidates_explain_all_differences: comparison.matches,
        order_only: false,
    };
    Ok((comparison.matches, report))
}

struct PackageComparison {
    matches: bool,
    differences: Vec<DocxBodyDifference>,
}

fn compare_packages(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[u8],
    actual: &[u8],
    rules: &[DocxTimestampRule],
    times: Option<RequestTimes>,
) -> Result<PackageComparison> {
    let expected = package(expected).context("expected response is not a valid DOCX package")?;
    let actual = package(actual).context("actual response is not a valid DOCX package")?;
    let expected_names = expected.keys().collect::<BTreeSet<_>>();
    let actual_names = actual.keys().collect::<BTreeSet<_>>();
    if expected_names != actual_names {
        return Ok(PackageComparison {
            matches: false,
            differences: vec![difference(
                "$package",
                None,
                DocxBodyDifferenceKind::EntrySetMismatch,
            )],
        });
    }
    let mut differences = Vec::new();
    let mut matches = true;
    for (part, expected_bytes) in &expected {
        let actual_bytes = &actual[part];
        let selected = rules
            .iter()
            .filter(|rule| rule.part == *part)
            .collect::<Vec<_>>();
        if expected_bytes == actual_bytes && selected.is_empty() {
            continue;
        }
        let part_differs = expected_bytes != actual_bytes;
        let mut expected_normalized = expected_bytes.clone();
        let mut actual_normalized = actual_bytes.clone();
        let mut timestamp_matched = false;
        for rule in selected {
            let expected_value = normalize_xml_timestamp(
                &mut expected_normalized,
                &rule.element,
                b"__traffic_e2e_docx_timestamp__",
            )?;
            let actual_value = normalize_xml_timestamp(
                &mut actual_normalized,
                &rule.element,
                b"__traffic_e2e_docx_timestamp__",
            )?;
            if expected_value != actual_value {
                timestamp_matched = true;
                differences.push(difference(
                    part,
                    Some(&rule.element),
                    DocxBodyDifferenceKind::TimestampMismatch,
                ));
            }
            if let Some(times) = times {
                let result = super::time::compare_preserved_timestamp(
                    policies,
                    rule.format,
                    &Value::String(expected_value),
                    &Value::String(actual_value),
                    times,
                );
                if let Err(kind) = result {
                    matches = false;
                    differences.push(difference(
                        part,
                        Some(&rule.element),
                        match kind {
                            super::model::ResponseDifferenceKind::TimeReferenceMissing => {
                                DocxBodyDifferenceKind::TimeReferenceMissing
                            }
                            super::model::ResponseDifferenceKind::TimestampOutsideRequestWindow => {
                                DocxBodyDifferenceKind::TimestampOutsideRequestWindow
                            }
                            super::model::ResponseDifferenceKind::DurationDeltaMismatch => {
                                DocxBodyDifferenceKind::TimestampDeltaMismatch
                            }
                            _ => DocxBodyDifferenceKind::TimestampInvalid,
                        },
                    ));
                }
            }
        }
        if expected_normalized != actual_normalized {
            matches = false;
            differences.push(difference(
                part,
                None,
                DocxBodyDifferenceKind::EntryValueMismatch,
            ));
        } else if part_differs && !timestamp_matched {
            // Equal decompressed content would have returned above, so reaching
            // here without a differing selected value is never explanatory.
            matches = false;
        }
    }
    Ok(PackageComparison {
        matches,
        differences,
    })
}

fn difference(
    part: &str,
    element: Option<&str>,
    kind: DocxBodyDifferenceKind,
) -> DocxBodyDifference {
    DocxBodyDifference {
        part: part.into(),
        element: element.map(str::to_string),
        kind,
    }
}

fn package(body: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let cursor = Cursor::new(body);
    let mut archive = zip::ZipArchive::new(cursor).context("invalid ZIP container")?;
    ensure!(
        archive.len() <= MAX_ENTRIES,
        "DOCX ZIP has too many entries"
    );
    let mut entries = BTreeMap::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let file = archive.by_index(index).context("invalid DOCX ZIP entry")?;
        if file.is_dir() {
            continue;
        }
        ensure!(
            file.enclosed_name().is_some(),
            "DOCX ZIP contains an unsafe entry name"
        );
        ensure!(
            file.size() <= MAX_ENTRY_BYTES,
            "DOCX ZIP entry exceeds supported size"
        );
        let name = file.name().replace('\\', "/");
        let mut bytes = Vec::with_capacity(usize::try_from(file.size()).unwrap_or(0));
        file.take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("failed to decompress DOCX ZIP entry")?;
        ensure!(
            bytes.len() as u64 <= MAX_ENTRY_BYTES,
            "DOCX ZIP entry exceeds supported size"
        );
        total = total
            .checked_add(bytes.len() as u64)
            .context("DOCX ZIP size overflow")?;
        ensure!(
            total <= MAX_TOTAL_BYTES,
            "DOCX ZIP expands beyond supported size"
        );
        ensure!(
            entries.insert(name, bytes).is_none(),
            "DOCX ZIP repeats an entry name"
        );
    }
    for required in ["[Content_Types].xml", "_rels/.rels", "word/document.xml"] {
        ensure!(
            entries.contains_key(required),
            "DOCX package is missing required part {required}"
        );
    }
    ensure!(
        entries["[Content_Types].xml"]
            .windows(DOCUMENT_CONTENT_TYPE.len())
            .any(|window| window == DOCUMENT_CONTENT_TYPE),
        "OPC package does not declare the DOCX main document content type"
    );
    Ok(entries)
}

fn normalize_xml_timestamp(bytes: &mut Vec<u8>, element: &str, marker: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("DOCX timestamp part is not UTF-8 XML")?;
    let open_prefix = format!("<{element}");
    let close = format!("</{element}>");
    let mut matches = text.match_indices(&open_prefix).filter(|(start, _)| {
        text.as_bytes()
            .get(start + open_prefix.len())
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>')
    });
    let (start, _) = matches
        .next()
        .with_context(|| format!("DOCX part does not contain XML element {element}"))?;
    ensure!(
        matches.next().is_none(),
        "DOCX part contains multiple XML elements named {element}"
    );
    let open_end = text[start..]
        .find('>')
        .map(|offset| start + offset + 1)
        .with_context(|| format!("DOCX XML element {element} has no closing angle bracket"))?;
    let close_start = text[open_end..]
        .find(&close)
        .map(|offset| open_end + offset)
        .with_context(|| format!("DOCX XML element {element} is not closed"))?;
    let value = &text[open_end..close_start];
    ensure!(
        !value.contains('<') && !value.contains('>'),
        "DOCX XML timestamp element {element} must contain text only"
    );
    let value = value.trim().to_string();
    let leading = text[open_end..close_start]
        .len()
        .saturating_sub(text[open_end..close_start].trim_start().len());
    let trailing = text[open_end..close_start]
        .len()
        .saturating_sub(text[open_end..close_start].trim_end().len());
    let range = open_end + leading..close_start - trailing;
    bytes.splice(range, marker.iter().copied());
    Ok(value)
}

#[cfg(test)]
mod tests;
