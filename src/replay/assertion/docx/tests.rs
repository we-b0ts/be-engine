use std::io::{Cursor, Write as _};

use chrono::{DateTime, Utc};
use zip::write::SimpleFileOptions;

use super::*;

fn docx(created: &str, document: &str, second: u8) -> Vec<u8> {
    let mut bytes = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut bytes);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::from_date_and_time(2024, 1, 2, 3, 4, second).unwrap());
    let core = format!(
        "<cp:coreProperties><dcterms:created>{created}</dcterms:created></cp:coreProperties>"
    );
    for (name, value) in [
        (
            "[Content_Types].xml",
            "<Types><Override ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>",
        ),
        ("_rels/.rels", "<Relationships/>"),
        ("word/document.xml", document),
        ("docProps/core.xml", core.as_str()),
    ] {
        writer.start_file(name, options).unwrap();
        writer.write_all(value.as_bytes()).unwrap();
    }
    writer.finish().unwrap();
    bytes.into_inner()
}

fn rule() -> DocxTimestampRule {
    DocxTimestampRule {
        part: CORE_PROPERTIES_PART.into(),
        element: CREATED_ELEMENT.into(),
        format: crate::replay::policy::ResponseTimestampFormat::Rfc3339,
        source_evidence: "generator sets the core created property from the request clock".into(),
        source_example: "2024-01-02T03:04:05Z".into(),
        target_example: "2024-01-02T04:04:05Z".into(),
    }
}

#[test]
fn compares_decompressed_parts_and_accepts_request_relative_created_time() {
    let expected = docx("2024-01-02T03:04:05Z", "<document>same</document>", 6);
    let actual = docx("2024-01-02T04:04:05Z", "<document>same</document>", 8);
    let times = RequestTimes {
        source: Some("2024-01-01T19:04:05Z".parse::<DateTime<Utc>>().unwrap()),
        target: Some("2024-01-01T20:04:05Z".parse::<DateTime<Utc>>().unwrap()),
    };
    let (matches, report) = evaluate_docx(&expected, &actual, &[rule()], times).unwrap();
    assert!(matches);
    assert!(report.candidates_explain_all_differences);
    assert!(matches!(
        report.differences.as_slice(),
        [crate::replay::ResponseBodyDifferenceDetail::Docx(
            DocxBodyDifference {
                kind: DocxBodyDifferenceKind::TimestampMismatch,
                ..
            }
        )]
    ));
}

#[test]
fn zip_metadata_alone_is_not_document_content() {
    let expected = docx("2024-01-02T03:04:05Z", "<document>same</document>", 6);
    let actual = docx("2024-01-02T03:04:05Z", "<document>same</document>", 8);
    let comparison = compare_packages(&expected, &actual, &[rule()], None).unwrap();
    assert!(comparison.matches);
    assert!(comparison.differences.is_empty());
}

#[test]
fn rejects_real_part_changes_and_unanchored_timestamps() {
    let expected = docx("2024-01-02T03:04:05Z", "<document>source</document>", 6);
    let actual = docx("2024-01-02T05:04:05Z", "<document>target</document>", 8);
    let times = RequestTimes {
        source: Some("2024-01-01T19:04:05Z".parse::<DateTime<Utc>>().unwrap()),
        target: Some("2024-01-01T20:04:05Z".parse::<DateTime<Utc>>().unwrap()),
    };
    let (matches, report) = evaluate_docx(&expected, &actual, &[rule()], times).unwrap();
    assert!(!matches);
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(serialized.contains("entry_value_mismatch"));
    assert!(serialized.contains("timestamp_delta_mismatch"));
}

#[test]
fn requires_a_docx_opc_package() {
    assert!(!is_docx_body(b"PK not a zip"));
    assert!(diagnose_docx(b"PK not a zip", b"PK not a zip").is_err());
}
