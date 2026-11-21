use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn relative_report_filename_has_the_current_directory_anchor() {
    assert_eq!(
        report_parent(Path::new("report.json")).unwrap(),
        Path::new(".")
    );
}

#[test]
fn first_inventory_creates_missing_private_report_output_parent() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("case/.replay/replay-report.json");
    assert!(!report.parent().unwrap().exists());
    let value = vec!["native-global-summary".to_owned()];
    let reference =
        ArtifactReference::retain(&report, digest(&value).unwrap(), |_| Ok(value.clone())).unwrap();
    let parent = report.parent().unwrap();
    assert_eq!(
        fs::metadata(parent).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(
        !report.exists(),
        "retaining a baseline does not publish a report"
    );
    assert_eq!(reference.load::<Vec<String>>(&report).unwrap().0, value);
    ArtifactReference::retain::<Vec<String>>(&report, digest(&value).unwrap(), |_| {
        panic!("warm reuse must not rebuild inventory")
    })
    .unwrap();
}

#[test]
fn existing_report_parent_permissions_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("existing");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
    let report = parent.join("report.json");
    ArtifactReference::retain(&report, "a".repeat(64), |_| Ok(0)).unwrap();
    assert_eq!(
        fs::metadata(parent).unwrap().permissions().mode() & 0o777,
        0o750
    );
}
