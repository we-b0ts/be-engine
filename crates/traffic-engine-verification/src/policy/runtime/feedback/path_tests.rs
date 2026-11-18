#![cfg(unix)]

use std::fs;

use tempfile::tempdir;

use super::read_published_report;

#[test]
fn published_report_fallback_does_not_bypass_symlink_rejection() {
    let temp = tempdir().unwrap();
    let stale_detail = temp
        .path()
        .join("focused/api-1/.active/reports/assertion-detail.json");
    let published_detail = temp
        .path()
        .join("focused/api-1/latest/reports/assertion-detail.json");
    fs::create_dir_all(stale_detail.parent().unwrap()).unwrap();
    fs::create_dir_all(published_detail.parent().unwrap()).unwrap();
    fs::write(&published_detail, "{}").unwrap();
    std::os::unix::fs::symlink(&published_detail, &stale_detail).unwrap();

    let error = read_published_report(&stale_detail, "assertion detail report").unwrap_err();

    assert!(error.to_string().contains("must be a regular file"));
}
