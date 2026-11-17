use super::*;
use chrono::{TimeZone, Utc};

fn rule() -> ResponseHeaderDateRule {
    ResponseHeaderDateRule {
        header: "content-disposition".into(),
        parameter: Some("filename".into()),
        format: "%Y-%m-%d".into(),
        timezone: "+00:00".into(),
        source_evidence: "Exporter:filename uses the current calendar date".into(),
    }
}
fn times() -> RequestTimes {
    RequestTimes {
        source: Some(Utc.with_ymd_and_hms(2026, 10, 7, 12, 0, 0).unwrap()),
        target: Some(Utc.with_ymd_and_hms(2026, 10, 8, 12, 0, 0).unwrap()),
    }
}
fn header(day: &str) -> Vec<String> {
    vec![format!("attachment; filename=\"report_{day}.docx\"")]
}

#[test]
fn date_rule_preserves_relative_days_and_the_filename_contract() {
    assert!(
        compare(
            &header("2026-10-07"),
            &header("2026-10-08"),
            &[rule()],
            times()
        )
        .unwrap()
    );
    assert!(
        compare(
            &header("2026-10-07"),
            &header("2026-10-10"),
            &[rule()],
            times()
        )
        .is_err()
    );
    assert!(
        compare(
            &header("2026-10-07"),
            &header("2026-10-08"),
            &[rule()],
            RequestTimes::default()
        )
        .is_err()
    );
    assert!(
        compare(
            &header("2026-10-07"),
            &["attachment; filename=other_2026-10-08.docx".into()],
            &[rule()],
            times()
        )
        .is_err()
    );
    assert!(
        !compare(
            &header("2026-10-07"),
            &["inline; filename=report_2026-10-08.docx".into()],
            &[rule()],
            times()
        )
        .unwrap()
    );
}

#[test]
fn filename_star_and_fallback_are_both_checked() {
    let source=vec!["attachment; filename=report_2026-10-07.docx; filename*=UTF-8''%E6%8A%A5%E5%91%8A_2026-10-07.docx".into()];
    let actual=vec!["ATTACHMENT; filename*=utf-8''%E6%8A%A5%E5%91%8A_2026-10-08.docx; filename=\"report_2026-10-08.docx\"".into()];
    assert!(compare(&source, &actual, &[rule()], times()).unwrap());
    let candidates = candidates("content-disposition", &source, &actual);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].parameter.as_deref(), Some("filename"));
    assert!(
        compare(
            &source,
            &[actual[0].replace("report_2026-10-08", "report_2026-10-09")],
            &[rule()],
            times()
        )
        .is_err()
    );
}

#[test]
fn malformed_ambiguous_or_missing_dates_do_not_authorize_rules() {
    for value in [
        "attachment; filename=report.docx",
        "attachment; filename=x_2026-10-08_2026-10-09.docx",
        "attachment; filename=x_2026-10-08.docx; filename=other",
        "attachment; filename*=UTF-8''bad%ZZ_2026-10-08.docx",
    ] {
        assert!(compare(&header("2026-10-07"), &[value.into()], &[rule()], times()).is_err());
    }
}

#[test]
fn relative_days_are_independent_of_legacy_timezone_configuration() {
    let mut selected = rule();
    selected.timezone = "+08:00".into();
    let refs = RequestTimes {
        source: Some(Utc.with_ymd_and_hms(2026, 10, 6, 16, 0, 0).unwrap()),
        target: Some(Utc.with_ymd_and_hms(2026, 10, 7, 16, 0, 0).unwrap()),
    };
    assert!(
        compare(
            &header("2026-10-07"),
            &header("2026-10-08"),
            &[selected],
            refs
        )
        .unwrap()
    );
    assert!(
        compare(
            &header("2026-10-07"),
            &header("2026-10-08"),
            &[rule()],
            refs
        )
        .unwrap()
    );
}

#[test]
fn relative_dates_allow_short_midnight_crossings_but_reject_impossible_day_changes() {
    let source = Utc.with_ymd_and_hms(2026, 10, 7, 15, 59, 0).unwrap();
    for seconds in [120, -120] {
        let refs = RequestTimes {
            source: Some(source),
            target: Some(source + chrono::TimeDelta::seconds(seconds)),
        };
        let possible = if seconds > 0 {
            "2026-10-08"
        } else {
            "2026-10-06"
        };
        for day in ["2026-10-07", possible] {
            assert!(compare(&header("2026-10-07"), &header(day), &[rule()], refs).unwrap());
        }
        assert!(
            compare(
                &header("2026-10-07"),
                &header("2026-10-10"),
                &[rule()],
                refs
            )
            .is_err()
        );
    }
}

#[test]
fn a_literal_date_marker_cannot_hide_relocating_the_generated_date() {
    assert!(
        compare(
            &["attachment; filename=x_{date}_2026-10-07.docx".into()],
            &["attachment; filename=x_2026-10-08_{date}.docx".into()],
            &[rule()],
            times()
        )
        .is_err()
    );
}

#[test]
fn extended_filename_language_remains_part_of_the_contract() {
    assert!(
        !compare(
            &["attachment; filename*=UTF-8'en'report_2026-10-07.docx".into()],
            &["attachment; filename*=UTF-8'zh'report_2026-10-08.docx".into()],
            &[rule()],
            times()
        )
        .unwrap()
    );
}
