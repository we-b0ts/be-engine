use super::*;

fn series(start: u32, end: u32, width: usize) -> MysqlTableSeries {
    MysqlTableSeries {
        prefix: "tasks_".into(),
        start,
        end,
        width,
    }
}

#[test]
fn compact_series_matches_exactly_the_formatted_physical_names() {
    for start in [0, 7, 98, 999, u32::MAX - 3] {
        for width in [0, 1, 2, 4, 10] {
            let series = series(start, start + 3, width);
            let matcher = TableMatcher::new(&[], &[], Some(&series)).unwrap();
            let expected: BTreeSet<_> = (series.start..=series.end)
                .map(|value| format!("tasks_{value:0width$}"))
                .collect();
            for name in &expected {
                assert!(matcher.matches(name), "{series:?}: {name}");
                let suffix = name.strip_prefix("tasks_").unwrap();
                for mutation in [
                    format!("tasks_0{suffix}"),
                    format!("tasks_{}", suffix.trim_start_matches('0')),
                    format!("tasks_+{suffix}"),
                    format!("Tasks_{suffix}"),
                    format!("tasks_{suffix}x"),
                ] {
                    assert_eq!(
                        matcher.matches(&mutation),
                        expected.contains(&mutation),
                        "{series:?}: {mutation}"
                    );
                }
            }
            for outside in [start.checked_sub(1), series.end.checked_add(1)]
                .into_iter()
                .flatten()
            {
                assert!(!matcher.matches(&format!("tasks_{outside:0width$}")));
            }
            assert!(!matcher.matches("tasks_4294967296"));
        }
    }
}

#[test]
fn exact_series_and_pattern_overlap_keeps_physical_name_equality() {
    let left = TableMatcher::new(&[], &[], Some(&series(7, 12, 4))).unwrap();
    for (tables, patterns, range, expected) in [
        (vec!["tasks_0007".into()], vec![], None, true),
        (vec!["tasks_7".into()], vec![], None, false),
        (vec![], vec!["*_0012".into()], None, true),
        (vec![], vec!["tasks_0013*".into()], None, false),
        (vec![], vec![], Some(series(12, 15, 4)), true),
        (vec![], vec![], Some(series(13, 15, 4)), false),
        (vec![], vec![], Some(series(7, 12, 3)), false),
        (
            vec![],
            vec![],
            Some(MysqlTableSeries {
                prefix: "tasks_0".into(),
                ..series(7, 12, 3)
            }),
            true,
        ),
    ] {
        let right = TableMatcher::new(&tables, &patterns, range.as_ref()).unwrap();
        assert_eq!(left.overlaps(&right), expected);
        assert_eq!(right.overlaps(&left), expected);
    }
}

#[test]
fn series_validation_preserves_identifier_and_union_size_bounds() {
    let range = series(0, 4095, 4);
    TableMatcher::new(&["tasks_0000".into()], &[], Some(&range)).unwrap();
    assert!(TableMatcher::new(&["other".into()], &[], Some(&range)).is_err());
    assert!(
        TableMatcher::new(
            &["tasks_0000".into(), "tasks_0000".into()],
            &[],
            Some(&range)
        )
        .is_err()
    );
    for invalid in [
        series(2, 1, 4),
        series(0, 4096, 4),
        series(0, 1, 11),
        MysqlTableSeries {
            prefix: String::new(),
            ..series(0, 1, 4)
        },
        MysqlTableSeries {
            prefix: "1tasks_".into(),
            ..series(0, 1, 4)
        },
        MysqlTableSeries {
            prefix: "db.tasks_".into(),
            ..series(0, 1, 4)
        },
        MysqlTableSeries {
            prefix: "a".repeat(63),
            ..series(9, 10, 0)
        },
    ] {
        assert!(
            TableMatcher::new(&[], &[], Some(&invalid)).is_err(),
            "{invalid:?}"
        );
    }
    let longest = MysqlTableSeries {
        prefix: "a".repeat(63),
        ..series(0, 9, 0)
    };
    let matcher = TableMatcher::new(&[], &[], Some(&longest)).unwrap();
    assert!(matcher.matches(&format!("{}9", longest.prefix)));
}
